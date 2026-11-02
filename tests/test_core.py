#!/usr/bin/env python3
"""Core-logic unit tests for CYBER-EVO (stdlib unittest, no data, no network).

These cover the deterministic pieces that the paper's claims rest on: the
behavioral invariants, the tool-name signature, the confusion math, the LLM
verdict / event parsing, the deployed-invariant transfer logic, and one round of
the synthetic co-evolution loop. They need neither the (git-ignored) telemetry
nor a running LLM, so they run anywhere and in CI.
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def load(rel: str, name: str):
    path = REPO / rel
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


lsass = load("experiments/lsass_detectors.py", "lsass_detectors")
fpb = load("experiments/invariant_fp_budget.py", "invariant_fp_budget")
ens = load("experiments/ensemble_ladder.py", "ensemble_ladder")
xds = load("experiments/cross_dataset.py", "cross_dataset")
abl = load("experiments/invariant_ablation.py", "invariant_ablation")


def eid10(src, granted, tgt="C:\\Windows\\System32\\lsass.exe"):
    return {"EventID": 10, "SourceImage": src, "TargetImage": tgt, "GrantedAccess": granted}


class TestSignatureDetector(unittest.TestCase):
    def test_learns_and_flags_known_image_only(self):
        d = lsass.SignatureDetector()
        d.fit([eid10("C:\\tools\\procdump.exe", "0x1410")])
        self.assertTrue(d.predict(eid10("C:\\x\\procdump.exe", "0x1410")))
        # unseen tool name -> signature is blind (the paper's spine)
        self.assertFalse(d.predict(eid10("C:\\x\\nanodump.exe", "0x1fffff")))


class TestBehavioralInvariant(unittest.TestCase):
    def test_vm_read_nonsystem_fires(self):
        d = lsass.BehavioralDetector()
        d.fit([eid10("procdump.exe", "0x1410")])
        self.assertTrue(d.predict(eid10("sharpdump.exe", "0x1fffff")))  # unseen tool, still caught

    def test_system_source_excluded(self):
        d = lsass.BehavioralDetector()
        d.fit([eid10("procdump.exe", "0x1410")])
        self.assertFalse(d.predict(eid10("C:\\Windows\\System32\\svchost.exe", "0x1fffff")))

    def test_no_vm_read_ignored(self):
        d = lsass.BehavioralDetector()
        d.fit([])  # no trained masks
        self.assertFalse(d.predict(eid10("taskmgr.exe", "0x1400")))  # 0x1400 has no VM_READ bit


class TestConfusion(unittest.TestCase):
    def test_counts_and_rates(self):
        c = lsass.confusion([(True, True), (True, False), (False, True), (False, False)])
        self.assertEqual((c["tp"], c["fn"], c["fp"], c["tn"]), (1, 1, 1, 1))
        self.assertAlmostEqual(c["precision"], 0.5)
        self.assertAlmostEqual(c["recall"], 0.5)

    def test_undefined_precision_when_no_positive(self):
        c = lsass.confusion([(True, False), (False, False)])
        self.assertIsNone(c["precision"])  # undefined, not 0


class TestFpBudgetInvariants(unittest.TestCase):
    def test_lsass_rule(self):
        self.assertTrue(fpb.inv_lsass(eid10("mimikatz.exe", "0x1410")))
        self.assertFalse(fpb.inv_lsass(eid10("svchost.exe", "0x1410")))

    def test_ntds_rule(self):
        pos = {"EventID": 4663, "ObjectName": "\\Device\\X\\Windows\\NTDS\\ntds.dit", "ProcessName": "ntdsutil.exe"}
        neg = {"EventID": 4663, "ObjectName": "\\Device\\X\\Windows\\NTDS\\ntds.dit", "ProcessName": "lsass.exe"}
        self.assertTrue(fpb.inv_ntds(pos))
        self.assertFalse(fpb.inv_ntds(neg))  # lsass is the legitimate owner

    def test_injection_rule(self):
        self.assertTrue(fpb.inv_injection({"EventID": 8, "SourceImage": "winword.exe"}))
        self.assertFalse(fpb.inv_injection({"EventID": 8, "SourceImage": "svchost.exe"}))
        self.assertFalse(fpb.inv_injection({"EventID": 10, "SourceImage": "winword.exe"}))


class TestDeployedTransfer(unittest.TestCase):
    """The ladder premise: a prior-surface rule does not fire on a new surface."""

    def test_lsass_rule_silent_on_injection_event(self):
        inj_ev = {"_eid": 8, "src": "powershell.exe", "ga": None}
        self.assertFalse(ens.invariant_pred(["lsass"], inj_ev))

    def test_lsass_rule_fires_on_lsass_verdict(self):
        v = {"_eid": 10, "src": "mimikatz.exe", "tgt": "lsass.exe", "ga": "0x1410"}
        self.assertTrue(ens.invariant_pred(["lsass"], v))


class TestCrossDatasetParse(unittest.TestCase):
    XML = (
        "<Event xmlns='x'><System><EventID>10</EventID></System><EventData>"
        "<Data Name='SourceImage'>C:\\x\\notprocdump.exe</Data>"
        "<Data Name='TargetImage'>C:\\Windows\\System32\\lsass.exe</Data>"
        "<Data Name='GrantedAccess'>0x1fffff</Data></EventData></Event>"
    )

    def test_parse_and_invariant(self):
        import tempfile, os
        fd, p = tempfile.mkstemp(suffix=".log")
        os.write(fd, self.XML.encode()); os.close(fd)
        try:
            evs = xds.parse_events(Path(p))
            self.assertEqual(len(evs), 1)
            self.assertEqual(evs[0]["_eid"], 10)
            # behavioral invariant catches the renamed tool; it keys on behavior not name
            self.assertTrue(xds.inv_lsass(evs[0]))
        finally:
            os.unlink(p)


class TestMaskAblation(unittest.TestCase):
    def test_exact_mask_is_signature_like(self):
        trained = {0x1410}
        exact = abl.mask_pred("trained_masks", trained)
        vmread = abl.mask_pred("vm_read", trained)
        self.assertTrue(exact(0x1410))
        self.assertFalse(exact(0x1fffff))   # unseen mask -> missed (overfit)
        self.assertTrue(vmread(0x1fffff))   # VM_READ bit generalizes


class TestSyntheticCoevolution(unittest.TestCase):
    def test_one_condition_runs(self):
        coev = load("experiments/coevolution.py", "coevolution")
        res = coev.run("D", rounds=3, seed=1337, n_attack=20, n_benign=20)
        self.assertEqual(len(res["series"]), 3)
        self.assertIn("detection_rate", res["series"][0]["overall"])


if __name__ == "__main__":
    unittest.main()
