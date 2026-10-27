#!/usr/bin/env python3
"""New-technique rung: does credential-dumping detection transfer to injection?

One rung further than ``ladder_subtechnique.py``. There we changed the
sub-technique (LSASS -> NTDS) inside OS Credential Dumping. Here we change the
*technique*: train/derive everything on credential dumping (T1003) and test on
process injection (T1055) -- a different ATT&CK technique entirely.

What makes this rung sharper than the last: injection SHARES the LSASS
telemetry surface. Both raise Sysmon EID10 ProcessAccess (a handle into another
process). The LSASS behavioral invariant keys on PROCESS_VM_READ to lsass.exe;
injection opens its target (often PROCESS_ALL_ACCESS) and then fires EID8
CreateRemoteThread. So we can see directly whether the invariant discriminates
within the shared surface (correctly stays silent) or misfires.

Evaluated on the injection slice:
* the LSASS-trained signature + behavioral detectors (unchanged),
* the NTDS-specific invariant (from the previous rung), and
* an injection-specific invariant (CreateRemoteThread from a non-system source),
each a separate surface-matched rule. The pattern across all three rungs: a rule
covers exactly its own surface and nothing beyond it.

Stdlib only.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LSASS_PROC = REPO_ROOT / "data" / "processed" / "lsass"
INJ_PROC = REPO_ROOT / "data" / "processed" / "injection"
LSASS_MANIFEST = REPO_ROOT / "results" / "lsass-slice-manifest.json"
INJ_MANIFEST = REPO_ROOT / "results" / "injection-slice-manifest.json"
OUT_PATH = REPO_ROOT / "results" / "ladder-technique.json"

SYSTEM_WHITELIST = {
    "wininit.exe", "services.exe", "svchost.exe", "csrss.exe", "lsm.exe",
    "lsass.exe", "winlogon.exe", "msmpeng.exe", "wmiprvse.exe",
    "mssense.exe", "sensecncproxy.exe", "system", "smss.exe",
    "taskhostw.exe", "sihost.exe", "explorer.exe", "searchindexer.exe",
}


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


LD = _load_module(REPO_ROOT / "experiments" / "lsass_detectors.py", "lsass_detectors")
LADDER2 = _load_module(REPO_ROOT / "experiments" / "ladder_subtechnique.py", "ladder_subtechnique")


def basename(image) -> str:
    if not image:
        return ""
    return str(image).replace("/", "\\").split("\\")[-1].lower()


def read_jsonl(path: Path):
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


class InjectionBehavioralDetector:
    """Technique-specific invariant: CreateRemoteThread from a non-system source."""
    name = "behavioral-INJECTION(crt-invariant)"

    def predict(self, ev) -> bool:
        if int(ev.get("EventID") or 0) != 8:
            return False
        src = basename(ev.get("SourceImage"))
        return bool(src) and src not in SYSTEM_WHITELIST


def load_campaign(proc_dir: Path, campaign: str):
    cdir = proc_dir / campaign
    labels = {r["event_index"]: r["attack_present"] for r in read_jsonl(cdir / "labels.jsonl")}
    events = list(read_jsonl(cdir / "events.jsonl"))
    return events, labels


def evaluate(detector, proc_dir, campaigns):
    per_campaign, all_pairs = {}, []
    for c in campaigns:
        events, labels = load_campaign(proc_dir, c)
        pairs = [(bool(labels.get(e["event_index"])), detector.predict(e)) for e in events]
        per_campaign[c] = LD.confusion(pairs)
        all_pairs += pairs
    return per_campaign, LD.confusion(all_pairs)


def main() -> None:
    ap = argparse.ArgumentParser(description="New-technique rung: T1003 -> T1055 transfer.")
    ap.add_argument("--out", type=Path, default=OUT_PATH)
    args = ap.parse_args()

    lsass_manifest = json.loads(LSASS_MANIFEST.read_text(encoding="utf-8"))
    inj_manifest = json.loads(INJ_MANIFEST.read_text(encoding="utf-8"))
    lsass_train = lsass_manifest["split"]["train"]
    inj_campaigns = inj_manifest["split"]["test"]

    # Fit LSASS detectors on LSASS training attacks, as in rung 1 -- unchanged.
    train_attacks = []
    for c in lsass_train:
        events, labels = load_campaign(LSASS_PROC, c)
        train_attacks += [e for e in events if labels.get(e["event_index"])]
    sig = LD.SignatureDetector(); sig.fit(train_attacks)
    beh = LD.BehavioralDetector(); beh.fit(train_attacks)
    ntds_beh = LADDER2.NtdsBehavioralDetector()   # the previous rung's rule
    inj_beh = InjectionBehavioralDetector()        # this rung's matched rule

    results = {
        "rung": "new_technique",
        "trained_on": lsass_manifest["technique_under_test"] + " (credential dumping)",
        "tested_on": inj_manifest["technique_under_test"] + " (process injection)",
        "procedures": {c: inj_manifest["campaigns"][i]["procedure"]
                       for i, c in enumerate(inj_campaigns)},
        "transfer": {},        # cred-dumping rules evaluated on injection
        "technique_specific": {},
    }

    for det in (sig, beh, ntds_beh):
        per_c, overall = evaluate(det, INJ_PROC, inj_campaigns)
        results["transfer"][det.name] = {"overall": overall, "per_campaign": per_c}

    per_c, overall = evaluate(inj_beh, INJ_PROC, inj_campaigns)
    results["technique_specific"][inj_beh.name] = {"overall": overall, "per_campaign": per_c}

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")

    def row(label, m):
        rec = "  n/a" if m["recall"] is None else f"{m['recall']:.2f}"
        prec = "  n/a" if m["precision"] is None else f"{m['precision']:.2f}"
        return f"  {label:36} recall={rec} precision={prec} TP={m['tp']:3d} FP={m['fp']:4d} FN={m['fn']:3d}"

    print(f"NEW-TECHNIQUE RUNG: trained on {results['trained_on']}, tested on {results['tested_on']}")
    print(f"injection procedures: {results['procedures']}\n")
    print("Credential-dumping rules evaluated on injection (transfer across technique):")
    for name, r in results["transfer"].items():
        print(row(name, r["overall"]))
    print("\nInjection-specific invariant (separate, surface-matched rule):")
    for name, r in results["technique_specific"].items():
        print(row(name, r["overall"]))
        pc = r["per_campaign"]
        grad = "   ".join(f"{c.split('_')[1]}:{(pc[c]['recall'] if pc[c]['recall'] is not None else 0):.2f}"
                          for c in inj_campaigns)
        print(f"    per-procedure recall -> {grad}")
    print(f"\n  wrote {args.out.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
