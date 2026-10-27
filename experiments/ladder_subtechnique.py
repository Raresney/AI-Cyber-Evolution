#!/usr/bin/env python3
"""New-subtechnique rung: does LSASS detection transfer to NTDS?

Takes the signature and behavioral detectors that won the LSASS new-instance
test (``experiments/lsass_detectors.py``), fits them on the LSASS training
procedures exactly as before, and evaluates them -- unchanged -- on the NTDS
slice (T1003.003), a different sub-technique of the same technique (OS
Credential Dumping).

Both LSASS detectors are tied to the LSASS surface (Sysmon EID10 ProcessAccess
to lsass.exe), so on NTDS -- which leaves a file-copy footprint, not a memory
read -- they cannot fire. That is the measurement: how far the detectors that
generalized across *tools* fall when the *sub-technique* changes.

For contrast, an analogous NTDS-specific behavioral invariant (a non-owner
process creating/accessing ``ntds*.dit``) is evaluated on the same slice. Like
the LSASS behavioral rule it encodes the ground-truth invariant, so its recall
is high by construction; the point is that it is a *separate* rule -- the LSASS
one does not become it. Each surface-specific invariant covers one sub-technique
only; nothing here transfers across the boundary.

Stdlib only. Reuses the detector classes from lsass_detectors.py by path import.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LSASS_PROC = REPO_ROOT / "data" / "processed" / "lsass"
NTDS_PROC = REPO_ROOT / "data" / "processed" / "ntds"
LSASS_MANIFEST = REPO_ROOT / "results" / "lsass-slice-manifest.json"
NTDS_MANIFEST = REPO_ROOT / "results" / "ntds-slice-manifest.json"
OUT_PATH = REPO_ROOT / "results" / "ladder-subtechnique.json"


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


LD = _load_module(REPO_ROOT / "experiments" / "lsass_detectors.py", "lsass_detectors")

NTDS_DIT = re.compile(r"^ntds.*\.dit$")
LEGIT_NTDS_OWNER = {"lsass.exe"}
NTDS_DUMP_EIDS = {11, 4663}


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


class NtdsBehavioralDetector:
    """Sub-technique-specific invariant: non-owner process touches ntds*.dit."""
    name = "behavioral-NTDS(file-invariant)"

    def predict(self, ev) -> bool:
        if int(ev.get("EventID") or 0) not in NTDS_DUMP_EIDS:
            return False
        path = ev.get("TargetFilename") or ev.get("ObjectName")
        if not path or not NTDS_DIT.match(basename(path)):
            return False
        actor = basename(ev.get("Image") or ev.get("ProcessName"))
        return bool(actor) and actor not in LEGIT_NTDS_OWNER


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
    ap = argparse.ArgumentParser(description="New-subtechnique rung: LSASS -> NTDS transfer.")
    ap.add_argument("--out", type=Path, default=OUT_PATH)
    args = ap.parse_args()

    lsass_manifest = json.loads(LSASS_MANIFEST.read_text(encoding="utf-8"))
    ntds_manifest = json.loads(NTDS_MANIFEST.read_text(encoding="utf-8"))
    lsass_train = lsass_manifest["split"]["train"]
    ntds_campaigns = ntds_manifest["split"]["test"]

    # Fit the LSASS detectors on the LSASS training procedures, as in the
    # new-instance experiment -- unchanged.
    train_attacks = []
    for c in lsass_train:
        events, labels = load_campaign(LSASS_PROC, c)
        train_attacks += [e for e in events if labels.get(e["event_index"])]

    sig = LD.SignatureDetector()
    beh = LD.BehavioralDetector()
    sig.fit(train_attacks)
    beh.fit(train_attacks)
    ntds_beh = NtdsBehavioralDetector()

    results = {
        "rung": "new_subtechnique",
        "trained_on": lsass_manifest["technique_under_test"],
        "tested_on": ntds_manifest["technique_under_test"],
        "ntds_procedures": {c: ntds_manifest["campaigns"][i]["procedure"]
                            for i, c in enumerate(ntds_campaigns)},
        "transfer": {},   # LSASS-trained detectors evaluated on NTDS
        "ntds_specific": {},  # a separate NTDS invariant, for contrast
    }

    for det in (sig, beh):
        per_c, overall = evaluate(det, NTDS_PROC, ntds_campaigns)
        results["transfer"][det.name] = {"overall": overall, "per_campaign": per_c}

    per_c, overall = evaluate(ntds_beh, NTDS_PROC, ntds_campaigns)
    results["ntds_specific"][ntds_beh.name] = {"overall": overall, "per_campaign": per_c}

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")

    def row(label, m):
        rec = "  n/a" if m["recall"] is None else f"{m['recall']:.2f}"
        prec = "  n/a" if m["precision"] is None else f"{m['precision']:.2f}"
        return f"  {label:34} recall={rec} precision={prec} TP={m['tp']:3d} FP={m['fp']:4d} FN={m['fn']:3d}"

    print(f"NEW-SUBTECHNIQUE RUNG: trained on {results['trained_on']} (LSASS), "
          f"tested on {results['tested_on']} (NTDS)")
    print(f"NTDS procedures: {results['ntds_procedures']}\n")
    print("LSASS-trained detectors evaluated on NTDS (transfer across sub-technique):")
    for name, r in results["transfer"].items():
        print(row(name, r["overall"]))
    print("\nNTDS-specific invariant (a separate rule, for contrast):")
    for name, r in results["ntds_specific"].items():
        print(row(name, r["overall"]))
        pc = r["per_campaign"]
        grad = "   ".join(f"{c.split('_')[1]}:{(pc[c]['recall'] if pc[c]['recall'] is not None else 0):.2f}"
                          for c in ntds_campaigns)
        print(f"    per-procedure recall -> {grad}")
    print(f"\n  wrote {args.out.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
