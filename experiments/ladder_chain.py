#!/usr/bin/env python3
"""New-chain rung: do per-technique invariants light up a full intrusion?

Runs the three behavioral invariants (LSASS, NTDS, injection) -- each built and
validated on an isolated atomic capture -- unchanged over the APT29 Day 1 chain
(~196k real host events from a different environment). Two measurements:

1. **Cross-environment transfer + realistic false-alarm rate.** For each
   technique that appears in the chain, does its invariant fire on the chain's
   instances (recall), and how many false positives does it raise against the
   full noisy stream (precision / FPR)? The atomic slices could not answer the
   FP question at scale; 196k mixed events can.

2. **Chain coverage.** The detector set has a rule for three techniques; the
   APT29 Day 1 emulation exercises far more. We report how many of the chain's
   labeled attack events (and distinct techniques) the whole set covers -- the
   fraction of the kill chain a per-technique approach illuminates.

Ground truth is the union of the three derived rules (evaluator-only), produced
by environment/apt29_loader.py. Stdlib only.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
APT29 = REPO_ROOT / "data" / "processed" / "apt29" / "day1"
LSASS_PROC = REPO_ROOT / "data" / "processed" / "lsass"
LSASS_MANIFEST = REPO_ROOT / "results" / "lsass-slice-manifest.json"
APT29_MANIFEST = REPO_ROOT / "results" / "apt29-slice-manifest.json"
OUT_PATH = REPO_ROOT / "results" / "ladder-chain.json"

# MITRE ATT&CK Evaluations APT29 Day 1 exercises this many distinct ATT&CK
# (sub-)techniques across its documented steps (the public operational flow).
# Used only as the coverage denominator; cited in the paper.
APT29_DAY1_TECHNIQUES = 20


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


LD = _load(REPO_ROOT / "experiments" / "lsass_detectors.py", "lsass_detectors")
L2 = _load(REPO_ROOT / "experiments" / "ladder_subtechnique.py", "ladder_subtechnique")
L3 = _load(REPO_ROOT / "experiments" / "ladder_technique.py", "ladder_technique")


def read_jsonl(path: Path):
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def confusion(pairs):
    tp = fp = tn = fn = 0
    for truth, pred in pairs:
        if truth and pred:
            tp += 1
        elif truth and not pred:
            fn += 1
        elif not truth and pred:
            fp += 1
        else:
            tn += 1
    prec = round(tp / (tp + fp), 4) if (tp + fp) else None
    rec = round(tp / (tp + fn), 4) if (tp + fn) else None
    fpr = round(fp / (fp + tn), 8) if (fp + tn) else None
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": prec, "recall": rec, "false_positive_rate": fpr}


def main() -> None:
    ap = argparse.ArgumentParser(description="New-chain rung: invariants over the APT29 Day1 chain.")
    ap.add_argument("--out", type=Path, default=OUT_PATH)
    args = ap.parse_args()

    # Fit the LSASS behavioral detector on atomic LSASS training, as before.
    lsass_train = json.loads(LSASS_MANIFEST.read_text(encoding="utf-8"))["split"]["train"]
    train_attacks = []
    for c in lsass_train:
        cdir = LSASS_PROC / c
        labels = {r["event_index"]: r["attack_present"] for r in read_jsonl(cdir / "labels.jsonl")}
        for e in read_jsonl(cdir / "events.jsonl"):
            if labels.get(e["event_index"]):
                train_attacks.append(e)
    lsass_beh = LD.BehavioralDetector(); lsass_beh.fit(train_attacks)
    ntds_beh = L2.NtdsBehavioralDetector()
    inj_beh = L3.InjectionBehavioralDetector()

    detectors = {
        "T1003.001": ("behavioral-LSASS", lsass_beh),
        "T1003.003": ("behavioral-NTDS", ntds_beh),
        "T1055": ("behavioral-INJECTION", inj_beh),
    }

    # Stream the chain once; collect per-detector pairs and the union prediction.
    labels = {r["event_index"]: r for r in read_jsonl(APT29 / "labels.jsonl")}
    per_det = {tid: [] for tid in detectors}           # (truth_for_that_technique, pred)
    union_pairs = []                                    # (any_attack, any_detector_fires)
    tech_truth_counts = {tid: 0 for tid in detectors}
    n = 0
    for ev in read_jsonl(APT29 / "events.jsonl"):
        n += 1
        lab = labels.get(ev["event_index"], {})
        tid_truth = lab.get("technique_id")
        any_truth = bool(lab.get("attack_present"))
        any_pred = False
        for tid, (_name, det) in detectors.items():
            pred = det.predict(ev)
            any_pred = any_pred or pred
            # per-technique truth: this event is a positive for tid only if labeled tid
            per_det[tid].append((tid_truth == tid, pred))
        if tid_truth in tech_truth_counts:
            tech_truth_counts[tid_truth] += 1
        union_pairs.append((any_truth, any_pred))

    results = {
        "rung": "new_chain",
        "dataset": "APT29 Day 1 (MITRE ATT&CK Evals)",
        "events": n,
        "chain_technique_count_documented": APT29_DAY1_TECHNIQUES,
        "techniques_with_a_detector": list(detectors.keys()),
        "labeled_attack_events_by_technique": tech_truth_counts,
        "per_technique_transfer": {},
        "union": confusion(union_pairs),
    }
    for tid, (name, _det) in detectors.items():
        results["per_technique_transfer"][tid] = {"detector": name, **confusion(per_det[tid])}

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")

    def row(label, m):
        rec = "  n/a" if m["recall"] is None else f"{m['recall']:.2f}"
        prec = "  n/a" if m["precision"] is None else f"{m['precision']:.2f}"
        return (f"  {label:26} recall={rec} precision={prec} "
                f"TP={m['tp']:2d} FP={m['fp']:4d} FN={m['fn']:2d}")

    covered_tech = sum(1 for tid in detectors if tech_truth_counts[tid] > 0)
    print(f"NEW-CHAIN RUNG: APT29 Day 1, {n} events")
    print("Per-technique cross-environment transfer (invariant over the full chain):")
    for tid, (name, _d) in detectors.items():
        r = results["per_technique_transfer"][tid]
        present = "present" if tech_truth_counts[tid] else "absent in day1"
        print(row(f"{tid} {name}", r) + f"   [{present}]")
    print("\nWhole detector set over the chain:")
    print(row("union", results["union"]))
    print(f"\nCoverage: detectors fire for {covered_tech} technique(s) actually present; "
          f"the set has rules for {len(detectors)} of ~{APT29_DAY1_TECHNIQUES} "
          f"chain techniques (~{len(detectors)/APT29_DAY1_TECHNIQUES:.0%}).")
    print(f"  wrote {args.out.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
