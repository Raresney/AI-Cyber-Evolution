#!/usr/bin/env python3
"""Seed sweep for the CYBER-EVO co-evolution loop.

Runs every condition (A-D) across many seeds and aggregates per-round and
summary statistics (mean and 95% confidence interval) so results are reported
with variability rather than from a single anecdotal seed -- as the
experimental-design doc requires ("Experiments should be repeated multiple
times to measure variability").

Stdlib only (statistics); the plotting script consumes the JSON this writes.

Output: ``results/seed-sweep.json`` and a console summary.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import math
import statistics
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = REPO_ROOT / "results"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


coevo = _load(REPO_ROOT / "experiments" / "coevolution.py", "coevolution")


def agg(values: list[float]) -> dict:
    """Mean / std / 95% CI over a list, skipping None."""
    xs = [v for v in values if v is not None]
    if not xs:
        return {"mean": None, "std": None, "ci95": None, "n": 0}
    mean = statistics.fmean(xs)
    if len(xs) < 2:
        return {"mean": round(mean, 4), "std": 0.0, "ci95": 0.0, "n": len(xs)}
    std = statistics.stdev(xs)
    ci95 = 1.96 * std / math.sqrt(len(xs))
    return {"mean": round(mean, 4), "std": round(std, 4),
            "ci95": round(ci95, 4), "n": len(xs)}


def _swing(detections: list[float]) -> float:
    """Mean absolute round-to-round change -- an oscillation measure."""
    clean = [d for d in detections if d is not None]
    if len(clean) < 2:
        return 0.0
    return statistics.fmean(abs(clean[i] - clean[i - 1])
                            for i in range(1, len(clean)))


def sweep(conditions, rounds, seeds, n_attack, n_benign) -> dict:
    out = {}
    for cond in conditions:
        # runs[seed_index] = coevolution result dict
        runs = [coevo.run(cond, rounds, s, n_attack, n_benign) for s in seeds]

        per_round = []
        for r in range(rounds):
            def col(path):
                vals = []
                for run in runs:
                    s = run["series"][r]
                    node = s
                    for key in path:
                        node = node[key]
                    vals.append(node)
                return vals
            per_round.append({
                "round": r,
                "detection_rate": agg(col(("overall", "detection_rate"))),
                "asr": agg(col(("overall", "asr"))),
                "false_positive_rate": agg(col(("overall", "false_positive_rate"))),
                "investigate_on_benign": agg(col(("overall", "investigate_on_benign"))),
                "final_test_detection": agg(col(("final_test", "detection_rate"))),
                "blue_known_signatures": agg(col(("blue_knowledge", "known_signature_count"))),
            })

        # Summary per seed, then aggregated.
        det_all_mean, det_last, asr_last, swings, minted, known_last, inv_benign_last = \
            [], [], [], [], [], [], []
        for run in runs:
            dets = [s["overall"]["detection_rate"] for s in run["series"]]
            det_all_mean.append(statistics.fmean([d for d in dets if d is not None]))
            det_last.append(run["series"][-1]["overall"]["detection_rate"])
            asr_last.append(run["series"][-1]["overall"]["asr"])
            swings.append(_swing(dets))
            minted.append(run["series"][-1]["red_strategy"]["tokens_minted"])
            known_last.append(run["series"][-1]["blue_knowledge"]["known_signature_count"])
            inv_benign_last.append(run["series"][-1]["overall"]["investigate_on_benign"])

        out[cond] = {
            "condition_meaning": runs[0]["condition_meaning"],
            "per_round": per_round,
            "summary": {
                "detection_mean_all_rounds": agg(det_all_mean),
                "detection_last_round": agg(det_last),
                "asr_last_round": agg(asr_last),
                "oscillation_swing": agg(swings),
                "tokens_minted": agg(minted),
                "blue_known_signatures_last": agg(known_last),
                "investigate_on_benign_last": agg(inv_benign_last),
            },
        }
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="Seed sweep over co-evolution conditions.")
    ap.add_argument("--seeds", type=int, default=20, help="number of seeds")
    ap.add_argument("--seed-start", type=int, default=1000)
    ap.add_argument("--rounds", type=int, default=12)
    ap.add_argument("--n-attack", type=int, default=60)
    ap.add_argument("--n-benign", type=int, default=60)
    ap.add_argument("--conditions", default="ABCD")
    args = ap.parse_args()

    seeds = [args.seed_start + i for i in range(args.seeds)]
    conditions = list(args.conditions)
    results = sweep(conditions, args.rounds, seeds, args.n_attack, args.n_benign)

    doc = {
        "seeds": seeds,
        "n_seeds": len(seeds),
        "rounds": args.rounds,
        "pool": {"n_attack": args.n_attack, "n_benign": args.n_benign},
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "conditions": results,
    }
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (RESULTS_DIR / "seed-sweep.json").write_text(
        json.dumps(doc, indent=2) + "\n", encoding="utf-8")

    def pm(a):
        return "n/a" if a["mean"] is None else f"{a['mean']:.2f} +/- {a['ci95']:.2f}"

    print(f"\n=== SEED SWEEP: {len(seeds)} seeds, {args.rounds} rounds, "
          f"conditions {''.join(conditions)} ===")
    print("cond | detection (all rounds) | asr (last) | oscillation swing | minted | blue sigs")
    print("-----+------------------------+------------+-------------------+--------+----------")
    for cond in conditions:
        s = results[cond]["summary"]
        print(f"  {cond}  | {pm(s['detection_mean_all_rounds']):>22} | "
              f"{pm(s['asr_last_round']):>10} | {pm(s['oscillation_swing']):>17} | "
              f"{s['tokens_minted']['mean']:>5.1f}  | {s['blue_known_signatures_last']['mean']:.1f}")
    print(f"\n  (swing = mean |det[r]-det[r-1]|; high swing = oscillating arms race)")
    print(f"  wrote results/seed-sweep.json")


if __name__ == "__main__":
    main()
