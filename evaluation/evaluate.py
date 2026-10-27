#!/usr/bin/env python3
"""Evaluator for CYBER-EVO.

Joins Blue decisions to evaluator-only ground truth (by ``case_id``) and
computes the metrics defined in the telemetry schema doc (section 9) and the
experimental-design doc: confusion matrix, precision, recall / detection rate,
false-positive rate, plus breakdowns by split, telemetry condition, and
generalization category.

Principles enforced here:

* Undefined, not zero -- when a denominator is 0 the metric is reported as
  ``null`` (undefined), never silently 0 (schema doc section 9).
* Detection rate is never reported alone -- precision, FPR and the held-out
  (final_test) breakdown are always included.
* ``investigate`` is a real third outcome. The primary confusion matrix is
  *strict* (only ``detect`` counts as a positive detection); investigate
  outcomes are also tallied separately so triage load is visible.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DECISIONS_PATH = REPO_ROOT / "results" / "blue-decisions.jsonl"
GROUND_TRUTH_PATH = REPO_ROOT / "telemetry" / "ground-truth.jsonl"
METRICS_PATH = REPO_ROOT / "results" / "metrics.json"

EVAL_VERSION = "evaluator-v1"


def _read_jsonl(path: Path) -> list[dict]:
    rows = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def _ratio(num: int, den: int):
    """Return num/den, or None when the denominator is 0 (undefined)."""
    return round(num / den, 4) if den else None


def confusion(pairs: list[tuple[bool, str]]) -> dict:
    """Build strict confusion matrix from (attack_present, decision) pairs.

    Strict rule: a positive detection is ``decision == 'detect'`` only.
    ``investigate`` and ``no_alert`` both count as "not detected" for TP/FN,
    but investigate counts are surfaced separately.
    """
    tp = fp = tn = fn = 0
    inv_on_attack = inv_on_benign = 0
    for attack, decision in pairs:
        detected = decision == "detect"
        if decision == "investigate":
            if attack:
                inv_on_attack += 1
            else:
                inv_on_benign += 1
        if attack and detected:
            tp += 1
        elif attack and not detected:
            fn += 1
        elif not attack and detected:
            fp += 1
        else:
            tn += 1

    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)          # detection rate
    fpr = _ratio(fp, fp + tn)
    f1 = None
    if precision not in (None, 0) and recall not in (None, 0):
        f1 = round(2 * precision * recall / (precision + recall), 4)

    return {
        "n": len(pairs),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "investigate_on_attack": inv_on_attack,
        "investigate_on_benign": inv_on_benign,
        "precision": precision,
        "recall_detection_rate": recall,
        "false_positive_rate": fpr,
        "f1": f1,
    }


def _grouped(pairs_by_key: dict[str, list[tuple[bool, str]]]) -> dict:
    return {k: confusion(v) for k, v in sorted(pairs_by_key.items())}


def evaluate(decisions: list[dict], ground_truth: list[dict]) -> dict:
    gt = {r["case_id"]: r for r in ground_truth}
    dec = {r["case_id"]: r for r in decisions}

    missing_decisions = sorted(set(gt) - set(dec))
    missing_truth = sorted(set(dec) - set(gt))

    overall: list[tuple[bool, str]] = []
    by_split: dict[str, list] = {}
    by_condition: dict[str, list] = {}
    by_generalization: dict[str, list] = {}

    for case_id, truth in gt.items():
        if case_id not in dec:
            continue
        pair = (bool(truth["attack_present"]), dec[case_id]["decision"])
        overall.append(pair)
        by_split.setdefault(truth["split"], []).append(pair)
        by_condition.setdefault(truth["telemetry_condition"], []).append(pair)
        by_generalization.setdefault(truth["generalization_category"], []).append(pair)

    return {
        "eval_version": EVAL_VERSION,
        "n_scored": len(overall),
        "integrity": {
            "cases_without_decision": missing_decisions,
            "decisions_without_truth": missing_truth,
            "label_leakage_check": _leakage_check(decisions),
        },
        "overall": confusion(overall),
        "by_split": _grouped(by_split),
        "by_telemetry_condition": _grouped(by_condition),
        "by_generalization": _grouped(by_generalization),
        "notes": [
            "recall_detection_rate == recall; interpret with precision and FPR.",
            "null metric = undefined (zero denominator), not zero.",
            "strict matrix: only 'detect' is a positive; investigate tallied separately.",
            "detection latency not modelled in v1 (no decision-time); delayed "
            "condition is evaluated on outcome only.",
        ],
    }


def _leakage_check(decisions: list[dict]) -> str:
    """Guard: Blue evidence must not reference hidden ground-truth labels."""
    banned = ("attack_present", "split", "telemetry_condition",
              "expected_detection", "scenario_id")
    for d in decisions:
        blob = json.dumps(d.get("evidence", [])).lower()
        for b in banned:
            if b in blob:
                return f"FAIL: evidence references hidden label '{b}'"
    return "pass"


def main() -> None:
    ap = argparse.ArgumentParser(description="Score Blue decisions against ground truth.")
    ap.add_argument("--decisions", type=Path, default=DECISIONS_PATH)
    ap.add_argument("--ground-truth", type=Path, default=GROUND_TRUTH_PATH)
    ap.add_argument("--out", type=Path, default=METRICS_PATH)
    args = ap.parse_args()

    decisions = _read_jsonl(args.decisions)
    ground_truth = _read_jsonl(args.ground_truth)
    metrics = evaluate(decisions, ground_truth)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")

    o = metrics["overall"]
    print(f"[evaluate] {EVAL_VERSION}: scored {metrics['n_scored']} cases "
          f"-> {args.out.name}")
    print(f"  overall    : TP={o['tp']} FP={o['fp']} TN={o['tn']} FN={o['fn']}")
    print(f"  precision={o['precision']} recall={o['recall_detection_rate']} "
          f"FPR={o['false_positive_rate']} F1={o['f1']}")
    ft = metrics["by_split"].get("final_test")
    if ft:
        print(f"  final_test : recall={ft['recall_detection_rate']} "
              f"precision={ft['precision']} FPR={ft['false_positive_rate']}")
    print(f"  leakage    : {metrics['integrity']['label_leakage_check']}")


if __name__ == "__main__":
    main()
