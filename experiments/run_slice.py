#!/usr/bin/env python3
"""End-to-end runner for the CYBER-EVO S001 vertical slice.

Orchestrates one round of the pipeline:

    environment (generate telemetry)
        -> blue-agent (decide)
        -> evaluation (score)

and writes a reproducibility record (experimental-design doc, "Reproducibility
Requirements") capturing seed, versions, config, scenario ids, telemetry
config, splits, git commit, timestamp and a metric summary.

Stages run as separate subprocesses so each remains independently runnable and
communicates only through the on-disk jsonl contract (no shared imports --
the agent directories use hyphens and are intentionally decoupled).

This slice realises experimental condition A (static Red implied by a fixed
scenario set vs. static baseline Blue). Adaptive Red/Blue and the co-evolution
loop build on top of this same contract.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
GENERATE = REPO_ROOT / "environment" / "generate_telemetry.py"
BLUE = REPO_ROOT / "blue-agent" / "baseline_blue.py"
EVALUATE = REPO_ROOT / "evaluation" / "evaluate.py"
RESULTS_DIR = REPO_ROOT / "results"

RUNNER_VERSION = "run-slice-v1"


def run_stage(script: Path, *stage_args: str) -> None:
    cmd = [sys.executable, str(script), *stage_args]
    print(f"\n$ {script.name} {' '.join(stage_args)}")
    subprocess.run(cmd, check=True)


def _git_commit() -> str | None:
    try:
        out = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, check=True)
        return out.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def main() -> None:
    ap = argparse.ArgumentParser(description="Run the CYBER-EVO S001 slice end to end.")
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--n-cases", type=int, default=60)
    ap.add_argument("--condition", default="A",
                    help="experimental condition label for the run record")
    args = ap.parse_args()

    started = datetime.now(timezone.utc)

    run_stage(GENERATE, "--seed", str(args.seed), "--n-cases", str(args.n_cases))
    run_stage(BLUE)
    run_stage(EVALUATE)

    manifest = _load_json(REPO_ROOT / "telemetry" / "dataset-manifest.json")
    blue_cfg = _load_json(RESULTS_DIR / "blue-config.json")
    metrics = _load_json(RESULTS_DIR / "metrics.json")
    overall = metrics.get("overall", {})

    record = {
        "runner_version": RUNNER_VERSION,
        "experimental_condition": args.condition,
        "timestamp": started.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "git_commit": _git_commit(),
        # Reproducibility fields (experimental-design doc).
        "seed": args.seed,
        "model": blue_cfg.get("blue_version", "unknown"),
        "agent_config": blue_cfg,
        "environment_version": manifest.get("schema_version"),
        "attack_version": manifest.get("attack_version"),
        "scenario_ids": ["S001"],
        "telemetry_config": manifest.get("conditions"),
        "splits": manifest.get("splits"),
        "class_balance": manifest.get("class_balance"),
        "eval_version": metrics.get("eval_version"),
        "metric_summary": {
            "overall": {
                "precision": overall.get("precision"),
                "recall_detection_rate": overall.get("recall_detection_rate"),
                "false_positive_rate": overall.get("false_positive_rate"),
                "f1": overall.get("f1"),
            },
            "final_test": {
                k: metrics.get("by_split", {}).get("final_test", {}).get(k)
                for k in ("precision", "recall_detection_rate",
                          "false_positive_rate", "f1")
            },
        },
        "label_leakage_check": metrics.get("integrity", {}).get("label_leakage_check"),
    }

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = started.strftime("%Y%m%dT%H%M%SZ")
    record_path = RESULTS_DIR / f"run-{stamp}.json"
    record_path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    # Also keep a stable pointer to the latest run.
    (RESULTS_DIR / "latest-run.json").write_text(
        json.dumps(record, indent=2) + "\n", encoding="utf-8")

    print("\n=== RUN COMPLETE ===")
    print(f"  condition  : {record['experimental_condition']}  "
          f"model={record['model']}  seed={record['seed']}")
    print(f"  overall    : {record['metric_summary']['overall']}")
    print(f"  final_test : {record['metric_summary']['final_test']}")
    print(f"  record     : results/{record_path.name}")


if __name__ == "__main__":
    main()
