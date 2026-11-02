#!/usr/bin/env python3
"""Reproduce CYBER-EVO's headline results.

Two tiers:

* ``--offline`` (default, CI-safe): reproduces everything that needs only the
  committed artifacts and the standard library -- the synthetic co-evolution
  dynamics (conditions A--D) and the layered-detection table (recomputed from the
  committed LLM verdicts). No telemetry download, no Ollama, no network.

* ``--full``: additionally re-runs the data-dependent pipeline (real-telemetry
  detectors, scale ablation, arms race, FP budget, cross-dataset) if the slices
  are present under ``data/processed/`` and -- for the LLM rungs -- a local
  Ollama is reachable. Missing prerequisites are skipped with a clear note rather
  than failing.

Each reproduced claim is asserted against its published value, so a regression
makes this script exit non-zero.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent
RES = REPO / "results"
PASS, FAIL = "PASS", "FAIL"
_failures = []


def load(rel: str, name: str):
    spec = importlib.util.spec_from_file_location(name, REPO / rel)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def check(label: str, cond: bool, detail: str = "") -> None:
    tag = PASS if cond else FAIL
    print(f"  [{tag}] {label}" + (f"  ({detail})" if detail else ""))
    if not cond:
        _failures.append(label)


def approx(a, b, tol=0.02) -> bool:
    return a is not None and abs(a - b) <= tol


# --------------------------------------------------------------------------- #
def repro_coevolution() -> None:
    print("\n== Synthetic co-evolution (self-contained, seed 1337) ==")
    coev = load("experiments/coevolution.py", "coevolution")
    last = {c: coev.run(c, rounds=12, seed=1337, n_attack=60, n_benign=60)
            ["series"][-1]["overall"]["detection_rate"] for c in ("A", "B", "C", "D")}
    check("B: adaptive Red collapses a static Blue (detection -> ~0)",
          last["B"] is not None and last["B"] < 0.2, f"det_last={last['B']}")
    check("C: adaptive Blue generalizes vs static Red (detection -> high)",
          last["C"] is not None and last["C"] > 0.8, f"det_last={last['C']}")


def repro_layering() -> None:
    print("\n== Layered detection (recomputed from committed LLM verdicts) ==")
    ens = load("experiments/ensemble_ladder.py", "ensemble_ladder")
    want = {  # matched-invariant recall and 14B LLM recall per rung
        "1 new-instance":     (1.0, 1.0),
        "2 new-subtechnique": (0.0, 1.0),
        "3 new-technique":    (0.0, 0.33),
        "4 new-chain":        (1.0, 0.60),
    }
    for label, fname, deployed, holdout in ens.RUNGS:
        p = RES / fname
        if not p.exists():
            check(f"{label}: verdict file present", False, f"missing {fname}")
            continue
        r = ens.run_rung(p, deployed, holdout)
        inv_r, llm_r = r["invariant"]["recall"], r["llm"]["recall"]
        exp_inv, exp_llm = want[label]
        ok = (approx(inv_r if inv_r is not None else 0.0, exp_inv)
              and approx(llm_r, exp_llm, 0.03))
        check(f"{label}: invariant {inv_r} ~ {exp_inv}, LLM {llm_r} ~ {exp_llm}", ok)


def repro_full() -> None:
    print("\n== Full tier (data-dependent) ==")
    have_data = (REPO / "data" / "processed" / "lsass").exists()
    if not have_data:
        print("  [SKIP] data/processed/ not present -- re-pull via environment/*_loader.py "
              "(OTRF Security-Datasets), then re-run with --full.")
        return
    import subprocess
    for script, needs_ollama in [
        ("experiments/invariant_fp_budget.py", False),
        ("experiments/coevolution_real.py --all --sweep", False),
    ]:
        print(f"  running {script} ...")
        rc = subprocess.run([sys.executable, "-I", *script.split()], cwd=REPO).returncode
        check(f"{script}", rc == 0, f"rc={rc}")
    print("  note: the LLM rungs (experiments/llm_*_detector.py) additionally need a "
          "local Ollama on :11434 with the models pulled; run them manually with --model.")


def main() -> None:
    ap = argparse.ArgumentParser(description="Reproduce CYBER-EVO results.")
    ap.add_argument("--full", action="store_true", help="also run the data-dependent pipeline")
    args = ap.parse_args()

    print("CYBER-EVO reproduction" + (" (full)" if args.full else " (offline, CI-safe)"))
    repro_coevolution()
    repro_layering()
    if args.full:
        repro_full()

    print("\n" + ("=" * 40))
    if _failures:
        print(f"FAILED {len(_failures)} check(s): " + "; ".join(_failures))
        sys.exit(1)
    print("All reproduced checks PASSED.")


if __name__ == "__main__":
    main()
