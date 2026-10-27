#!/usr/bin/env python3
"""Co-evolution loop for CYBER-EVO (experimental conditions A-D).

Runs repeated Red/Blue rounds over a stable case pool and records how attack
success and detection move over time. Realizes the conditions from the README:

    A  Red static , Blue static   -- baseline
    B  Red adaptive, Blue static  -- can an adaptive attacker beat a fixed defense?
    C  Red static , Blue adaptive -- defensive adaptation vs a fixed attacker
    D  Red adaptive, Blue adaptive -- the co-evolution arms race

Each round:
  1. Red renders ALL cases' attack telemetry (benign telemetry is fixed).
  2. Blue decides on every case using its current knowledge.
  3. Evaluate BEFORE this round's adaptation (overall + held-out final_test).
  4. Red adapts on adaptation+validation attacks; Blue learns from adaptation
     attacks only. final_test is never used to adapt.

Agents live in hyphenated dirs (red-agent/, blue-agent/) that are not Python
packages, so they are loaded by file path. Scoring reuses evaluation/evaluate.py.

Metrics per round: detection rate (strict: only 'detect'), attack success rate
(ASR = 1 - detection rate), false-positive rate on benign, investigate load,
and the same on the held-out final_test split, plus Red/Blue strategy snapshots.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = REPO_ROOT / "results"
LOOP_VERSION = "coevolution-v1"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    # Register before exec so dataclasses can resolve the module by name.
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod

# Make `import case_pool` resolve for the agent modules (they import vocab).
_cp_path = REPO_ROOT / "environment" / "case_pool.py"
sys.path.insert(0, str(_cp_path.parent))
case_pool = _load(_cp_path, "case_pool")
red_mod = _load(REPO_ROOT / "red-agent" / "red_agent.py", "red_agent")
blue_mod = _load(REPO_ROOT / "blue-agent" / "adaptive_blue.py", "adaptive_blue")
evaluate = _load(REPO_ROOT / "evaluation" / "evaluate.py", "evaluate")

CONDITIONS = {
    "A": (False, False),
    "B": (True, False),
    "C": (False, True),
    "D": (True, True),
}


def _metrics(pairs):
    """confusion() -> trimmed per-round view."""
    c = evaluate.confusion(pairs)
    n_attack = c["tp"] + c["fn"]
    asr = round(1 - c["recall_detection_rate"], 4) if c["recall_detection_rate"] is not None else None
    return {
        "n": c["n"], "n_attack": n_attack,
        "detection_rate": c["recall_detection_rate"],
        "asr": asr,
        "precision": c["precision"],
        "false_positive_rate": c["false_positive_rate"],
        "investigate_on_attack": c["investigate_on_attack"],
        "investigate_on_benign": c["investigate_on_benign"],
        "tp": c["tp"], "fp": c["fp"], "tn": c["tn"], "fn": c["fn"],
    }


def run(condition: str, rounds: int, seed: int, n_attack: int, n_benign: int) -> dict:
    red_adaptive, blue_adaptive = CONDITIONS[condition]
    cases, vocab = case_pool.build_pool(seed, n_attack, n_benign)
    cases_by_id = {c.case_id: c for c in cases}
    attack_cases = [c for c in cases if c.attack_present]
    benign_cases = [c for c in cases if not c.attack_present]

    red = red_mod.RedAgent(adaptive=red_adaptive)
    blue = blue_mod.AdaptiveBlue(adaptive=blue_adaptive)

    series = []
    for r in range(rounds):
        round_seed = seed * 1000 + r

        # 1. Red renders attacks; benign telemetry is fixed background.
        events_by_case: dict[str, list[dict]] = {}
        for ev in red.render(attack_cases, round_seed):
            events_by_case.setdefault(ev["case_id"], []).append(ev)
        for c in benign_cases:
            events_by_case[c.case_id] = [{
                "case_id": c.case_id,
                "timestamp": "2026-10-13T09:00:00Z",
                "host": "WIN-09", "user": "svc", "process": "powershell.exe",
                "parent_process": c.fixed_parent,
                "process_id": 5000, "parent_process_id": 1200,
                "command_line": c.fixed_cmdline,
                "integrity_level": "Medium",
                "event_source": "synthetic_process_telemetry",
            }]

        # 2. Blue decides.
        decisions = blue.decide(events_by_case)

        # 3. Evaluate BEFORE adaptation (current generalization).
        overall_pairs, ft_pairs = [], []
        for cid, case in cases_by_id.items():
            pair = (case.attack_present, decisions[cid]["decision"])
            overall_pairs.append(pair)
            if case.split == "final_test":
                ft_pairs.append(pair)

        red_snap = red.snapshot()
        blue_snap = blue.snapshot()

        # 4. Adapt (Red on adapt+val attacks, Blue on adapt attacks only).
        red_after = red.adapt(decisions)
        blue_after = blue.adapt(events_by_case, cases_by_id)

        series.append({
            "round": r,
            "overall": _metrics(overall_pairs),
            "final_test": _metrics(ft_pairs),
            "red_strategy": red_snap,
            "blue_knowledge": {"known_signature_count": blue_snap["known_signature_count"],
                               "learned_total": blue_snap["learned_total"]},
            "red_adapt": {"p_benign_parent": red_after["p_benign_parent"],
                          "p_novel_token": red_after["p_novel_token"],
                          "minted_this_round": red_after["minted_this_round"],
                          "current_novel": red_after["current_novel"]},
            "blue_adapt": {"learned_this_round": blue_after["learned_this_round"]},
        })

    return {
        "loop_version": LOOP_VERSION,
        "condition": condition,
        "condition_meaning": {"red_adaptive": red_adaptive, "blue_adaptive": blue_adaptive},
        "seed": seed,
        "rounds": rounds,
        "schema_version": vocab["schema_version"],
        "pool": {"n_attack": len(attack_cases), "n_benign": len(benign_cases),
                 "splits": {s: sum(c.split == s for c in cases)
                            for s in ("adaptation", "validation", "final_test")}},
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "series": series,
    }


def _fmt(x):
    return "  n/a" if x is None else f"{x:5.2f}"


def print_table(result: dict) -> None:
    print(f"\n=== Condition {result['condition']} "
          f"(Red adaptive={result['condition_meaning']['red_adaptive']}, "
          f"Blue adaptive={result['condition_meaning']['blue_adaptive']}) "
          f"| seed={result['seed']} rounds={result['rounds']} ===")
    print("rnd | det_all  asr  fpr | det_FT | p_benP p_novT mint | blue_sigs")
    print("----+--------------------+--------+--------------------+----------")
    for s in result["series"]:
        o, ft, ra = s["overall"], s["final_test"], s["red_adapt"]
        mint = "*" if ra["minted_this_round"] else " "
        print(f"{s['round']:3d} | "
              f"{_fmt(o['detection_rate'])} {_fmt(o['asr'])} {_fmt(o['false_positive_rate'])} | "
              f"{_fmt(ft['detection_rate'])} | "
              f"{ra['p_benign_parent']:5.2f} {ra['p_novel_token']:5.2f}  {mint}  | "
              f"{s['blue_knowledge']['known_signature_count']:3d}")


def main() -> None:
    ap = argparse.ArgumentParser(description="CYBER-EVO co-evolution loop.")
    ap.add_argument("--condition", choices=list(CONDITIONS), default="D")
    ap.add_argument("--rounds", type=int, default=10)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--n-attack", type=int, default=60)
    ap.add_argument("--n-benign", type=int, default=60)
    ap.add_argument("--all", action="store_true", help="run A,B,C,D")
    args = ap.parse_args()

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    conditions = list(CONDITIONS) if args.all else [args.condition]

    summary = {}
    for cond in conditions:
        result = run(cond, args.rounds, args.seed, args.n_attack, args.n_benign)
        print_table(result)
        out = RESULTS_DIR / f"coevolution-{cond}-{stamp}.json"
        out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        first, last = result["series"][0]["overall"], result["series"][-1]["overall"]
        summary[cond] = {
            "detection_first": first["detection_rate"],
            "detection_last": last["detection_rate"],
            "asr_first": first["asr"],
            "asr_last": last["asr"],
            "fpr_last": last["false_positive_rate"],
            "tokens_minted": result["series"][-1]["red_strategy"]["tokens_minted"],
            "record": out.name,
        }

    (RESULTS_DIR / "coevolution-summary.json").write_text(
        json.dumps({"seed": args.seed, "rounds": args.rounds, "conditions": summary},
                   indent=2) + "\n", encoding="utf-8")
    print("\n=== SUMMARY (first -> last round) ===")
    for cond, s in summary.items():
        print(f"  {cond}: detection {_fmt(s['detection_first'])} -> {_fmt(s['detection_last'])}"
              f" | asr {_fmt(s['asr_first'])} -> {_fmt(s['asr_last'])}"
              f" | fpr_last {_fmt(s['fpr_last'])} | minted {s['tokens_minted']}")


if __name__ == "__main__":
    main()
