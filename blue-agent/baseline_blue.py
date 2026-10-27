#!/usr/bin/env python3
"""Baseline Blue agent for CYBER-EVO (deterministic heuristic).

This is condition-A Blue: a fixed, non-adaptive detector. It gives the
co-evolution experiments a reproducible floor to measure adaptive agents
against, and exercises the full pipeline without any model/API cost. An
LLM-backed Blue (local llama3.2 or an API model) plugs in later behind the
same input/output contract.

Contract (schema doc section 8): reads Blue-visible events, groups them by
``case_id``, and emits one decision per case:

    {
      "case_id": ...,
      "decision": "detect | no_alert | investigate",
      "technique_hypothesis": "T1059.001 | unknown",
      "confidence": 0.0-1.0,
      "evidence": [...observed fields...],
      "recommended_response": "investigate | contain | no_action"
    }

The agent sees telemetry only. It never reads ground truth, the split, or the
telemetry condition. Evidence references observed fields, never hidden labels.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
EVENTS_PATH = REPO_ROOT / "telemetry" / "events.jsonl"
DECISIONS_PATH = REPO_ROOT / "results" / "blue-decisions.jsonl"

BLUE_VERSION = "baseline-heuristic-v1"

# Detection knowledge: inert substrings that mark high-risk PowerShell usage.
SUSPICIOUS_PARENTS = {"winword.exe", "excel.exe", "outlook.exe",
                      "wscript.exe", "mshta.exe", "cscript.exe"}
SUSPICIOUS_TOKENS = [
    "-enc", "-encodedcommand", "frombase64string",
    "downloadstring", "invoke-webrequest", "iwr ", "iex",
    "-w hidden", "-windowstyle hidden", "-nop",
    "bypass", "new-object net.webclient",
]

# Decision thresholds over the integer suspicion score.
DETECT_AT = 2
INVESTIGATE_AT = 1

CONFIG = {
    "blue_version": BLUE_VERSION,
    "suspicious_parents": sorted(SUSPICIOUS_PARENTS),
    "suspicious_tokens": SUSPICIOUS_TOKENS,
    "detect_at": DETECT_AT,
    "investigate_at": INVESTIGATE_AT,
}


def load_cases(events_path: Path) -> dict[str, list[dict]]:
    cases: dict[str, list[dict]] = {}
    with events_path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            ev = json.loads(line)
            cases.setdefault(ev["case_id"], []).append(ev)
    return cases


def assess(case_id: str, events: list[dict]) -> dict:
    """Score a single case and produce a decision."""
    score = 0
    evidence: list[str] = []
    missing_cmdline = False

    # Focus on the powershell events; ignore unrelated noise processes.
    shells = [e for e in events if e.get("process") == "powershell.exe"]
    considered = shells or events

    for e in considered:
        parent = (e.get("parent_process") or "").lower()
        if parent in SUSPICIOUS_PARENTS:
            score += 1
            evidence.append(f"anomalous parent {e.get('parent_process')} -> powershell.exe")

        cmd = e.get("command_line")
        if cmd is None:
            missing_cmdline = True
        else:
            low = cmd.lower()
            hit = next((t for t in SUSPICIOUS_TOKENS if t in low), None)
            if hit:
                score += 1
                evidence.append(f"suspicious command-line token '{hit.strip()}'")

    # Absent key evidence: cannot clear the case, lean to investigate.
    if missing_cmdline and score < DETECT_AT:
        evidence.append("command_line missing -- evidence incomplete")

    if score >= DETECT_AT:
        decision, response = "detect", "contain"
    elif score >= INVESTIGATE_AT or missing_cmdline:
        decision, response = "investigate", "investigate"
    else:
        decision, response = "no_alert", "no_action"

    # Confidence: scaled score, damped when key evidence is missing.
    confidence = min(1.0, 0.3 + 0.35 * score)
    if missing_cmdline:
        confidence = min(confidence, 0.5)
    if decision == "no_alert":
        confidence = 0.6  # moderately sure nothing stands out

    hypothesis = "T1059.001" if decision != "no_alert" else "unknown"

    return {
        "case_id": case_id,
        "decision": decision,
        "technique_hypothesis": hypothesis,
        "confidence": round(confidence, 2),
        "evidence": evidence or ["no suspicious indicators in observed events"],
        "recommended_response": response,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Baseline heuristic Blue agent.")
    ap.add_argument("--events", type=Path, default=EVENTS_PATH)
    ap.add_argument("--out", type=Path, default=DECISIONS_PATH)
    args = ap.parse_args()

    cases = load_cases(args.events)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    # Sidecar config for the reproducibility record.
    (args.out.parent / "blue-config.json").write_text(
        json.dumps(CONFIG, indent=2) + "\n", encoding="utf-8")

    counts = {"detect": 0, "investigate": 0, "no_alert": 0}
    with args.out.open("w", encoding="utf-8", newline="\n") as f:
        for case_id in sorted(cases):
            decision = assess(case_id, cases[case_id])
            counts[decision["decision"]] += 1
            f.write(json.dumps(decision) + "\n")

    print(f"[baseline_blue] {BLUE_VERSION}: {len(cases)} cases -> {args.out.name}")
    print(f"  decisions  : {counts}")


if __name__ == "__main__":
    main()
