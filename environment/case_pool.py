#!/usr/bin/env python3
"""Stable case pool for CYBER-EVO co-evolution.

A *case* is the stable evaluation unit: its identity (``case_id``), label
(``attack_present``), and dataset ``split`` never change across rounds, so a
held-out case stays held out for the whole experiment. What changes round to
round is only the *observable telemetry* an attack case produces, because the
Red agent re-renders attacks under its evolving strategy.

This module owns:

* the shared vocabulary (parents + signature flags) the agents are
  parameterised with, and
* ``build_pool`` -- a seeded, stratified pool of attack and benign cases.

Benign cases are rendered once and fixed (stable background / false-positive
baseline). Attack cases carry only their intent here; the Red agent renders
them (see ``red-agent/red_agent.py``).

Signature-token model (used by the loop's agents): a "signature" is a
flag-like token (starts with ``-`` or ``obf_``). Normal benign activity uses
no such flags, so it never triggers Blue. The ambiguous flag deliberately
appears in both some attacks and some benign look-alikes, so that when Blue
learns it from a confirmed attack it also starts producing false positives --
the cost of adaptation (hypothesis 3).
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field

SCHEMA_VERSION = "coevo-S001-v1"

# Parent processes.
BENIGN_PARENTS = ["explorer.exe", "cmd.exe", "powershell_ise.exe",
                  "services.exe", "taskeng.exe"]
ANOMALOUS_PARENTS = ["winword.exe", "excel.exe", "outlook.exe",
                     "wscript.exe", "mshta.exe"]

# Signature flags Blue knows at the start (condition-A/baseline knowledge).
KNOWN_FLAGS = ["-enc", "-encodedcommand", "-w", "-nop"]

# Ambiguous flag: NOT known to Blue initially, present in some attacks AND
# some benign look-alikes. Learning it raises recall but costs precision.
AMBIGUOUS_FLAG = "-ep_bypass"

# Benign command bodies that carry no signature flag (never false-positive).
BENIGN_BODIES = [
    "Get-ChildItem C:\\Users -Recurse",
    "Get-Process | Sort-Object CPU",
    "Import-Module ActiveDirectory; Get-ADUser alice",
    "Get-Service | Where-Object Status -eq Running",
    "$PSVersionTable",
]


@dataclass
class Case:
    case_id: str
    attack_present: bool
    split: str                       # adaptation | validation | final_test
    generalization_category: str = "known_technique"
    technique_id: str | None = None
    # Benign cases are pre-rendered and fixed:
    fixed_parent: str | None = None
    fixed_cmdline: str | None = None


def _stratified_splits(rng: random.Random, cases: list[Case]) -> None:
    """60/20/20 split within each class so every split has both labels."""
    for present in (True, False):
        group = [c for c in cases if c.attack_present is present]
        rng.shuffle(group)
        n = len(group)
        n_adapt = int(round(n * 0.60))
        n_val = int(round(n * 0.20))
        for i, c in enumerate(group):
            c.split = ("adaptation" if i < n_adapt
                       else "validation" if i < n_adapt + n_val
                       else "final_test")


def build_pool(seed: int, n_attack: int = 60, n_benign: int = 60
               ) -> tuple[list[Case], dict]:
    """Return (cases, vocab). Deterministic in ``seed``."""
    rng = random.Random(seed)
    cases: list[Case] = []
    idx = 0

    for _ in range(n_attack):
        cases.append(Case(case_id=f"C{idx:04d}", attack_present=True,
                           split="adaptation", technique_id="T1059.001"))
        idx += 1

    for _ in range(n_benign):
        # ~30% look-alikes carry the ambiguous flag (false-positive traps).
        if rng.random() < 0.30:
            parent = rng.choice(BENIGN_PARENTS)
            cmdline = f"powershell.exe {AMBIGUOUS_FLAG} -File C:\\Scripts\\approved.ps1"
        else:
            parent = rng.choice(BENIGN_PARENTS)
            cmdline = f"powershell.exe -Command {rng.choice(BENIGN_BODIES)}"
        cases.append(Case(case_id=f"C{idx:04d}", attack_present=False,
                          split="adaptation", fixed_parent=parent,
                          fixed_cmdline=cmdline))
        idx += 1

    _stratified_splits(rng, cases)

    vocab = {
        "schema_version": SCHEMA_VERSION,
        "benign_parents": BENIGN_PARENTS,
        "anomalous_parents": ANOMALOUS_PARENTS,
        "known_flags": list(KNOWN_FLAGS),
        "ambiguous_flag": AMBIGUOUS_FLAG,
    }
    return cases, vocab


def tokenize_signatures(cmdline: str | None) -> set[str]:
    """Extract flag-like signature tokens from a command line.

    Shared by Red (knows what it emitted) and Blue (learns from confirmed
    attacks). A signature is a whitespace token starting with '-' or 'obf_'.
    """
    if not cmdline:
        return set()
    return {t for t in cmdline.lower().split()
            if t.startswith("-") or t.startswith("obf_")}
