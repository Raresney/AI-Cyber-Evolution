#!/usr/bin/env python3
"""Layered detection across the ladder: the constructive counterpart to the map.

Every earlier rung is diagnostic -- it shows where each detector family fails.
This asks the defender's question: if you *stack* the precise surface invariant
under the broad LLM, what operating point do you get at each ladder distance?

It reuses the per-event verdicts the LLM detectors already wrote
(``results/llm-*-14b.json``). Each verdict carries the raw Sysmon fields the
behavioral invariant needs (source/granted, actor/path/eid, src/tgt), so the
invariant's decision is recomputed per verdict and joined to the LLM's on the
*identical* judged event set -- attack events plus the LLM's benign subsample.
No model is re-run; this is an offline analysis of saved verdicts.

Two layered detectors per rung:

* **union** (inv OR llm) -- the coverage ceiling of running both.
* **cascade** -- the invariant is the trusted *block* tier (high confidence);
  the LLM judges only invariant-negatives, as a *triage* tier. We report the
  block tier's recall/FP and the extra recall/FP the triage tier adds.

The point is not that stacking beats the frontier (it cannot) but *which tier a
defender gets at each distance*: a 0-FP high-confidence tier exactly where a
surface invariant applies, degenerating to noisy LLM-only triage where none does.
Stdlib only.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = REPO_ROOT / "results"

SYSTEM_WHITELIST = {
    "wininit.exe", "services.exe", "svchost.exe", "csrss.exe", "lsm.exe",
    "lsass.exe", "winlogon.exe", "msmpeng.exe", "wmiprvse.exe",
    "mssense.exe", "sensecncproxy.exe",
}
PROCESS_VM_READ = 0x0010

# Each rung: verdict file (best-recall 14B config the ladder summary headlines),
# the DEPLOYED invariant rules the defender has already built when this rung's
# technique appears (never a rule for the rung's own novel technique -- that is
# the ladder premise), and a campaign holdout filter.
RUNGS = [
    ("1 new-instance",    "llm-fewshot-detection-14b.json",     ["lsass"],                     {"04", "05", "06", "07"}),
    ("2 new-subtechnique", "llm-subtechnique-fewshot-14b.json", ["lsass"],                     None),
    ("3 new-technique",   "llm-technique-zeroshot-14b.json",    ["lsass", "ntds"],             None),
    ("4 new-chain",       "llm-chain-detection-14b.json",       ["lsass", "ntds", "injection"], None),
]


def _base(x) -> str:
    if not x:
        return ""
    return str(x).replace("/", "\\").split("\\")[-1].lower()


def _hex(x):
    try:
        return int(str(x), 16)
    except (TypeError, ValueError):
        return None


def _rule_lsass(v: dict) -> bool:
    """LSASS-memory invariant: non-system source reads lsass with VM_READ."""
    eid = int(v.get("eid") or 10)  # rung-1 lsass verdicts omit eid (all EID10)
    tgt = _base(v.get("tgt") or v.get("target") or "lsass.exe")
    src = _base(v.get("source") or v.get("src"))
    a = _hex(v.get("granted") or v.get("ga"))
    return (eid == 10 and tgt == "lsass.exe" and src != "" and src not in SYSTEM_WHITELIST
            and a is not None and bool(a & PROCESS_VM_READ))


def _rule_ntds(v: dict) -> bool:
    """NTDS invariant: file create / object access to ntds*.dit off a non-lsass actor."""
    eid = int(v.get("eid") or 0)
    actor = _base(v.get("actor") or v.get("src"))
    path = _base(v.get("path"))
    return eid in (11, 4663) and path.startswith("ntds") and path.endswith(".dit") and actor != "lsass.exe"


def _rule_injection(v: dict) -> bool:
    """Injection invariant: CreateRemoteThread (EID8) from a non-system source."""
    eid = int(v.get("eid") or 0)
    src = _base(v.get("src") or v.get("source"))
    return eid == 8 and src != "" and src not in SYSTEM_WHITELIST


RULES = {"lsass": _rule_lsass, "ntds": _rule_ntds, "injection": _rule_injection}


def invariant_pred(deployed: list[str], v: dict) -> bool:
    """The defender's DEPLOYED invariant set, each rule applied to the event.

    A rule whose surface does not match the event simply does not fire, so this
    reproduces the ladder's cross-boundary transfer: the LSASS rule on an NTDS
    or injection event returns False, which is exactly the 0.00 transfer the
    ladder measured. On the chain, the union fires on the techniques it covers.
    """
    return any(RULES[name](v) for name in deployed)


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
    prec = round(tp / (tp + fp), 3) if (tp + fp) else None
    rec = round(tp / (tp + fn), 3) if (tp + fn) else None
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": prec, "recall": rec}


def run_rung(verdict_file: Path, deployed: list[str], holdout: set | None):
    j = json.loads(verdict_file.read_text(encoding="utf-8"))
    verdicts = j["verdicts"]
    rows = []
    for v in verdicts:
        if holdout is not None:
            camp = str(v.get("campaign", ""))
            if camp.split("_")[-1] not in holdout:
                continue
        truth = bool(v["truth"])
        llm = bool(v["pred"])
        inv = invariant_pred(deployed, v)
        rows.append((truth, inv, llm))

    inv_pairs = [(t, i) for t, i, _ in rows]
    llm_pairs = [(t, l) for t, _, l in rows]
    union_pairs = [(t, i or l) for t, i, l in rows]

    # Cascade: invariant = block tier; LLM triages only invariant-negatives.
    block_tp = sum(1 for t, i, _ in rows if t and i)
    block_fp = sum(1 for t, i, _ in rows if (not t) and i)
    n_attack = sum(1 for t, _, _ in rows if t)
    triage_tp = sum(1 for t, i, l in rows if t and (not i) and l)   # caught only by LLM
    triage_fp = sum(1 for t, i, l in rows if (not t) and (not i) and l)
    missed = sum(1 for t, i, l in rows if t and (not i) and (not l))

    return {
        "n_events": len(rows), "n_attack": n_attack,
        "invariant": confusion(inv_pairs),
        "llm": confusion(llm_pairs),
        "union": confusion(union_pairs),
        "cascade": {
            "block_tier": {"tp": block_tp, "fp": block_fp,
                           "recall": round(block_tp / n_attack, 3) if n_attack else None},
            "triage_tier": {"extra_tp": triage_tp, "extra_fp": triage_fp},
            "still_missed": missed,
        },
    }


def _rp(m):
    r = " n/a" if m["recall"] is None else f"{m['recall']:4.2f}"
    p = " n/a" if m["precision"] is None else f"{m['precision']:4.2f}"
    return f"{r}/{p}"


def main() -> None:
    ap = argparse.ArgumentParser(description="Layered detection across the ladder (offline).")
    ap.add_argument("--results", type=Path, default=RESULTS_DIR)
    ap.add_argument("--out", type=Path, default=RESULTS_DIR / "ensemble-ladder.json")
    args = ap.parse_args()

    out = {"experiment": "layered-detection-ladder", "model": "qwen2.5:14b",
           "note": "inv/llm/stack on the identical LLM-judged event set (attacks + benign subsample); "
                   "invariant recomputed per verdict, so values are on the subsample, not the full stream.",
           "rungs": {}}

    print("Layered detection across the ladder (recall/precision on the LLM-judged subsample)")
    print("rung               | invariant | llm       | union     | cascade block(rec,fp) | triage(+tp,+fp)")
    print("-------------------+-----------+-----------+-----------+-----------------------+----------------")
    for label, fname, deployed, holdout in RUNGS:
        res = run_rung(args.results / fname, deployed, holdout)
        out["rungs"][label] = {"deployed_invariants": deployed, "source_file": fname, **res}
        c = res["cascade"]
        bt, tt = c["block_tier"], c["triage_tier"]
        br = " n/a" if bt["recall"] is None else f"{bt['recall']:.2f}"
        print(f"{label:18.18s} | {_rp(res['invariant'])} | {_rp(res['llm'])} | {_rp(res['union'])} | "
              f"rec={br} fp={bt['fp']:<2d}          | +{tt['extra_tp']}tp/+{tt['extra_fp']}fp")

    args.out.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print(f"\nwrote {args.out.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
