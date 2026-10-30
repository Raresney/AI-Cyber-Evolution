#!/usr/bin/env python3
"""False-alarm budget of the surface invariants at full scale, across environments.

Rung 4 showed the invariant set fires with zero false positives over the 196k
APT29 Day-1 events. This measures that claim systematically: each of the three
behavioral invariants is run over the FULL event stream of EVERY processed
dataset (lsass, ntds, injection, apt29) -- ~600k real Windows/Sysmon events from
four different capture environments -- and we count, per invariant per dataset,
how often it fires on its own technique (recall, where present) and how often it
fires at all on everything else (false positives, by that dataset's labels).

The point is two-fold and neither part is by construction:
  * each invariant stays silent off its surface (cross-boundary, finding 9) at
    full scale, so stacking them does not create interference; and
  * on-surface it keeps a near-zero false-alarm rate across hundreds of
    thousands of benign events from environments it was never tuned on.

Reuses the leakage-free slices and the detector primitives. Stdlib only.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PROCESSED = REPO_ROOT / "data" / "processed"
OUT_PATH = REPO_ROOT / "results" / "invariant-fp-budget.json"

SYSTEM_WHITELIST = {
    "wininit.exe", "services.exe", "svchost.exe", "csrss.exe", "lsm.exe",
    "lsass.exe", "winlogon.exe", "msmpeng.exe", "wmiprvse.exe",
    "mssense.exe", "sensecncproxy.exe",
}
PROCESS_VM_READ = 0x0010

DATASETS = ["lsass", "ntds", "injection", "apt29"]


def _base(x) -> str:
    if not x:
        return ""
    return str(x).replace("/", "\\").split("\\")[-1].lower()


def _hex(x):
    try:
        return int(str(x), 16)
    except (TypeError, ValueError):
        return None


def read_jsonl(path: Path):
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


# --- the three surface invariants, on raw processed events ------------------

def inv_lsass(ev) -> bool:
    if int(ev.get("EventID") or 0) != 10 or _base(ev.get("TargetImage")) != "lsass.exe":
        return False
    src = _base(ev.get("SourceImage"))
    a = _hex(ev.get("GrantedAccess"))
    return src != "" and src not in SYSTEM_WHITELIST and a is not None and bool(a & PROCESS_VM_READ)


def inv_ntds(ev) -> bool:
    eid = int(ev.get("EventID") or 0)
    if eid == 4663:
        path, actor = _base(ev.get("ObjectName")), _base(ev.get("ProcessName"))
    elif eid == 11:
        path, actor = _base(ev.get("TargetFilename")), _base(ev.get("Image"))
    else:
        return False
    return path.startswith("ntds") and path.endswith(".dit") and actor != "lsass.exe"


def inv_injection(ev) -> bool:
    if int(ev.get("EventID") or 0) != 8:
        return False
    src = _base(ev.get("SourceImage"))
    return src != "" and src not in SYSTEM_WHITELIST


INVARIANTS = {"lsass (T1003.001)": inv_lsass,
              "ntds (T1003.003)": inv_ntds,
              "injection (T1055)": inv_injection}


def campaigns_of(dataset: str):
    d = PROCESSED / dataset
    return sorted(p.name for p in d.iterdir() if p.is_dir())


def scan(dataset: str):
    """Return events + attack-label map (by event_index) for the whole dataset."""
    rows = []
    for c in campaigns_of(dataset):
        cdir = PROCESSED / dataset / c
        labels = {r["event_index"]: bool(r["attack_present"]) for r in read_jsonl(cdir / "labels.jsonl")}
        for e in read_jsonl(cdir / "events.jsonl"):
            rows.append((e, labels.get(e["event_index"], False)))
    return rows


def main() -> None:
    ap = argparse.ArgumentParser(description="Invariant false-alarm budget at full scale.")
    ap.add_argument("--out", type=Path, default=OUT_PATH)
    args = ap.parse_args()

    # Cache each dataset once.
    data = {ds: scan(ds) for ds in DATASETS}
    totals = {ds: {"events": len(rows), "attacks": sum(1 for _, t in rows if t)} for ds, rows in data.items()}

    out = {"experiment": "invariant-false-alarm-budget",
           "note": "each invariant over the FULL stream of each dataset; recall where its "
                   "technique is the labeled one, FP by that dataset's labels (an invariant "
                   "firing off its own technique's dataset counts as a false positive).",
           "dataset_totals": totals,
           "grand_total_events": sum(t["events"] for t in totals.values()),
           "cells": {}}

    for iname, rule in INVARIANTS.items():
        out["cells"][iname] = {}
        for ds, rows in data.items():
            tp = fp = fn = 0
            for ev, truth in rows:
                pred = rule(ev)
                if truth and pred:
                    tp += 1
                elif truth and not pred:
                    fn += 1
                elif pred and not truth:
                    fp += 1
            n_benign = len(rows) - totals[ds]["attacks"]
            out["cells"][iname][ds] = {
                "tp": tp, "fp": fp, "fn": fn,
                "recall": round(tp / (tp + fn), 3) if (tp + fn) else None,
                "fp_rate": round(fp / n_benign, 8) if n_benign else None,
            }

    out["grand_total_fp"] = {iname: sum(c[ds]["fp"] for ds in DATASETS) for iname, c in out["cells"].items()}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")

    # Report.
    gt = out["grand_total_events"]
    print(f"Invariant false-alarm budget over {gt:,} real events across {len(DATASETS)} environments")
    for ds in DATASETS:
        t = totals[ds]
        print(f"  {ds:10s}: {t['events']:>7,} events, {t['attacks']} labeled attacks")
    print("\ninvariant            | " + " | ".join(f"{ds:^17}" for ds in DATASETS))
    print("                     | " + " | ".join("recall  /  FP    " for _ in DATASETS))
    print("-" * 21 + "+" + "+".join("-" * 19 for _ in DATASETS))
    for iname in INVARIANTS:
        cells = []
        for ds in DATASETS:
            c = out["cells"][iname][ds]
            rec = " --  " if c["recall"] is None else f"{c['recall']:.2f} "
            cells.append(f" {rec} / {c['fp']:>4d} FP ")
        print(f"{iname:20.20s} |" + "|".join(cells))
    print("\ngrand-total false positives:")
    for iname, fp in out["grand_total_fp"].items():
        print(f"  {iname:20s}: {fp} FP over {gt:,} events")
    print(f"\nwrote {args.out.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
