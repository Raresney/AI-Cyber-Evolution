#!/usr/bin/env python3
"""OTRF APT29 (Evals Day 1) loader for the new-chain rung.

The previous rungs each held out a single technique in isolation. A real
intrusion is a *chain* of many techniques. We use the MITRE ATT&CK Evaluations
APT29 Day 1 emulation (OTRF Security-Datasets, compound/apt29), a multi-step
Windows intrusion of ~196k host events spanning roughly two dozen techniques, to
ask two questions a per-technique benchmark cannot:

1. **Cross-environment transfer.** The behavioral invariants were derived on
   small, isolated atomic captures. Do they still fire on the *same* techniques
   when they occur inside a full, noisy intrusion on a different host? We tag
   each event with the SAME derived ground-truth rules used in the atomic slices
   (LSASS T1003.001, NTDS T1003.003, injection T1055) and keep them evaluator-
   only; a detector sees telemetry only.

2. **Chain coverage.** Our detector set has a rule for three techniques. The
   APT29 Day 1 chain exercises many more. The labels here mark only the three we
   can derive reliably; the point (quantified in experiments/ladder_chain.py) is
   that per-technique detection illuminates a few steps of the kill chain and is
   dark for the rest.

Leakage-free contract, same as the other loaders. Ground truth is the UNION of
the three per-technique rules, each tagging its technique id; everything else is
benign for our purposes (an underestimate of true malice in the chain, stated as
a limitation). Stdlib only.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RAW = REPO_ROOT / "data" / "raw" / "otrf" / "apt29" / "day1"
DEFAULT_OUT = REPO_ROOT / "data" / "processed" / "apt29" / "day1"
DEFAULT_MANIFEST = REPO_ROOT / "results" / "apt29-slice-manifest.json"

SCHEMA_VERSION = "otrf-apt29-day1-v1"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


OTRF = _load(REPO_ROOT / "environment" / "otrf_loader.py", "otrf_loader")
NTDS = _load(REPO_ROOT / "environment" / "ntds_loader.py", "ntds_loader")
INJ = _load(REPO_ROOT / "environment" / "injection_loader.py", "injection_loader")

# Fields kept visible: union of what the three per-technique loaders need.
KEEP_FIELDS = sorted(set(OTRF.KEEP_FIELDS) | set(NTDS.KEEP_FIELDS) | set(INJ.KEEP_FIELDS))

# Reuse each slice's derived ground-truth rule unchanged.
RULES = [
    ("T1003.001", OTRF.is_lsass_dump),
    ("T1003.003", NTDS.is_ntds_dump),
    ("T1055", INJ.is_injection),
]


def tag(ev: dict):
    """Return the technique id this event is a decisive act of, or None."""
    for tid, rule in RULES:
        if rule(ev):
            return tid
    return None


def _find_json(raw_dir: Path) -> Path:
    jsons = list(raw_dir.glob("*.json"))
    if jsons:
        return max(jsons, key=lambda p: p.stat().st_size)
    zips = list(raw_dir.glob("*.zip"))
    if not zips:
        raise FileNotFoundError(f"no json/zip under {raw_dir}")
    with zipfile.ZipFile(zips[0]) as zf:
        names = [n for n in zf.namelist() if n.lower().endswith(".json")]
        zf.extract(names[0], raw_dir)
    return max(raw_dir.glob("*.json"), key=lambda p: p.stat().st_size)


def main() -> None:
    ap = argparse.ArgumentParser(description="Ingest OTRF APT29 Day1 into the leakage-free chain slice.")
    ap.add_argument("--raw", type=Path, default=DEFAULT_RAW)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    args = ap.parse_args()

    src = _find_json(args.raw)
    args.out.mkdir(parents=True, exist_ok=True)
    ev_path = args.out / "events.jsonl"
    lbl_path = args.out / "labels.jsonl"

    n = n_attack = 0
    by_technique: dict[str, int] = {}
    with src.open(encoding="utf-8", errors="replace") as fin, \
         ev_path.open("w", encoding="utf-8", newline="\n") as fev, \
         lbl_path.open("w", encoding="utf-8", newline="\n") as flbl:
        for line in fin:
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue
            idx = n
            n += 1
            tid = tag(raw)
            if tid:
                n_attack += 1
                by_technique[tid] = by_technique.get(tid, 0) + 1

            visible = {"event_index": idx}
            for k in KEEP_FIELDS:
                if k in raw:
                    visible[k] = raw[k]
            fev.write(json.dumps(visible) + "\n")
            flbl.write(json.dumps({
                "event_index": idx,
                "attack_present": bool(tid),
                "technique_id": tid,
            }) + "\n")

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "source": "OTRF Security-Datasets (MIT); compound/apt29/day1 (MITRE ATT&CK Evals APT29 Day 1)",
        "generalization_level": "new_chain (a full multi-step intrusion, not an isolated technique)",
        "ground_truth_note": ("union of the three per-technique derived rules (LSASS T1003.001, "
                              "NTDS T1003.003, injection T1055); only these three techniques are "
                              "labeled, so chain coverage is an UNDERCOUNT of true malice."),
        "detector_visible_fields": KEEP_FIELDS,
        "totals": {"events": n, "labeled_attack_events": n_attack},
        "attack_events_by_technique": by_technique,
    }
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    print(f"[apt29_loader] {SCHEMA_VERSION}: {n} events, {n_attack} labeled attack events")
    for tid, c in sorted(by_technique.items()):
        print(f"  {tid}: {c}")
    print(f"  manifest -> {args.manifest.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
