#!/usr/bin/env python3
"""OTRF Security-Datasets loader for the LSASS new-instance slice.

Ingests the seven ``LSASS_campaign_0X`` datasets (Open Threat Research Forge
Security-Datasets, MIT license) and turns each raw host-telemetry recording
into the project's leakage-free contract:

* ``events.jsonl``  -- detector-visible telemetry ONLY (normalized Windows /
  Sysmon events, no labels).
* ``labels.jsonl``  -- evaluator-only ground truth: which events are the LSASS
  credential-dump (T1003.001), plus the procedure (tool) and campaign.

Each campaign is one procedure of the SAME technique (T1003.001, OS Credential
Dumping: LSASS Memory), run with a different tool:

    01 mimikatz logonpasswords   05 sharpdump
    02 procdump                  06 outflank-dumpert
    03 comsvcs                   07 nanodump
    04 out-minidump

That lets us test *new-instance / new-procedure* generalization: train a
detector on some procedures, hold the others out, and ask whether detection
transfers to tools it never saw.

Ground truth is DERIVED, not hand-annotated. These are controlled exercises in
which a known LSASS dump occurred, so we label the malicious LSASS memory
access with a documented rule (see ``is_lsass_dump``) and keep it strictly out
of the detector-visible stream. The rule is deliberately NOT a complete
detector -- a detector must still infer intent from raw telemetry; the
evaluator uses the label only after the decision. Label noise is possible
(some benign high-access reads); this is a v1 limitation, noted in the manifest.

Stdlib only.
"""
from __future__ import annotations

import argparse
import json
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RAW = REPO_ROOT / "data" / "raw" / "otrf" / "lsass"
DEFAULT_OUT = REPO_ROOT / "data" / "processed" / "lsass"
DEFAULT_MANIFEST = REPO_ROOT / "results" / "lsass-slice-manifest.json"

SCHEMA_VERSION = "otrf-lsass-v1"
TECHNIQUE = "T1003.001"

# campaign id -> procedure (tool) label, from the dataset filenames.
PROCEDURES = {
    "campaign_01": "mimikatz_logonpasswords",
    "campaign_02": "procdump",
    "campaign_03": "comsvcs",
    "campaign_04": "out-minidump",
    "campaign_05": "sharpdump",
    "campaign_06": "outflank-dumpert",
    "campaign_07": "nanodump",
}

# new-instance split: train on three procedures, hold out four unseen tools.
TRAIN_CAMPAIGNS = ["campaign_01", "campaign_02", "campaign_03"]
HOLDOUT_CAMPAIGNS = ["campaign_04", "campaign_05", "campaign_06", "campaign_07"]

# Detector-visible fields kept from the raw event (no labels among them).
KEEP_FIELDS = [
    "@timestamp", "Channel", "EventID", "Hostname",
    "Image", "SourceImage", "TargetImage", "ParentImage",
    "GrantedAccess", "CallTrace", "CommandLine",
    "User", "SourceUser", "TargetUser",
    "ProcessId", "SourceProcessId", "TargetProcessId", "Hashes",
]

# System processes that legitimately open LSASS (excluded from attack ground
# truth). Lowercased image basenames.
LEGIT_LSASS_ACCESSORS = {
    "wininit.exe", "services.exe", "svchost.exe", "csrss.exe", "lsm.exe",
    "lsass.exe", "winlogon.exe", "msmpeng.exe", "wmiprvse.exe",
    "mssense.exe", "sensecncproxy.exe",
}

PROCESS_VM_READ = 0x0010  # the access right a memory dump needs


def _basename(image) -> str:
    if not image:
        return ""
    return str(image).replace("/", "\\").split("\\")[-1].lower()


def is_lsass_dump(ev: dict) -> bool:
    """Evaluator-only ground-truth rule for a LSASS credential dump (T1003.001).

    Sysmon ProcessAccess (EventID 10) targeting lsass.exe, requesting a memory
    read (PROCESS_VM_READ), from a source process that is not a known system
    accessor. This flags the dump access while excluding routine system reads.
    """
    if int(ev.get("EventID") or 0) != 10:
        return False
    if _basename(ev.get("TargetImage")) != "lsass.exe":
        return False
    src = _basename(ev.get("SourceImage"))
    if src in LEGIT_LSASS_ACCESSORS or not src:
        return False
    ga = ev.get("GrantedAccess")
    try:
        access = int(str(ga), 16)
    except (TypeError, ValueError):
        return False
    return bool(access & PROCESS_VM_READ)


def _find_json(campaign_dir: Path) -> Path:
    """Return the host-event JSON, extracting it from the zip if needed."""
    jsons = [p for p in campaign_dir.glob("*.json")]
    if jsons:
        return jsons[0]
    zips = [p for p in campaign_dir.glob("*_lsass_memory_dump.zip")]
    if not zips:
        raise FileNotFoundError(f"no host-event json/zip in {campaign_dir}")
    with zipfile.ZipFile(zips[0]) as zf:
        names = [n for n in zf.namelist() if n.lower().endswith(".json")]
        if not names:
            raise FileNotFoundError(f"no .json inside {zips[0].name}")
        zf.extract(names[0], campaign_dir)
    return next(campaign_dir.glob("*.json"))


def process_campaign(campaign: Path, out_dir: Path) -> dict:
    procedure = PROCEDURES[campaign.name]
    src_json = _find_json(campaign)
    out_c = out_dir / campaign.name
    out_c.mkdir(parents=True, exist_ok=True)
    ev_path = out_c / "events.jsonl"
    lbl_path = out_c / "labels.jsonl"

    n = n_attack = 0
    attack_sources: dict[str, int] = {}
    with src_json.open(encoding="utf-8", errors="replace") as fin, \
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
            attack = is_lsass_dump(raw)
            if attack:
                n_attack += 1
                s = _basename(raw.get("SourceImage"))
                attack_sources[s] = attack_sources.get(s, 0) + 1

            # Detector-visible: only observable fields, plus an opaque index.
            visible = {"event_index": idx}
            for k in KEEP_FIELDS:
                if k in raw:
                    visible[k] = raw[k]
            fev.write(json.dumps(visible) + "\n")

            # Evaluator-only ground truth.
            flbl.write(json.dumps({
                "event_index": idx,
                "attack_present": attack,
                "technique_id": TECHNIQUE if attack else None,
                "procedure": procedure,
                "campaign": campaign.name,
            }) + "\n")

    return {
        "campaign": campaign.name,
        "procedure": procedure,
        "events": n,
        "attack_events": n_attack,
        "attack_source_images": attack_sources,
        "split": "train" if campaign.name in TRAIN_CAMPAIGNS else "holdout",
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Ingest OTRF LSASS campaigns into the leakage-free slice.")
    ap.add_argument("--raw", type=Path, default=DEFAULT_RAW)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    args = ap.parse_args()

    campaigns = sorted(d for d in args.raw.iterdir()
                       if d.is_dir() and d.name in PROCEDURES)
    if not campaigns:
        raise SystemExit(f"no campaign dirs under {args.raw}")

    per_campaign = [process_campaign(c, args.out) for c in campaigns]

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "source": "OTRF Security-Datasets (MIT); datasets/compound/LSASS_campaign_01..07",
        "technique_under_test": TECHNIQUE,
        "generalization_level": "new_instance (unseen procedure of a known technique)",
        "ground_truth_rule": ("Sysmon EID10 ProcessAccess, TargetImage=lsass.exe, "
                              "GrantedAccess & PROCESS_VM_READ(0x10), SourceImage not a "
                              "known system accessor. Derived label (not hand-annotated); "
                              "mild label noise possible."),
        "split": {"train": TRAIN_CAMPAIGNS, "holdout": HOLDOUT_CAMPAIGNS},
        "detector_visible_fields": KEEP_FIELDS,
        "label_fields_evaluator_only": ["attack_present", "technique_id", "procedure", "campaign"],
        "totals": {
            "events": sum(c["events"] for c in per_campaign),
            "attack_events": sum(c["attack_events"] for c in per_campaign),
        },
        "campaigns": per_campaign,
    }
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    print(f"[otrf_loader] {SCHEMA_VERSION}: {len(campaigns)} campaigns")
    for c in per_campaign:
        print(f"  {c['campaign']} {c['procedure']:22} "
              f"events={c['events']:6d} attack={c['attack_events']:4d} "
              f"[{c['split']}] sources={c['attack_source_images']}")
    print(f"  totals: events={manifest['totals']['events']} "
          f"attack={manifest['totals']['attack_events']}")
    print(f"  manifest -> {args.manifest.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
