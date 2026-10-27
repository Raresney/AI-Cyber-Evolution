#!/usr/bin/env python3
"""OTRF loader for the NTDS slice (T1003.003) -- the new-subtechnique rung.

Ingests three Open Threat Research Forge atomic datasets, each one tool that
steals the Active Directory database (``ntds.dit``) -- a *different sub-technique*
of OS Credential Dumping than the LSASS slice (T1003.001):

    01 ntdsutil              (ntdsutil "ac i ntds" IFM snapshot copy)
    02 volume_shadow_copy    (vssadmin shadow + copy ntds.dit off the snapshot)
    03 ninjacopy             (Empire Invoke-NinjaCopy raw-volume read -> copy)

The point of this rung: the detectors that won the LSASS new-instance test are
tied to the LSASS *surface* (Sysmon EID10 ProcessAccess to lsass.exe with a
memory-read mask). NTDS leaves a completely different footprint -- a file copy
of ``ntds.dit`` -- so those detectors cannot fire here at all. This slice lets
us measure whether detection transfers ACROSS sub-techniques of the same
technique, and whether a semantic (LLM) approach that reasons about "credential
dumping" generalizes where a surface-specific rule is blind by construction.

Same leakage-free contract as ``otrf_loader.py``:
* ``events.jsonl``  -- detector-visible telemetry only (no labels).
* ``labels.jsonl``  -- evaluator-only ground truth.

Ground truth (DERIVED, not hand-annotated): a file/object event whose path
basename matches ``ntds*.dit`` performed by a process that is not ``lsass.exe``
(the legitimate directory-service owner of the live database on a domain
controller). This captures the malicious copy/read of the AD database while
excluding the DC's own routine access. Mild label noise possible; v1 limitation.

Stdlib only.
"""
from __future__ import annotations

import argparse
import json
import re
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RAW = REPO_ROOT / "data" / "raw" / "otrf" / "ntds"
DEFAULT_OUT = REPO_ROOT / "data" / "processed" / "ntds"
DEFAULT_MANIFEST = REPO_ROOT / "results" / "ntds-slice-manifest.json"

SCHEMA_VERSION = "otrf-ntds-v1"
TECHNIQUE = "T1003.003"
TRAINED_ON = "T1003.001"  # the LSASS slice; this sub-technique is held out whole

PROCEDURES = {
    "campaign_01": "ntdsutil",
    "campaign_02": "volume_shadow_copy",
    "campaign_03": "ninjacopy",
}

# Every NTDS campaign is a held-out sub-technique (nothing here is trained on).
TEST_CAMPAIGNS = ["campaign_01", "campaign_02", "campaign_03"]

# Detector-visible fields. Superset of the LSASS fields plus the file/object and
# Security-channel fields that NTDS theft shows up in.
KEEP_FIELDS = [
    "@timestamp", "Channel", "EventID", "Hostname",
    "Image", "SourceImage", "TargetImage", "ParentImage", "ProcessName",
    "GrantedAccess", "CallTrace", "CommandLine",
    "TargetFilename", "ObjectName", "ShareName", "RelativeTargetName",
    "AccessMask", "AccessList", "Accesses",
    "User", "SourceUser", "TargetUser", "SubjectUserName",
    "ProcessId", "SourceProcessId", "TargetProcessId", "Hashes",
]

# The legitimate owner of the live ntds.dit on a domain controller.
LEGIT_NTDS_OWNER = {"lsass.exe"}

NTDS_DIT = re.compile(r"^ntds.*\.dit$")
# File-create of a copy (Sysmon 11) or object-access to the database (Security 4663).
DUMP_EVENT_IDS = {11, 4663}


def _basename(image) -> str:
    if not image:
        return ""
    return str(image).replace("/", "\\").split("\\")[-1].lower()


def _actor(ev: dict) -> str:
    # Sysmon uses Image; the Security channel (4656/4663) uses ProcessName.
    return _basename(ev.get("Image") or ev.get("ProcessName"))


def is_ntds_dump(ev: dict) -> bool:
    """Evaluator-only ground-truth rule for an NTDS dump (T1003.003).

    A Sysmon FileCreate (11) or Security object-access (4663) whose file/object
    path is ``ntds*.dit``, performed by a process other than ``lsass.exe``. This
    flags the malicious copy/read of the AD database and excludes the directory
    service's own access to the live file.
    """
    if int(ev.get("EventID") or 0) not in DUMP_EVENT_IDS:
        return False
    path = ev.get("TargetFilename") or ev.get("ObjectName")
    if not path or not NTDS_DIT.match(_basename(path)):
        return False
    actor = _actor(ev)
    if actor in LEGIT_NTDS_OWNER or not actor:
        return False
    return True


def _find_json(campaign_dir: Path) -> Path:
    jsons = [p for p in campaign_dir.glob("*.json")]
    if jsons:
        return jsons[0]
    zips = [p for p in campaign_dir.glob("*.zip")]
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
            attack = is_ntds_dump(raw)
            if attack:
                n_attack += 1
                s = _actor(raw)
                attack_sources[s] = attack_sources.get(s, 0) + 1

            visible = {"event_index": idx}
            for k in KEEP_FIELDS:
                if k in raw:
                    visible[k] = raw[k]
            fev.write(json.dumps(visible) + "\n")

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
        "split": "test",
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Ingest OTRF NTDS campaigns (new-subtechnique rung).")
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
        "source": "OTRF Security-Datasets (MIT); datasets/atomic/.../credential_access NTDS",
        "technique_under_test": TECHNIQUE,
        "trained_on": TRAINED_ON,
        "generalization_level": "new_subtechnique (different sub-technique of the same technique T1003)",
        "ground_truth_rule": ("Sysmon FileCreate(11) or Security object-access(4663) with a "
                              "file/object path basename matching ntds*.dit, actor process not "
                              "lsass.exe. Derived label (not hand-annotated); mild noise possible."),
        "split": {"train": [], "test": TEST_CAMPAIGNS},
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

    print(f"[ntds_loader] {SCHEMA_VERSION}: {len(campaigns)} campaigns (sub-technique {TECHNIQUE})")
    for c in per_campaign:
        print(f"  {c['campaign']} {c['procedure']:20} "
              f"events={c['events']:6d} attack={c['attack_events']:3d} "
              f"sources={c['attack_source_images']}")
    print(f"  totals: events={manifest['totals']['events']} "
          f"attack={manifest['totals']['attack_events']}")
    print(f"  manifest -> {args.manifest.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
