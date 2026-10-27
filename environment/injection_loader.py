#!/usr/bin/env python3
"""OTRF loader for the Process Injection slice (T1055) -- the new-technique rung.

Ingests three OTRF atomic datasets, each one tool that injects code into another
process -- a DIFFERENT technique from credential dumping (T1003), one rung
further out on the generalization ladder:

    01 dll_injection   (Empire LoadLibrary + CreateRemoteThread into notepad)
    02 pe_injection    (PurpleSharp PE injection + CreateRemoteThread)
    03 lolbin_crt      (Covenant wuauclt LOLBIN CreateRemoteThread)

The twist of this rung: process injection SHARES a telemetry surface with LSASS
dumping -- both show Sysmon EID10 ProcessAccess (a handle opened into another
process). They differ in intent: a dump opens lsass.exe for *memory read*
(PROCESS_VM_READ), while injection opens an arbitrary target for *thread
creation / memory write* (CREATE_THREAD / VM_WRITE) and then fires EID8
CreateRemoteThread. So the LSASS invariant does not merely face a new surface
(as with NTDS) -- it faces the SAME event type with a different meaning, and we
can see whether it discriminates or misfires.

Leakage-free contract, same as the other loaders. Ground truth (DERIVED):
* Sysmon EID8 (CreateRemoteThread) from a non-system source.

CreateRemoteThread is the decisive injection primitive -- a process spawning a
thread inside another process. We label that act only, deliberately NOT the
surrounding attack chain (process launches, C2 handles), several of which also
request PROCESS_ALL_ACCESS (0x1fffff) and would make the label noisy and
over-broad. This mirrors the LSASS slice, which labels the single decisive
memory-read access rather than every handle in the exercise. One clean positive
per procedure; recall is correspondingly coarse (noted in the manifest).

Stdlib only.
"""
from __future__ import annotations

import argparse
import json
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RAW = REPO_ROOT / "data" / "raw" / "otrf" / "injection"
DEFAULT_OUT = REPO_ROOT / "data" / "processed" / "injection"
DEFAULT_MANIFEST = REPO_ROOT / "results" / "injection-slice-manifest.json"

SCHEMA_VERSION = "otrf-injection-v1"
TECHNIQUE = "T1055"
TRAINED_ON = "T1003"  # credential dumping; this technique is held out whole

PROCEDURES = {
    "campaign_01": "dll_injection_loadlibrary_crt",
    "campaign_02": "pe_injection_purplesharp",
    "campaign_03": "lolbin_wuauclt_crt",
}
TEST_CAMPAIGNS = ["campaign_01", "campaign_02", "campaign_03"]

KEEP_FIELDS = [
    "@timestamp", "Channel", "EventID", "Hostname",
    "Image", "SourceImage", "TargetImage", "ParentImage", "ProcessName",
    "GrantedAccess", "CallTrace", "CommandLine",
    "StartFunction", "StartAddress", "StartModule", "NewThreadId",
    "TargetFilename", "ObjectName",
    "User", "SourceUser", "TargetUser",
    "ProcessId", "SourceProcessId", "TargetProcessId", "Hashes",
]

# System processes that legitimately open handles / create remote threads.
SYSTEM_WHITELIST = {
    "wininit.exe", "services.exe", "svchost.exe", "csrss.exe", "lsm.exe",
    "lsass.exe", "winlogon.exe", "msmpeng.exe", "wmiprvse.exe",
    "mssense.exe", "sensecncproxy.exe", "system", "smss.exe",
    "taskhostw.exe", "sihost.exe", "explorer.exe", "searchindexer.exe",
}

CREATE_REMOTE_THREAD = 8


def _basename(image) -> str:
    if not image:
        return ""
    return str(image).replace("/", "\\").split("\\")[-1].lower()


def is_injection(ev: dict) -> bool:
    """Evaluator-only ground-truth rule for process injection (T1055).

    A Sysmon CreateRemoteThread (EID8) raised by a non-system source process:
    the decisive injection primitive. Deliberately narrow -- see module docstring.
    """
    if int(ev.get("EventID") or 0) != CREATE_REMOTE_THREAD:
        return False
    src = _basename(ev.get("SourceImage"))
    return bool(src) and src not in SYSTEM_WHITELIST


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
            attack = is_injection(raw)
            if attack:
                n_attack += 1
                s = _basename(raw.get("SourceImage"))
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
    ap = argparse.ArgumentParser(description="Ingest OTRF injection campaigns (new-technique rung).")
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
        "source": "OTRF Security-Datasets (MIT); datasets/atomic/.../defense_evasion injection",
        "technique_under_test": TECHNIQUE,
        "trained_on": TRAINED_ON,
        "generalization_level": "new_technique (a different ATT&CK technique from the trained one)",
        "ground_truth_rule": ("Sysmon CreateRemoteThread(8) from a non-system source: the decisive "
                              "injection primitive. Narrow by design (labels the injection act, not the "
                              "surrounding attack chain); one positive per procedure, coarse recall."),
        "surface_note": ("injection also opens EID10 ProcessAccess handles into its target (often "
                         "PROCESS_ALL_ACCESS 0x1fffff), the same surface LSASS dumping uses; the LSASS "
                         "invariant keys on VM_READ to lsass.exe specifically, so it does not fire here."),
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

    print(f"[injection_loader] {SCHEMA_VERSION}: {len(campaigns)} campaigns (technique {TECHNIQUE})")
    for c in per_campaign:
        print(f"  {c['campaign']} {c['procedure']:28} "
              f"events={c['events']:6d} attack={c['attack_events']:3d} "
              f"sources={c['attack_source_images']}")
    print(f"  totals: events={manifest['totals']['events']} "
          f"attack={manifest['totals']['attack_events']}")
    print(f"  manifest -> {args.manifest.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
