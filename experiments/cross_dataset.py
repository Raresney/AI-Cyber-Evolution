#!/usr/bin/env python3
"""External validity: the LSASS detectors on a DIFFERENT dataset family.

Every rung so far is OTRF (Mordor/Security-Datasets). The obvious threat is that
the shape is an OTRF artefact. This runs the unchanged detectors on an
independent capture: Splunk `attack_data` (atomic_red_team, attack_range
environment, 2022, different authors, host, and collection pipeline), a single
XmlWinEventLog Sysmon stream for T1003.001 that happens to contain *several*
credential-dumping tools at once -- including a renamed ``notprocdump.exe`` and a
GUID-named direct-syscall payload meant to defeat name signatures -- alongside
real benign LSASS access (``svchost`` with mask ``0x1400``).

Ground truth here is tool identity (the documented dumping tools), deliberately
independent of the invariant's access-mask rule, so the invariant's recall is
not by construction. The question is the paper's rung-1 question on
foreign data: does the behavioral invariant still fire on every dumper while the
OTRF-trained signature misses the unseen / renamed ones, and does the invariant
stay quiet on this environment's benign access?

Input is the LFS-fetched text log under data/raw/ (untrusted; parsed read-only,
never executed). Stdlib only.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LOG = REPO_ROOT / "data" / "raw" / "xdataset_t1003_splunk" / "windows-sysmon.log"
SLICE_DIR = REPO_ROOT / "data" / "processed" / "xdataset_lsass"
OUT_PATH = REPO_ROOT / "results" / "cross-dataset-lsass.json"
MANIFEST = REPO_ROOT / "results" / "lsass-slice-manifest.json"

SYSTEM_WHITELIST = {
    "wininit.exe", "services.exe", "svchost.exe", "csrss.exe", "lsm.exe",
    "lsass.exe", "winlogon.exe", "msmpeng.exe", "wmiprvse.exe",
    "mssense.exe", "sensecncproxy.exe",
}
PROCESS_VM_READ = 0x0010

# Independent ground truth: documented, unambiguous credential-dumping tool images
# in this capture (atomic T1003.001 procdump / direct-syscall / renamed-procdump /
# outflank-dumpert). LOLBin/manual methods (rundll32=comsvcs, powershell=pypykatz,
# taskmgr manual dump) are deliberately EXCLUDED from the positive label -- they
# are reported separately, so the GT never overlaps the behavioral rule.
DUMPER_TOOLS = {
    "procdump.exe", "procdump64.exe",
    "notprocdump.exe", "notprocdump64.exe",          # renamed to defeat name signatures
    "644c305e-30f4-470b-b616-d924c3206d1d.exe",       # direct-syscall / API-unhooking payload
    "outflank-dumpert.exe", "sharpdump.exe", "nanodump.x64.exe", "mimikatz.exe",
}
AMBIGUOUS = {"rundll32.exe", "powershell.exe", "taskmgr.exe"}  # real dumps, but LOLBin/manual


def _base(x) -> str:
    return str(x or "").replace("/", "\\").split("\\")[-1].lower()


def _hex(x):
    try:
        return int(str(x), 16)
    except (TypeError, ValueError):
        return None


def parse_events(log_path: Path):
    txt = log_path.read_text(encoding="utf-8", errors="replace")
    out = []
    for i, blk in enumerate(re.findall(r"<Event\b.*?</Event>", txt, re.S)):
        m = re.search(r"<EventID[^>]*>(\d+)</EventID>", blk)
        eid = int(m.group(1)) if m else 0
        data = dict(re.findall(r"<Data Name='([^']+)'>(.*?)</Data>", blk, re.S))
        out.append({"event_index": i, "EventID": eid,
                    "SourceImage": data.get("SourceImage"),
                    "TargetImage": data.get("TargetImage"),
                    "GrantedAccess": data.get("GrantedAccess")})
    return out


def targets_lsass(ev) -> bool:
    return ev["EventID"] == 10 and _base(ev["TargetImage"]) == "lsass.exe"


def inv_pred(ev) -> bool:
    if not targets_lsass(ev):
        return False
    src = _base(ev["SourceImage"])
    a = _hex(ev["GrantedAccess"])
    return src != "" and src not in SYSTEM_WHITELIST and a is not None and bool(a & PROCESS_VM_READ)


def sig_pred(ev, images: set[str]) -> bool:
    return targets_lsass(ev) and _base(ev["SourceImage"]) in images


def confusion(pairs):
    tp = fp = tn = fn = 0
    for t, p in pairs:
        tp += t and p; fn += t and not p; fp += (not t) and p; tn += (not t) and not p
    return {"tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
            "precision": round(tp / (tp + fp), 3) if (tp + fp) else None,
            "recall": round(tp / (tp + fn), 3) if (tp + fn) else None}


def main() -> None:
    ap = argparse.ArgumentParser(description="Cross-dataset external-validity test for the LSASS detectors.")
    ap.add_argument("--log", type=Path, default=DEFAULT_LOG)
    ap.add_argument("--out", type=Path, default=OUT_PATH)
    args = ap.parse_args()

    # OTRF-trained signature images (what the signature detector learned upstream).
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    otrf_images = set()
    for c in manifest["campaigns"]:
        otrf_images |= {k.lower() for k in (c.get("attack_source_images") or {})}

    events = parse_events(args.log)
    lsass_events = [e for e in events if targets_lsass(e)]

    # Independent, tool-identity ground truth.
    def truth(ev):
        return _base(ev["SourceImage"]) in DUMPER_TOOLS

    inv_pairs = [(truth(e), inv_pred(e)) for e in lsass_events]
    sig_pairs = [(truth(e), sig_pred(e, otrf_images)) for e in lsass_events]
    inv_m, sig_m = confusion(inv_pairs), confusion(sig_pairs)

    # Honest extra: invariant fires that are NOT in the tool GT -> which images?
    extra = {}
    for e in lsass_events:
        if inv_pred(e) and not truth(e):
            extra[_base(e["SourceImage"])] = extra.get(_base(e["SourceImage"]), 0) + 1
    # Which dumpers did the OTRF signature miss?
    missed_by_sig = sorted({_base(e["SourceImage"]) for e in lsass_events
                            if truth(e) and not sig_pred(e, otrf_images)})
    caught_by_sig = sorted({_base(e["SourceImage"]) for e in lsass_events
                            if truth(e) and sig_pred(e, otrf_images)})

    result = {
        "experiment": "cross-dataset-external-validity",
        "dataset": "splunk/attack_data atomic_red_team T1003.001 (attack_range, 2022)",
        "note": "independent dataset family; ground truth = documented dumping-tool identity, "
                "independent of the invariant's access-mask rule.",
        "total_events": len(events), "lsass_access_events": len(lsass_events),
        "gt_attack_events": sum(truth(e) for e in lsass_events),
        "otrf_signature_images": sorted(otrf_images),
        "behavioral_invariant": inv_m,
        "otrf_signature": sig_m,
        "signature_caught_tools": caught_by_sig,
        "signature_missed_tools": missed_by_sig,
        "invariant_extra_fires_beyond_tool_gt": extra,
    }

    SLICE_DIR.mkdir(parents=True, exist_ok=True)
    (SLICE_DIR / "events.jsonl").write_text(
        "".join(json.dumps(e) + "\n" for e in lsass_events), encoding="utf-8")
    (SLICE_DIR / "labels.jsonl").write_text(
        "".join(json.dumps({"event_index": e["event_index"], "attack_present": truth(e)}) + "\n"
                for e in lsass_events), encoding="utf-8")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

    def row(label, m):
        r = "  n/a" if m["recall"] is None else f"{m['recall']:.2f}"
        p = "  n/a" if m["precision"] is None else f"{m['precision']:.2f}"
        return f"  {label:28} recall={r} precision={p}  TP={m['tp']:3d} FP={m['fp']:3d} FN={m['fn']:3d}"

    print(f"Cross-dataset: {result['dataset']}")
    print(f"  {len(events)} Sysmon events, {len(lsass_events)} EID10->lsass, "
          f"{result['gt_attack_events']} tool-GT dump events")
    print(row("behavioral invariant", inv_m))
    print(row("OTRF-trained signature", sig_m))
    print(f"  signature caught : {caught_by_sig}")
    print(f"  signature MISSED : {missed_by_sig}")
    print(f"  invariant extra fires (real dumps beyond the conservative tool GT): {extra}")
    print(f"\nwrote {args.out.relative_to(REPO_ROOT)} and the parsed slice under {SLICE_DIR.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
