#!/usr/bin/env python3
"""External validity: the ladder detectors on a DIFFERENT dataset family.

Every rung in the main study is OTRF (Mordor/Security-Datasets). The sharpest
threat is that the shape is an OTRF artefact. This runs the unchanged detectors
on independent captures from Splunk `attack_data` (atomic Red Team and Cobalt
Strike; a different host, year, and collection pipeline), one Sysmon stream per
technique:

* **LSASS (T1003.001)** -- atomic_red_team: several dumpers in one stream,
  including a renamed ``notprocdump.exe`` and a GUID-named direct-syscall payload
  built to defeat name signatures.
* **injection (T1055)** -- cobalt_strike: CreateRemoteThread (EID8) from
  ``winword.exe`` into ``dllhost.exe``, the classic weaponized-document inject.
* **NTDS (T1003.003)** -- atomic_red_team: the capture dumps via
  ``reg save`` / ``ntdsutil`` command lines, so the FileCreate/object-access
  ``ntds.dit`` surface the OTRF invariant keys on is *absent* here -- a concrete
  case of surface-lock being per-procedure, not merely per-technique.

For each capture we run all three behavioral invariants (a transfer matrix, like
the full-scale FP budget) plus the OTRF-trained name signature on LSASS. Ground
truth is independent of the invariant's access-mask rule: tool identity for
LSASS, the documented CreateRemoteThread for injection.

Inputs are public LFS artifacts under data/raw/ (untrusted; parsed read-only,
never executed). Stdlib only.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RAW = REPO_ROOT / "data" / "raw"
SLICE_DIR = REPO_ROOT / "data" / "processed" / "xdataset"
OUT_PATH = REPO_ROOT / "results" / "cross-dataset-ladder.json"
MANIFEST = REPO_ROOT / "results" / "lsass-slice-manifest.json"

SYSTEM_WHITELIST = {
    "wininit.exe", "services.exe", "svchost.exe", "csrss.exe", "lsm.exe",
    "lsass.exe", "winlogon.exe", "msmpeng.exe", "wmiprvse.exe",
    "mssense.exe", "sensecncproxy.exe",
}
PROCESS_VM_READ = 0x0010

# Documented, unambiguous LSASS-dumping tool images in the atomic capture
# (GT independent of the mask rule). LOLBin/manual methods are excluded.
DUMPER_TOOLS = {
    "procdump.exe", "procdump64.exe", "notprocdump.exe", "notprocdump64.exe",
    "644c305e-30f4-470b-b616-d924c3206d1d.exe", "outflank-dumpert.exe",
    "sharpdump.exe", "nanodump.x64.exe", "mimikatz.exe",
}

CAPTURES = [
    ("LSASS (T1003.001)", "lsass",     RAW / "xdataset_t1003_splunk" / "windows-sysmon.log"),
    ("injection (T1055)", "injection", RAW / "xdataset_t1055_splunk" / "dllhost.log"),
    ("NTDS (T1003.003)",  "ntds",      RAW / "xdataset_t1003003_splunk" / "windows-sysmon.log"),
]


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
        d = dict(re.findall(r"<Data Name='([^']+)'>(.*?)</Data>", blk, re.S))
        d["_eid"] = int(m.group(1)) if m else 0
        d["_i"] = i
        out.append(d)
    return out


# --- the three surface invariants ------------------------------------------

def inv_lsass(e) -> bool:
    if e["_eid"] != 10 or _base(e.get("TargetImage")) != "lsass.exe":
        return False
    src, a = _base(e.get("SourceImage")), _hex(e.get("GrantedAccess"))
    return src != "" and src not in SYSTEM_WHITELIST and a is not None and bool(a & PROCESS_VM_READ)


def inv_injection(e) -> bool:
    return e["_eid"] == 8 and _base(e.get("SourceImage")) not in SYSTEM_WHITELIST and _base(e.get("SourceImage")) != ""


def inv_ntds(e) -> bool:
    if e["_eid"] == 4663:
        path, actor = _base(e.get("ObjectName")), _base(e.get("ProcessName"))
    elif e["_eid"] == 11:
        path, actor = _base(e.get("TargetFilename")), _base(e.get("Image"))
    else:
        return False
    return path.startswith("ntds") and path.endswith(".dit") and actor != "lsass.exe"


INVARIANTS = {"lsass": inv_lsass, "injection": inv_injection, "ntds": inv_ntds}


def confusion(pairs):
    tp = fp = fn = 0
    for t, p in pairs:
        tp += t and p; fn += t and not p; fp += (not t) and p
    return {"tp": int(tp), "fp": int(fp), "fn": int(fn),
            "precision": round(tp / (tp + fp), 3) if (tp + fp) else None,
            "recall": round(tp / (tp + fn), 3) if (tp + fn) else None}


def gt_truth(surface, e) -> bool:
    if surface == "lsass":
        return e["_eid"] == 10 and _base(e.get("TargetImage")) == "lsass.exe" and _base(e.get("SourceImage")) in DUMPER_TOOLS
    if surface == "injection":
        return e["_eid"] == 8 and _base(e.get("SourceImage")) not in SYSTEM_WHITELIST and _base(e.get("SourceImage")) != ""
    if surface == "ntds":
        return inv_ntds(e)  # the file/object surface; absent in this capture
    return False


def main() -> None:
    ap = argparse.ArgumentParser(description="Cross-dataset external-validity ladder.")
    ap.add_argument("--out", type=Path, default=OUT_PATH)
    args = ap.parse_args()

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    otrf_images = set()
    for c in manifest["campaigns"]:
        otrf_images |= {k.lower() for k in (c.get("attack_source_images") or {})}

    out = {"experiment": "cross-dataset-external-validity-ladder",
           "source": "splunk/attack_data (atomic_red_team, cobalt_strike; attack_range)",
           "gt": "tool identity (lsass) / documented CreateRemoteThread (injection); "
                 "independent of the access-mask rule",
           "otrf_signature_images": sorted(otrf_images),
           "captures": {}}

    SLICE_DIR.mkdir(parents=True, exist_ok=True)
    for label, surface, log in CAPTURES:
        if not log.exists():
            out["captures"][label] = {"error": f"missing {log}"}
            continue
        ev = parse_events(log)
        n_gt = sum(gt_truth(surface, e) for e in ev)
        # matched-surface invariant recall vs independent GT
        matched = INVARIANTS[surface]
        matched_cm = confusion([(gt_truth(surface, e), matched(e)) for e in ev])
        # transfer matrix: every invariant's fire count on this capture
        fires = {name: sum(rule(e) for e in ev) for name, rule in INVARIANTS.items()}
        cap = {"surface": surface, "events": len(ev), "gt_attack_events": n_gt,
               "matched_invariant": matched_cm, "invariant_fires": fires}

        if surface == "lsass":
            sig = [(gt_truth("lsass", e), (e["_eid"] == 10 and _base(e.get("TargetImage")) == "lsass.exe"
                    and _base(e.get("SourceImage")) in otrf_images)) for e in ev]
            cap["otrf_signature"] = confusion(sig)
            cap["signature_missed_tools"] = sorted({_base(e.get("SourceImage")) for e in ev
                if gt_truth("lsass", e) and _base(e.get("SourceImage")) not in otrf_images})
            cap["signature_caught_tools"] = sorted({_base(e.get("SourceImage")) for e in ev
                if gt_truth("lsass", e) and _base(e.get("SourceImage")) in otrf_images})
        if surface == "ntds":
            # the file/object surface is absent; show what the procedure left instead
            cmdline_ntds = sum(1 for e in ev if e["_eid"] == 1 and "ntds" in (e.get("CommandLine") or "").lower())
            cap["note"] = ("file/object ntds.dit surface absent; capture dumps via reg/ntdsutil "
                           "command lines (EID1), a different observable the OTRF invariant does not key on")
            cap["eid1_cmdlines_mentioning_ntds"] = cmdline_ntds
        out["captures"][label] = cap

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")

    def f(m):
        r = " n/a" if m["recall"] is None else f"{m['recall']:.2f}"
        p = " n/a" if m["precision"] is None else f"{m['precision']:.2f}"
        return f"{r}/{p}"

    print("Cross-dataset external-validity ladder (Splunk attack_data)")
    print("\ncapture              | events | matched inv (rec/prec) | invariant fires {lsass,inj,ntds}")
    print("---------------------+--------+------------------------+---------------------------------")
    for label, cap in out["captures"].items():
        if "error" in cap:
            print(f"{label:20.20s} | MISSING"); continue
        fr = cap["invariant_fires"]
        print(f"{label:20.20s} | {cap['events']:>6d} | {f(cap['matched_invariant']):>18s}     | "
              f"lsass={fr['lsass']} inj={fr['injection']} ntds={fr['ntds']}")
    lc = out["captures"].get("LSASS (T1003.001)", {})
    if "otrf_signature" in lc:
        print(f"\nLSASS OTRF-signature: {f(lc['otrf_signature'])}  "
              f"caught={lc['signature_caught_tools']} missed={lc['signature_missed_tools']}")
    nc = out["captures"].get("NTDS (T1003.003)", {})
    if "note" in nc:
        print(f"NTDS: {nc['note']}  (EID1 cmdlines mentioning ntds: {nc.get('eid1_cmdlines_mentioning_ntds')})")
    print(f"\nwrote {args.out.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
