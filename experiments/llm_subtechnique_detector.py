#!/usr/bin/env python3
"""Cross-subtechnique LLM test: does a general reasoner transfer LSASS -> NTDS?

The deterministic detectors are tied to one surface (see
``experiments/ladder_subtechnique.py``): the LSASS behavioral invariant scores
0 on NTDS because NTDS leaves a file-copy footprint, not an EID10 memory read.
A hand-coded rule is specialized to its sub-technique by construction.

An LLM asked the *general* question -- "is this OS Credential Dumping,
T1003, in any form?" -- is not bound to a surface. This script measures whether
that generality buys cross-sub-technique transfer: the same llama3.2 judges NTDS
events (ntds.dit copy / shadow-copy read / NinjaCopy) it was never shown.

Two modes:
* ``zero-shot``   -- the model's pretrained knowledge of the technique family.
* ``few-shot``    -- labeled exemplars drawn from the LSASS slice (a DIFFERENT
  sub-technique). Tests in-context transfer: do LSASS memory-dump examples help
  or mislead the model on NTDS file-dumps?

Judged surface on NTDS: candidate file/object events -- Sysmon FileCreate(11)
and Security object-access(4663). All attack events judged; benign candidates of
the same event types are subsampled (seeded) for precision. Deterministic
(temp 0, seed 42). Stdlib only (urllib to Ollama).
"""
from __future__ import annotations

import argparse
import json
import random
import time
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
NTDS_PROC = REPO_ROOT / "data" / "processed" / "ntds"
LSASS_PROC = REPO_ROOT / "data" / "processed" / "lsass"
NTDS_MANIFEST = REPO_ROOT / "results" / "ntds-slice-manifest.json"
LSASS_MANIFEST = REPO_ROOT / "results" / "lsass-slice-manifest.json"
OUT_PATH = REPO_ROOT / "results" / "llm-subtechnique-detection.json"

SYSTEM_PROMPT = (
    "You are a SOC detection analyst. You are given one Windows host event "
    "(Sysmon or the Security log). Decide whether it is part of OS Credential "
    "Dumping (MITRE ATT&CK T1003) in ANY form -- stealing credential material "
    "from the operating system, for example from LSASS process memory, from the "
    "Active Directory database ntds.dit, from the SAM/SECURITY registry hives, "
    "or from a cached/shadow copy of any of these. Judge the intent of the "
    "telemetry, not the specific tool. Respond ONLY with JSON of the form "
    '{"malicious": true or false, "reason": "<one short sentence>"}.'
)

# NTDS candidate surface: file create of a copy, or object access to the db.
NTDS_SURFACE_EIDS = {11, 4663}
# LSASS candidate surface (for drawing exemplars): EID10 access to lsass.exe.
LSASS_SURFACE_EID = 10


def basename(image) -> str:
    if not image:
        return ""
    return str(image).replace("/", "\\").split("\\")[-1].lower()


def read_jsonl(path: Path):
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def on_ntds_surface(ev) -> bool:
    if int(ev.get("EventID") or 0) not in NTDS_SURFACE_EIDS:
        return False
    # must be a file/object event (has a path field); keeps the candidate set to
    # file activity the detector could plausibly act on.
    return bool(ev.get("TargetFilename") or ev.get("ObjectName"))


def on_lsass_surface(ev) -> bool:
    return int(ev.get("EventID") or 0) == LSASS_SURFACE_EID and basename(ev.get("TargetImage")) == "lsass.exe"


def event_to_prompt(ev) -> str:
    call = str(ev.get("CallTrace") or "")
    if len(call) > 200:
        call = call[:200] + "..."
    cmd = str(ev.get("CommandLine") or "")
    if len(cmd) > 200:
        cmd = cmd[:200] + "..."
    fields = [
        ("EventID", ev.get("EventID")),
        ("Channel", ev.get("Channel")),
        ("Image/Process", ev.get("Image") or ev.get("ProcessName")),
        ("TargetImage", ev.get("TargetImage")),
        ("GrantedAccess", ev.get("GrantedAccess")),
        ("TargetFilename", ev.get("TargetFilename")),
        ("ObjectName", ev.get("ObjectName")),
        ("CommandLine", cmd or None),
        ("CallTrace", call or None),
    ]
    lines = ["Windows host event:"]
    lines += [f"- {k}: {v}" for k, v in fields if v not in (None, "")]
    return "\n".join(lines)


def ollama_generate(prompt: str, model: str, url: str, system: str, retries: int = 2) -> str:
    body = json.dumps({
        "model": model, "prompt": prompt, "system": system,
        "stream": False, "format": "json",
        "options": {"temperature": 0, "seed": 42, "num_predict": 80},
    }).encode()
    req = urllib.request.Request(url, body, {"Content-Type": "application/json"})
    last = None
    for _ in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                return json.loads(r.read()).get("response", "")
        except Exception as e:  # noqa: BLE001
            last = e
            time.sleep(1.0)
    raise RuntimeError(f"ollama call failed: {last}")


def parse_verdict(resp: str) -> bool:
    try:
        return bool(json.loads(resp).get("malicious"))
    except (json.JSONDecodeError, AttributeError):
        return "true" in resp.lower() and "malicious" in resp.lower()


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
    prec = round(tp / (tp + fp), 4) if (tp + fp) else None
    rec = round(tp / (tp + fn), 4) if (tp + fn) else None
    fpr = round(fp / (fp + tn), 6) if (fp + tn) else None
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": prec, "recall": rec, "false_positive_rate": fpr}


def ntds_candidates(campaign, max_benign, rng):
    cdir = NTDS_PROC / campaign
    labels = {r["event_index"]: r["attack_present"] for r in read_jsonl(cdir / "labels.jsonl")}
    attacks, benign = [], []
    for ev in read_jsonl(cdir / "events.jsonl"):
        if not on_ntds_surface(ev):
            continue
        (attacks if labels.get(ev["event_index"]) else benign).append(ev)
    if len(benign) > max_benign:
        benign = rng.sample(benign, max_benign)
    return attacks, benign


def lsass_exemplars(train, n_pos, n_neg, rng):
    """Draw labeled exemplars from the LSASS slice (a different sub-technique)."""
    pos, neg = [], []
    for c in train:
        cdir = LSASS_PROC / c
        labels = {r["event_index"]: r["attack_present"] for r in read_jsonl(cdir / "labels.jsonl")}
        for ev in read_jsonl(cdir / "events.jsonl"):
            if not on_lsass_surface(ev):
                continue
            (pos if labels.get(ev["event_index"]) else neg).append(ev)
    rng.shuffle(pos)
    rng.shuffle(neg)
    shots = []
    for i in range(max(n_pos, n_neg)):
        if i < n_pos and i < len(pos):
            shots.append((pos[i], True))
        if i < n_neg and i < len(neg):
            shots.append((neg[i], False))
    return shots


def build_preamble(shots) -> str:
    blocks = ["Here are labeled examples of credential dumping (and benign access) "
              "from past investigations of a RELATED technique:\n"]
    for i, (ev, label) in enumerate(shots, 1):
        verdict = json.dumps({"malicious": label,
                              "reason": ("credential dumping (LSASS memory read)" if label
                                         else "benign system access")})
        blocks.append(f"Example {i}:\n{event_to_prompt(ev)}\nVerdict: {verdict}\n")
    blocks.append("Now judge this new event using the same reasoning:\n")
    return "\n".join(blocks)


def main() -> None:
    ap = argparse.ArgumentParser(description="Cross-subtechnique LLM test (LSASS -> NTDS).")
    ap.add_argument("--mode", choices=["zero-shot", "few-shot"], default="zero-shot")
    ap.add_argument("--out", type=Path, default=OUT_PATH)
    ap.add_argument("--model", default="llama3.2")
    ap.add_argument("--url", default="http://localhost:11434/api/generate")
    ap.add_argument("--max-benign", type=int, default=15)
    ap.add_argument("--pos-shots", type=int, default=3)
    ap.add_argument("--neg-shots", type=int, default=3)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--seed", type=int, default=1337)
    args = ap.parse_args()

    ntds_manifest = json.loads(NTDS_MANIFEST.read_text(encoding="utf-8"))
    campaigns = ntds_manifest["split"]["test"]
    rng = random.Random(args.seed)

    preamble = ""
    exemplar_note = None
    if args.mode == "few-shot":
        lsass_train = json.loads(LSASS_MANIFEST.read_text(encoding="utf-8"))["split"]["train"]
        shots = lsass_exemplars(lsass_train, args.pos_shots, args.neg_shots, rng)
        preamble = build_preamble(shots)
        exemplar_note = (f"{args.pos_shots}+{args.neg_shots} LSASS (T1003.001) exemplars "
                         f"from procedures {lsass_train}")

    per_campaign, all_pairs = {}, []
    verdict_log, n_calls = [], 0
    t0 = time.time()
    for c in campaigns:
        attacks, benign = ntds_candidates(c, args.max_benign, rng)
        pairs = []
        for truth, ev in ([(True, e) for e in attacks] + [(False, e) for e in benign]):
            if args.limit and n_calls >= args.limit:
                break
            prompt = (preamble + "\n" + event_to_prompt(ev)) if preamble else event_to_prompt(ev)
            resp = ollama_generate(prompt, args.model, args.url, SYSTEM_PROMPT)
            pred = parse_verdict(resp)
            n_calls += 1
            pairs.append((truth, pred))
            verdict_log.append({"campaign": c, "truth": truth, "pred": pred,
                                "eid": ev.get("EventID"),
                                "actor": basename(ev.get("Image") or ev.get("ProcessName")),
                                "path": ev.get("TargetFilename") or ev.get("ObjectName")})
            if n_calls % 20 == 0:
                print(f"  ...{n_calls} calls ({time.time()-t0:.0f}s)")
        per_campaign[c] = confusion(pairs)
        all_pairs += pairs
        if args.limit and n_calls >= args.limit:
            break

    results = {
        "model": args.model,
        "mode": args.mode,
        "rung": "new_subtechnique",
        "trained_on": "T1003.001 (LSASS)",
        "tested_on": "T1003.003 (NTDS)",
        "exemplars": exemplar_note,
        "surface": "NTDS file/object events: Sysmon FileCreate(11) + Security object-access(4663)",
        "max_benign_per_campaign": args.max_benign,
        "note": ("general T1003 prompt (not LSASS-specific). precision/FPR on a benign "
                 "subsample; all attack events judged. Deterministic (temp 0, seed 42)."),
        "n_calls": n_calls,
        "seconds": round(time.time() - t0, 1),
        "per_campaign": per_campaign,
        "overall": confusion(all_pairs),
        "verdicts": verdict_log,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")

    def row(label, m):
        rec = "  n/a" if m["recall"] is None else f"{m['recall']:.2f}"
        prec = "  n/a" if m["precision"] is None else f"{m['precision']:.2f}"
        return f"  {label:28} recall={rec} precision={prec} TP={m['tp']:3d} FP={m['fp']:4d} FN={m['fn']:3d}"

    print(f"\ncross-subtechnique LLM ({args.mode}): {args.model}, {n_calls} calls in {results['seconds']}s")
    print(f"trained/exemplified on LSASS (T1003.001), tested on NTDS (T1003.003)")
    print(row(f"llm({args.mode})", results["overall"]))
    pc = results["per_campaign"]
    grad = "   ".join(f"{c.split('_')[1]}:{(pc[c]['recall'] if pc[c]['recall'] is not None else 0):.2f}"
                      for c in campaigns if c in pc)
    print(f"  per-procedure recall -> {grad}")
    try:
        shown = args.out.resolve().relative_to(REPO_ROOT)
    except ValueError:
        shown = args.out
    print(f"\n  wrote {shown}")


if __name__ == "__main__":
    main()
