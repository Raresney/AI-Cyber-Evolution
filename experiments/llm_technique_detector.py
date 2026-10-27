#!/usr/bin/env python3
"""New-technique LLM test: does a general reasoner transfer T1003 -> T1055?

The deterministic rule for one technique detects nothing of another (see
``experiments/ladder_technique.py``): credential-dumping rules score 0 on
process injection. The open question is whether an LLM, asked the *general*
question -- "is this event part of ANY malicious attack technique?" -- carries
over. Unlike the sub-technique test, the prompt here is not tied to credential
dumping at all; it is a general-malice detector.

Two modes:
* ``zero-shot`` -- the model's pretrained sense of malicious host activity.
* ``few-shot``  -- labeled exemplars from the LSASS slice (credential dumping,
  a DIFFERENT technique). Tests whether cross-technique in-context examples help
  the model flag injection, or anchor it to the wrong technique.

Judged surface on the injection slice: Sysmon CreateRemoteThread(8) events (the
injection primitive, all attack events) plus a seeded subsample of EID10
ProcessAccess handles (overwhelmingly benign) for precision. Deterministic
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
INJ_PROC = REPO_ROOT / "data" / "processed" / "injection"
LSASS_PROC = REPO_ROOT / "data" / "processed" / "lsass"
INJ_MANIFEST = REPO_ROOT / "results" / "injection-slice-manifest.json"
LSASS_MANIFEST = REPO_ROOT / "results" / "lsass-slice-manifest.json"
OUT_PATH = REPO_ROOT / "results" / "llm-technique-detection.json"

SYSTEM_PROMPT = (
    "You are a SOC detection analyst. You are given one Windows host event "
    "(Sysmon or the Security log). Decide whether it is part of ANY malicious "
    "attack technique (MITRE ATT&CK) -- for example credential dumping, process "
    "injection, persistence, lateral movement, defense evasion -- as opposed to "
    "normal operating-system or application activity. Judge the intent of the "
    "telemetry. Respond ONLY with JSON of the form "
    '{"malicious": true or false, "reason": "<one short sentence>"}.'
)

# Injection candidate surface: CreateRemoteThread (attacks) + ProcessAccess (benign-ish).
INJ_SURFACE_EIDS = {8, 10}
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


def on_inj_surface(ev) -> bool:
    return int(ev.get("EventID") or 0) in INJ_SURFACE_EIDS


def on_lsass_surface(ev) -> bool:
    return int(ev.get("EventID") or 0) == LSASS_SURFACE_EID and basename(ev.get("TargetImage")) == "lsass.exe"


def event_to_prompt(ev) -> str:
    call = str(ev.get("CallTrace") or "")
    if len(call) > 200:
        call = call[:200] + "..."
    fields = [
        ("EventID", ev.get("EventID")),
        ("Channel", ev.get("Channel")),
        ("SourceImage", ev.get("SourceImage") or ev.get("Image")),
        ("TargetImage", ev.get("TargetImage")),
        ("GrantedAccess", ev.get("GrantedAccess")),
        ("StartFunction", ev.get("StartFunction")),
        ("StartAddress", ev.get("StartAddress")),
        ("CallTrace", call or None),
    ]
    lines = ["Windows host event:"]
    lines += [f"- {k}: {v}" for k, v in fields if v not in (None, "")]
    return "\n".join(lines)


def ollama_generate(prompt: str, model: str, url: str, retries: int = 2) -> str:
    body = json.dumps({
        "model": model, "prompt": prompt, "system": SYSTEM_PROMPT,
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


def inj_candidates(campaign, max_benign, rng):
    cdir = INJ_PROC / campaign
    labels = {r["event_index"]: r["attack_present"] for r in read_jsonl(cdir / "labels.jsonl")}
    attacks, benign = [], []
    for ev in read_jsonl(cdir / "events.jsonl"):
        if not on_inj_surface(ev):
            continue
        (attacks if labels.get(ev["event_index"]) else benign).append(ev)
    if len(benign) > max_benign:
        benign = rng.sample(benign, max_benign)
    return attacks, benign


def lsass_exemplars(train, n_pos, n_neg, rng):
    pos, neg = [], []
    for c in train:
        cdir = LSASS_PROC / c
        labels = {r["event_index"]: r["attack_present"] for r in read_jsonl(cdir / "labels.jsonl")}
        for ev in read_jsonl(cdir / "events.jsonl"):
            if not on_lsass_surface(ev):
                continue
            (pos if labels.get(ev["event_index"]) else neg).append(ev)
    rng.shuffle(pos); rng.shuffle(neg)
    shots = []
    for i in range(max(n_pos, n_neg)):
        if i < n_pos and i < len(pos):
            shots.append((pos[i], True))
        if i < n_neg and i < len(neg):
            shots.append((neg[i], False))
    return shots


def build_preamble(shots) -> str:
    blocks = ["Here are labeled examples of malicious and benign activity from "
              "past investigations (a DIFFERENT technique, credential dumping):\n"]
    for i, (ev, label) in enumerate(shots, 1):
        verdict = json.dumps({"malicious": label,
                              "reason": ("malicious: credential dumping (LSASS memory read)" if label
                                         else "benign system access")})
        blocks.append(f"Example {i}:\n{event_to_prompt(ev)}\nVerdict: {verdict}\n")
    blocks.append("Now judge this new event (it may be a different technique):\n")
    return "\n".join(blocks)


def main() -> None:
    ap = argparse.ArgumentParser(description="New-technique LLM test (T1003 -> T1055).")
    ap.add_argument("--mode", choices=["zero-shot", "few-shot"], default="zero-shot")
    ap.add_argument("--out", type=Path, default=OUT_PATH)
    ap.add_argument("--model", default="llama3.2")
    ap.add_argument("--url", default="http://localhost:11434/api/generate")
    ap.add_argument("--max-benign", type=int, default=20)
    ap.add_argument("--pos-shots", type=int, default=3)
    ap.add_argument("--neg-shots", type=int, default=3)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--seed", type=int, default=1337)
    args = ap.parse_args()

    inj_manifest = json.loads(INJ_MANIFEST.read_text(encoding="utf-8"))
    campaigns = inj_manifest["split"]["test"]
    rng = random.Random(args.seed)

    preamble, exemplar_note = "", None
    if args.mode == "few-shot":
        lsass_train = json.loads(LSASS_MANIFEST.read_text(encoding="utf-8"))["split"]["train"]
        shots = lsass_exemplars(lsass_train, args.pos_shots, args.neg_shots, rng)
        preamble = build_preamble(shots)
        exemplar_note = f"{args.pos_shots}+{args.neg_shots} LSASS (T1003.001) exemplars from {lsass_train}"

    per_campaign, all_pairs = {}, []
    verdict_log, n_calls = [], 0
    t0 = time.time()
    for c in campaigns:
        attacks, benign = inj_candidates(c, args.max_benign, rng)
        pairs = []
        for truth, ev in ([(True, e) for e in attacks] + [(False, e) for e in benign]):
            if args.limit and n_calls >= args.limit:
                break
            prompt = (preamble + "\n" + event_to_prompt(ev)) if preamble else event_to_prompt(ev)
            resp = ollama_generate(prompt, args.model, args.url)
            pred = parse_verdict(resp)
            n_calls += 1
            pairs.append((truth, pred))
            verdict_log.append({"campaign": c, "truth": truth, "pred": pred,
                                "eid": ev.get("EventID"),
                                "src": basename(ev.get("SourceImage") or ev.get("Image")),
                                "tgt": basename(ev.get("TargetImage")),
                                "ga": ev.get("GrantedAccess")})
            if n_calls % 20 == 0:
                print(f"  ...{n_calls} calls ({time.time()-t0:.0f}s)")
        per_campaign[c] = confusion(pairs)
        all_pairs += pairs
        if args.limit and n_calls >= args.limit:
            break

    results = {
        "model": args.model,
        "mode": args.mode,
        "rung": "new_technique",
        "trained_on": "T1003 (credential dumping)",
        "tested_on": "T1055 (process injection)",
        "prompt": "general malicious-activity (any ATT&CK technique)",
        "exemplars": exemplar_note,
        "surface": "injection slice: CreateRemoteThread(8) + ProcessAccess(10) subsample",
        "max_benign_per_campaign": args.max_benign,
        "note": "precision/FPR on a benign subsample; all attack events judged. Deterministic (temp 0, seed 42).",
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

    print(f"\nnew-technique LLM ({args.mode}): {args.model}, {n_calls} calls in {results['seconds']}s")
    print(f"general-malice prompt; trained/exemplified on T1003, tested on T1055 injection")
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
