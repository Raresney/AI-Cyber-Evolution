#!/usr/bin/env python3
"""LLM-based LSASS-dump detector (local llama3.2 via Ollama).

Asks a local LLM to judge, per event, whether a Sysmon ProcessAccess to
lsass.exe is a malicious credential dump (MITRE T1003.001). The point is the
generalization question that decides the paper: does the LLM reason to the
technique invariant (and so detect unseen tools, like the behavioral detector),
or does it latch onto familiar tool names (and miss unseen tools, like the
signature detector)?

The LLM judges the same surface the other detectors act on: Event ID 10 events
targeting lsass.exe. Every attack event is judged; benign LSASS accesses are
subsampled (seeded) to keep the number of calls tractable, so precision/FPR are
estimated on that benign sample (documented in the output).

Zero-shot by default: the verdict reflects the model's pretrained knowledge,
with a neutral prompt that does not coach behavioral-vs-signature reasoning.

Dependencies: none beyond the standard library (urllib talks to Ollama). The
only external requirement is a running Ollama with the model pulled.
"""
from __future__ import annotations

import argparse
import json
import random
import time
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PROC = REPO_ROOT / "data" / "processed" / "lsass"
DEFAULT_MANIFEST = REPO_ROOT / "results" / "lsass-slice-manifest.json"
BASELINE_PATH = REPO_ROOT / "results" / "lsass-detection.json"
OUT_PATH = REPO_ROOT / "results" / "llm-detection.json"

SYSTEM_PROMPT = (
    "You are a SOC detection analyst. You are given one Windows Sysmon "
    "ProcessAccess event (Event ID 10). Decide whether it represents a "
    "malicious attempt to read LSASS process memory for credential theft "
    "(MITRE ATT&CK T1003.001 - OS Credential Dumping: LSASS Memory). "
    "Base your judgement on the telemetry. Respond ONLY with JSON of the form "
    '{"malicious": true or false, "reason": "<one short sentence>"}.'
)


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


def targets_lsass(ev) -> bool:
    return int(ev.get("EventID") or 0) == 10 and basename(ev.get("TargetImage")) == "lsass.exe"


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
        except Exception as e:  # noqa: BLE001 - surface as benign-default below
            last = e
            time.sleep(1.0)
    raise RuntimeError(f"ollama call failed: {last}")


def event_to_prompt(ev) -> str:
    call = str(ev.get("CallTrace") or "")
    if len(call) > 300:
        call = call[:300] + "..."
    lines = [
        "Windows Sysmon ProcessAccess event (EventID 10):",
        f"- SourceImage: {ev.get('SourceImage')}",
        f"- TargetImage: {ev.get('TargetImage')}",
        f"- GrantedAccess: {ev.get('GrantedAccess')}",
        f"- SourceUser: {ev.get('SourceUser')}",
        f"- CallTrace: {call}",
    ]
    return "\n".join(lines)


def parse_verdict(resp: str) -> bool:
    try:
        obj = json.loads(resp)
        return bool(obj.get("malicious"))
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


def build_candidates(proc_dir: Path, campaign: str, max_benign: int, rng: random.Random):
    cdir = proc_dir / campaign
    labels = {r["event_index"]: r["attack_present"] for r in read_jsonl(cdir / "labels.jsonl")}
    attacks, benign = [], []
    for ev in read_jsonl(cdir / "events.jsonl"):
        if not targets_lsass(ev):
            continue
        (attacks if labels.get(ev["event_index"]) else benign).append(ev)
    if len(benign) > max_benign:
        benign = rng.sample(benign, max_benign)
    return attacks, benign


def main() -> None:
    ap = argparse.ArgumentParser(description="LLM LSASS detector via Ollama.")
    ap.add_argument("--processed", type=Path, default=DEFAULT_PROC)
    ap.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    ap.add_argument("--out", type=Path, default=OUT_PATH)
    ap.add_argument("--model", default="llama3.2")
    ap.add_argument("--url", default="http://localhost:11434/api/generate")
    ap.add_argument("--max-benign", type=int, default=40,
                    help="benign lsass-access events judged per campaign")
    ap.add_argument("--limit", type=int, default=0,
                    help="smoke test: cap total LLM calls (0 = no cap)")
    ap.add_argument("--seed", type=int, default=1337)
    args = ap.parse_args()

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    train = manifest["split"]["train"]
    holdout = manifest["split"]["holdout"]
    all_campaigns = train + holdout
    rng = random.Random(args.seed)

    per_campaign, split_pairs = {}, {"train": [], "holdout": []}
    verdict_log = []
    n_calls = 0
    t0 = time.time()
    for c in all_campaigns:
        attacks, benign = build_candidates(args.processed, c, args.max_benign, rng)
        pairs = []
        for truth, ev in ([(True, e) for e in attacks] + [(False, e) for e in benign]):
            if args.limit and n_calls >= args.limit:
                break
            resp = ollama_generate(event_to_prompt(ev), args.model, args.url)
            pred = parse_verdict(resp)
            n_calls += 1
            pairs.append((truth, pred))
            verdict_log.append({"campaign": c, "truth": truth, "pred": pred,
                                "source": basename(ev.get("SourceImage")),
                                "granted": ev.get("GrantedAccess")})
            if n_calls % 20 == 0:
                print(f"  ...{n_calls} calls ({time.time()-t0:.0f}s)")
        per_campaign[c] = confusion(pairs)
        split = "train" if c in train else "holdout"
        split_pairs[split] += pairs
        if args.limit and n_calls >= args.limit:
            break

    results = {
        "model": args.model,
        "mode": "zero-shot",
        "surface": "EID10 ProcessAccess to lsass.exe",
        "max_benign_per_campaign": args.max_benign,
        "note": ("precision/FPR estimated on a benign subsample; all attack "
                 "events judged. Verdicts deterministic (temp 0, seed 42)."),
        "n_calls": n_calls,
        "seconds": round(time.time() - t0, 1),
        "per_campaign": per_campaign,
        "train": confusion(split_pairs["train"]),
        "holdout": confusion(split_pairs["holdout"]),
        "verdicts": verdict_log,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")

    # Comparison with the signature/behavioral baselines.
    baseline = json.loads(BASELINE_PATH.read_text(encoding="utf-8")) if BASELINE_PATH.exists() else None

    def row(label, m):
        rec = "  n/a" if m["recall"] is None else f"{m['recall']:.2f}"
        prec = "  n/a" if m["precision"] is None else f"{m['precision']:.2f}"
        return f"  {label:28} recall={rec} precision={prec} TP={m['tp']:3d} FP={m['fp']:4d} FN={m['fn']:3d}"

    print(f"\nLLM detector: {args.model} (zero-shot), {n_calls} calls in {results['seconds']}s")
    print("TRAIN:");   print(row("llm", results["train"]))
    print("HOLDOUT:"); print(row("llm", results["holdout"]))
    pc = results["per_campaign"]
    grad = "   ".join(f"{c.split('_')[1]}:{(pc[c]['recall'] if pc[c]['recall'] is not None else 0):.2f}"
                      for c in holdout if c in pc)
    print(f"  holdout per-campaign recall -> {grad}")
    if baseline:
        print("\n=== comparison (holdout recall / precision) ===")
        for name, det in baseline["detectors"].items():
            h = det["holdout"]
            print(f"  {name:28} recall={h['recall']} precision={h['precision']}")
        h = results["holdout"]
        print(f"  {'llm(zero-shot)':28} recall={h['recall']} precision={h['precision']}")
    print(f"\n  wrote {args.out.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
