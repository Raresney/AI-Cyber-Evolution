#!/usr/bin/env python3
"""LLM over the APT29 Day 1 chain: coverage vs. false-alarm on a real intrusion.

The behavioral invariants catch the chain's credential-dumping and injection
steps with zero false positives, but cover only their own ~3 techniques
(experiments/ladder_chain.py). This asks the complementary question for an LLM:
run the general ``is this ANY malicious technique?'' detector over candidate
chain events and see whether its broader net buys coverage at a false-alarm
cost -- the precision/coverage trade the deterministic rules make explicit.

Judged surface: the same handle/thread events the invariants act on -- Sysmon
ProcessAccess(10) and CreateRemoteThread(8). All labeled attack events judged;
benign candidates of the same types are subsampled (seeded). Deterministic
(temp 0, seed 42). Defaults to the 8B model. Stdlib only.
"""
from __future__ import annotations

import argparse
import json
import random
import time
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
APT29 = REPO_ROOT / "data" / "processed" / "apt29" / "day1"
OUT_PATH = REPO_ROOT / "results" / "llm-chain-detection.json"

SYSTEM_PROMPT = (
    "You are a SOC detection analyst. You are given one Windows host event "
    "(Sysmon or the Security log) from an enterprise host. Decide whether it is "
    "part of ANY malicious attack technique (MITRE ATT&CK) -- credential "
    "dumping, process injection, lateral movement, persistence, defense evasion, "
    "and so on -- as opposed to normal operating-system or application activity. "
    "Judge the intent of the telemetry. Respond ONLY with JSON of the form "
    '{"malicious": true or false, "reason": "<one short sentence>"}.'
)

SURFACE_EIDS = {8, 10}


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


def on_surface(ev) -> bool:
    return int(ev.get("EventID") or 0) in SURFACE_EIDS


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
        ("CallTrace", call or None),
    ]
    lines = ["Windows host event:"]
    lines += [f"- {k}: {v}" for k, v in fields if v not in (None, "")]
    return "\n".join(lines)


def ollama_generate(prompt, model, url, retries=2):
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


def parse_verdict(resp):
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


def main() -> None:
    ap = argparse.ArgumentParser(description="LLM over the APT29 Day1 chain.")
    ap.add_argument("--model", default="llama3.1:8b")
    ap.add_argument("--url", default="http://localhost:11434/api/generate")
    ap.add_argument("--out", type=Path, default=OUT_PATH)
    ap.add_argument("--max-benign", type=int, default=50)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--seed", type=int, default=1337)
    args = ap.parse_args()

    labels = {r["event_index"]: r for r in read_jsonl(APT29 / "labels.jsonl")}
    attacks, benign = [], []
    for ev in read_jsonl(APT29 / "events.jsonl"):
        if not on_surface(ev):
            continue
        (attacks if labels.get(ev["event_index"], {}).get("attack_present") else benign).append(ev)
    rng = random.Random(args.seed)
    if len(benign) > args.max_benign:
        benign = rng.sample(benign, args.max_benign)

    pairs, verdict_log, n_calls = [], [], 0
    t0 = time.time()
    for truth, ev in ([(True, e) for e in attacks] + [(False, e) for e in benign]):
        if args.limit and n_calls >= args.limit:
            break
        pred = parse_verdict(ollama_generate(event_to_prompt(ev), args.model, args.url))
        n_calls += 1
        pairs.append((truth, pred))
        verdict_log.append({"truth": truth, "pred": pred, "eid": ev.get("EventID"),
                            "src": basename(ev.get("SourceImage") or ev.get("Image")),
                            "tgt": basename(ev.get("TargetImage")), "ga": ev.get("GrantedAccess")})
        if n_calls % 20 == 0:
            print(f"  ...{n_calls} calls ({time.time()-t0:.0f}s)")

    conf = confusion(pairs)
    flagged = sum(1 for _, p in pairs if p)
    results = {
        "model": args.model, "rung": "new_chain",
        "dataset": "APT29 Day 1 (MITRE ATT&CK Evals)",
        "prompt": "general malicious-activity (any ATT&CK technique)",
        "surface": "ProcessAccess(10) + CreateRemoteThread(8)",
        "judged": n_calls, "attack_events": len(attacks),
        "benign_subsample": len(benign),
        "flag_rate_on_judged": round(flagged / n_calls, 4) if n_calls else None,
        "overall": conf, "seconds": round(time.time() - t0, 1),
        "verdicts": verdict_log,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")

    def row(m):
        rec = "n/a" if m["recall"] is None else f"{m['recall']:.2f}"
        prec = "n/a" if m["precision"] is None else f"{m['precision']:.2f}"
        return f"  recall={rec} precision={prec} TP={m['tp']} FP={m['fp']} FN={m['fn']}"

    print(f"\nLLM over APT29 chain: {args.model}, {n_calls} calls in {results['seconds']}s")
    print(row(conf))
    print(f"  flagged {flagged}/{n_calls} judged events as malicious "
          f"(invariants: 5 TP / 0 FP over all 196k)")
    print(f"  wrote {args.out.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
