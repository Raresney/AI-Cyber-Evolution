#!/usr/bin/env python3
"""Few-shot LSASS-dump detector (local llama3.2 via Ollama).

The companion to ``llm_detector.py`` (zero-shot). Here the model is shown a
handful of LABELED example events drawn ONLY from the training campaigns
(procedures 01-03) before each query, then asked to judge an unseen event.

This is the proper generalization test for the LLM. The held-out campaigns
(04-07) use four tools that never appear among the exemplars, so holdout recall
measures whether the model generalizes the *technique* from a few examples of
other tools -- the same new-instance question the signature/behavioral
detectors answer. The signature detector collapses on unseen tools; does an LLM
given a few training examples collapse the same way, or reason to the invariant?

Exemplars are seeded and fixed: a few malicious dumps spread across the three
training tools, plus a few benign LSASS accesses (system processes), so the
model sees both classes. Exemplar event indices are excluded from the train
evaluation so the model is never scored on an event it was shown.

Same judged surface as zero-shot: Event ID 10 ProcessAccess to lsass.exe. All
attack events judged; benign accesses subsampled (seeded). Deterministic
(temp 0, seed 42).

Stdlib only (urllib talks to Ollama).
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
ZEROSHOT_PATH = REPO_ROOT / "results" / "llm-detection.json"
OUT_PATH = REPO_ROOT / "results" / "llm-fewshot-detection.json"

SYSTEM_PROMPT = (
    "You are a SOC detection analyst. You are given one Windows Sysmon "
    "ProcessAccess event (Event ID 10). Decide whether it represents a "
    "malicious attempt to read LSASS process memory for credential theft "
    "(MITRE ATT&CK T1003.001 - OS Credential Dumping: LSASS Memory). "
    "Base your judgement on the telemetry and on the labeled examples given. "
    "Respond ONLY with JSON of the form "
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


def build_fewshot_preamble(shots) -> str:
    """Render labeled exemplars as a fixed block that precedes every query."""
    blocks = ["Here are labeled examples from past investigations:\n"]
    for i, (ev, label) in enumerate(shots, 1):
        verdict = json.dumps({"malicious": label,
                              "reason": ("known LSASS credential dump"
                                         if label else
                                         "benign system access to lsass")})
        blocks.append(f"Example {i}:\n{event_to_prompt(ev)}\nVerdict: {verdict}\n")
    blocks.append("Now judge this new event using the same reasoning:\n")
    return "\n".join(blocks)


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


def load_lsass(proc_dir: Path, campaign: str):
    """Return (attacks, benign) EID10->lsass events for a campaign."""
    cdir = proc_dir / campaign
    labels = {r["event_index"]: r["attack_present"] for r in read_jsonl(cdir / "labels.jsonl")}
    attacks, benign = [], []
    for ev in read_jsonl(cdir / "events.jsonl"):
        if not targets_lsass(ev):
            continue
        (attacks if labels.get(ev["event_index"]) else benign).append(ev)
    return attacks, benign


def select_exemplars(proc_dir, train, n_pos, n_neg, rng):
    """Pick malicious + benign exemplars from TRAIN campaigns only.

    Malicious exemplars are spread across the training tools (one campaign at a
    time, round-robin) so the model sees tool variety. Returns the exemplar
    list and the set of (campaign, event_index) used, to exclude from eval.
    """
    per_train = {c: load_lsass(proc_dir, c) for c in train}
    pos, neg, used = [], [], set()

    # round-robin malicious across train tools
    pools = {c: list(per_train[c][0]) for c in train}
    for c in train:
        rng.shuffle(pools[c])
    ci = 0
    while len(pos) < n_pos and any(pools.values()):
        c = train[ci % len(train)]
        ci += 1
        if pools[c]:
            ev = pools[c].pop()
            pos.append((ev, True))
            used.add((c, ev["event_index"]))

    # benign from pooled train benign
    benign_pool = []
    for c in train:
        for ev in per_train[c][1]:
            benign_pool.append((c, ev))
    rng.shuffle(benign_pool)
    for c, ev in benign_pool:
        if len(neg) >= n_neg:
            break
        neg.append((ev, False))
        used.add((c, ev["event_index"]))

    # interleave pos/neg so order does not bias the model toward one class
    shots = []
    for i in range(max(len(pos), len(neg))):
        if i < len(pos):
            shots.append(pos[i])
        if i < len(neg):
            shots.append(neg[i])
    return shots, used


def main() -> None:
    ap = argparse.ArgumentParser(description="Few-shot LLM LSASS detector via Ollama.")
    ap.add_argument("--processed", type=Path, default=DEFAULT_PROC)
    ap.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    ap.add_argument("--out", type=Path, default=OUT_PATH)
    ap.add_argument("--model", default="llama3.2")
    ap.add_argument("--url", default="http://localhost:11434/api/generate")
    ap.add_argument("--max-benign", type=int, default=15,
                    help="benign lsass-access events judged per campaign")
    ap.add_argument("--pos-shots", type=int, default=3)
    ap.add_argument("--neg-shots", type=int, default=3)
    ap.add_argument("--limit", type=int, default=0,
                    help="smoke test: cap total LLM calls (0 = no cap)")
    ap.add_argument("--seed", type=int, default=1337)
    args = ap.parse_args()

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    train = manifest["split"]["train"]
    holdout = manifest["split"]["holdout"]
    all_campaigns = train + holdout
    rng = random.Random(args.seed)

    shots, used = select_exemplars(args.processed, train, args.pos_shots,
                                   args.neg_shots, rng)
    preamble = build_fewshot_preamble(shots)
    shot_summary = [{"campaign": c, "event_index": idx} for (c, idx) in sorted(used)]

    per_campaign, split_pairs = {}, {"train": [], "holdout": []}
    verdict_log = []
    n_calls = 0
    t0 = time.time()
    for c in all_campaigns:
        attacks, benign = load_lsass(args.processed, c)
        # exclude exemplar events so the model is not scored on what it was shown
        attacks = [e for e in attacks if (c, e["event_index"]) not in used]
        benign = [e for e in benign if (c, e["event_index"]) not in used]
        if len(benign) > args.max_benign:
            benign = rng.sample(benign, args.max_benign)
        pairs = []
        for truth, ev in ([(True, e) for e in attacks] + [(False, e) for e in benign]):
            if args.limit and n_calls >= args.limit:
                break
            prompt = preamble + "\n" + event_to_prompt(ev)
            resp = ollama_generate(prompt, args.model, args.url)
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
        "mode": f"few-shot ({args.pos_shots}+{args.neg_shots})",
        "surface": "EID10 ProcessAccess to lsass.exe",
        "exemplars_from": "train campaigns only (01-03); excluded from train eval",
        "exemplars": shot_summary,
        "max_benign_per_campaign": args.max_benign,
        "note": ("precision/FPR estimated on a benign subsample; all non-exemplar "
                 "attack events judged. Verdicts deterministic (temp 0, seed 42)."),
        "n_calls": n_calls,
        "seconds": round(time.time() - t0, 1),
        "per_campaign": per_campaign,
        "train": confusion(split_pairs["train"]),
        "holdout": confusion(split_pairs["holdout"]),
        "verdicts": verdict_log,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")

    def row(label, m):
        rec = "  n/a" if m["recall"] is None else f"{m['recall']:.2f}"
        prec = "  n/a" if m["precision"] is None else f"{m['precision']:.2f}"
        return f"  {label:28} recall={rec} precision={prec} TP={m['tp']:3d} FP={m['fp']:4d} FN={m['fn']:3d}"

    print(f"\nfew-shot LLM: {args.model} ({args.pos_shots}+{args.neg_shots}), "
          f"{n_calls} calls in {results['seconds']}s")
    print("TRAIN:");   print(row("llm(few-shot)", results["train"]))
    print("HOLDOUT:"); print(row("llm(few-shot)", results["holdout"]))
    pc = results["per_campaign"]
    grad = "   ".join(f"{c.split('_')[1]}:{(pc[c]['recall'] if pc[c]['recall'] is not None else 0):.2f}"
                      for c in holdout if c in pc)
    print(f"  holdout per-campaign recall -> {grad}")

    # Comparison with signature/behavioral + zero-shot LLM.
    baseline = json.loads(BASELINE_PATH.read_text(encoding="utf-8")) if BASELINE_PATH.exists() else None
    zero = json.loads(ZEROSHOT_PATH.read_text(encoding="utf-8")) if ZEROSHOT_PATH.exists() else None
    print("\n=== comparison (holdout recall / precision) ===")
    if baseline:
        for name, det in baseline["detectors"].items():
            h = det["holdout"]
            print(f"  {name:28} recall={h['recall']} precision={h['precision']}")
    if zero:
        h = zero["holdout"]
        print(f"  {'llm(zero-shot)':28} recall={h['recall']} precision={h['precision']}")
    h = results["holdout"]
    print(f"  {'llm(few-shot)':28} recall={h['recall']} precision={h['precision']}")
    print(f"\n  wrote {args.out.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
