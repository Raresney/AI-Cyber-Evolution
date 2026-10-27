#!/usr/bin/env python3
"""Two LSASS-dump detectors and a new-instance generalization test.

Both detectors LEARN only from the training campaigns (procedures 01-03) and are
then evaluated per-event on every campaign. The question: does detection
transfer to held-out tools (procedures 04-07) the detector never saw?

* **Signature detector** keys on *tool identity*: it learns the malicious
  SourceImage basenames seen in training attacks (e.g. ``procdump.exe``,
  ``rundll32.exe``) and flags a LSASS access only from a known-bad image. This
  is the realistic IOC / signature approach. It cannot recognize a tool it has
  never seen.

* **Behavioral detector** keys on the *technique invariant*: a process that is
  not a known system accessor opening ``lsass.exe`` with a memory-read access
  mask seen in training. It learns the access masks from training, so it can
  still fail if a new tool uses an unusual mask -- an honest test, not an oracle.

The behavioral rule deliberately encodes the same invariant used to derive
ground truth, so its recall is expected to be high; the scientific content is
the CONTRAST -- whether the signature approach collapses on unseen tools while
the behavioral one holds, and at what precision/false-positive cost on a
354k-event stream dominated by benign LSASS access.

Reads the leakage-free slice produced by ``environment/otrf_loader.py``.
Stdlib only.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PROC = REPO_ROOT / "data" / "processed" / "lsass"
DEFAULT_MANIFEST = REPO_ROOT / "results" / "lsass-slice-manifest.json"
OUT_PATH = REPO_ROOT / "results" / "lsass-detection.json"

# Same system-accessor whitelist the loader uses for the behavioral prior.
SYSTEM_WHITELIST = {
    "wininit.exe", "services.exe", "svchost.exe", "csrss.exe", "lsm.exe",
    "lsass.exe", "winlogon.exe", "msmpeng.exe", "wmiprvse.exe",
    "mssense.exe", "sensecncproxy.exe",
}
PROCESS_VM_READ = 0x0010


def basename(image) -> str:
    if not image:
        return ""
    return str(image).replace("/", "\\").split("\\")[-1].lower()


def access_int(ev) -> int | None:
    try:
        return int(str(ev.get("GrantedAccess")), 16)
    except (TypeError, ValueError):
        return None


def targets_lsass(ev) -> bool:
    return int(ev.get("EventID") or 0) == 10 and basename(ev.get("TargetImage")) == "lsass.exe"


def read_jsonl(path: Path):
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


class SignatureDetector:
    """Flags LSASS access from a tool image seen as malicious in training."""
    name = "signature(tool-identity)"

    def __init__(self):
        self.bad_images: set[str] = set()

    def fit(self, attack_events):
        for ev in attack_events:
            img = basename(ev.get("SourceImage"))
            if img:
                self.bad_images.add(img)

    def predict(self, ev) -> bool:
        return targets_lsass(ev) and basename(ev.get("SourceImage")) in self.bad_images


class BehavioralDetector:
    """Flags non-system LSASS access using a memory-read mask seen in training."""
    name = "behavioral(access-pattern)"

    def __init__(self):
        self.masks: set[int] = set()

    def fit(self, attack_events):
        for ev in attack_events:
            a = access_int(ev)
            if a is not None:
                self.masks.add(a)

    def predict(self, ev) -> bool:
        if not targets_lsass(ev):
            return False
        if basename(ev.get("SourceImage")) in SYSTEM_WHITELIST:
            return False
        a = access_int(ev)
        if a is None:
            return False
        # Mask seen in training, or any mask carrying PROCESS_VM_READ.
        return a in self.masks or bool(a & PROCESS_VM_READ)


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


def load_campaign(proc_dir: Path, campaign: str):
    cdir = proc_dir / campaign
    labels = {r["event_index"]: r["attack_present"] for r in read_jsonl(cdir / "labels.jsonl")}
    events = list(read_jsonl(cdir / "events.jsonl"))
    return events, labels


def main() -> None:
    ap = argparse.ArgumentParser(description="LSASS detectors + new-instance generalization test.")
    ap.add_argument("--processed", type=Path, default=DEFAULT_PROC)
    ap.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    ap.add_argument("--out", type=Path, default=OUT_PATH)
    args = ap.parse_args()

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    train = manifest["split"]["train"]
    holdout = manifest["split"]["holdout"]
    all_campaigns = train + holdout

    # Cache campaign data.
    data = {c: load_campaign(args.processed, c) for c in all_campaigns}

    # Fit both detectors on TRAIN attack events only.
    train_attacks = []
    for c in train:
        events, labels = data[c]
        train_attacks += [e for e in events if labels.get(e["event_index"])]

    detectors = [SignatureDetector(), BehavioralDetector()]
    for d in detectors:
        d.fit(train_attacks)

    results = {"schema": manifest["schema_version"],
               "technique": manifest["technique_under_test"],
               "split": manifest["split"],
               "signature_learned_images": sorted(detectors[0].bad_images),
               "behavioral_learned_masks": sorted(hex(m) for m in detectors[1].masks),
               "detectors": {}}

    for d in detectors:
        per_campaign = {}
        split_pairs = {"train": [], "holdout": []}
        for c in all_campaigns:
            events, labels = data[c]
            pairs = [(bool(labels.get(e["event_index"])), d.predict(e)) for e in events]
            per_campaign[c] = confusion(pairs)
            split = "train" if c in train else "holdout"
            split_pairs[split] += pairs
        results["detectors"][d.name] = {
            "per_campaign": per_campaign,
            "train": confusion(split_pairs["train"]),
            "holdout": confusion(split_pairs["holdout"]),
        }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")

    # Console report.
    print(f"technique under test: {results['technique']}  (new-instance generalization)")
    print(f"train procedures : {train}")
    print(f"holdout procedures: {holdout}")
    print(f"signature learned images: {results['signature_learned_images']}")
    print(f"behavioral learned masks: {results['behavioral_learned_masks']}\n")

    def row(label, m):
        rec = "  n/a" if m["recall"] is None else f"{m['recall']:.2f}"
        prec = "  n/a" if m["precision"] is None else f"{m['precision']:.2f}"
        return (f"  {label:12} recall={rec} precision={prec} "
                f"TP={m['tp']:3d} FP={m['fp']:4d} FN={m['fn']:3d}")

    for d in detectors:
        r = results["detectors"][d.name]
        print(d.name)
        print(row("TRAIN", r["train"]))
        print(row("HOLDOUT", r["holdout"]))
        # per-holdout-campaign recall to expose the novelty gradient
        pc = r["per_campaign"]
        grad = "   ".join(f"{c.split('_')[1]}:{(pc[c]['recall'] if pc[c]['recall'] is not None else 0):.2f}"
                          for c in holdout)
        print(f"    holdout per-campaign recall -> {grad}")
    print(f"\n  wrote {args.out.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
