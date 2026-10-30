#!/usr/bin/env python3
"""Sensitivity ablation of the LSASS behavioral invariant.

The invariant's high recall is "partly by construction" -- it encodes the same
observable used to derive ground truth. The fair question is whether that recall
is a knife-edge (a cherry-picked mask) or a robust plateau: do *reasonable*
variations of the rule still generalize to unseen tools at a low false-alarm
rate? This sweeps the two knobs that define the rule and measures each variant
on the full LSASS stream (354k events, new-instance split 01-03 / 04-07):

  * the access-mask predicate, from permissive to strict --
      none          : any non-system EID10 handle into lsass (no mask filter)
      vm_read       : mask carries PROCESS_VM_READ (0x10)   <- the paper's rule
      trained_masks : mask is one of the exact masks seen in training
  * the system-accessor whitelist, on or off.

Expected shape: the permissive end keeps recall but leaks false positives; the
strict (exact-mask) end collapses on unseen tools like a signature; the paper's
vm_read + whitelist sits at the robust corner (holdout 1.00, 0 FP). That the
exact-mask variant behaves like the signature detector is itself the point --
"behavioral vs signature" is a continuum set by how much of the surface the rule
memorizes.

Reuses the leakage-free LSASS slice and primitives. Stdlib only.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT_PATH = REPO_ROOT / "results" / "invariant-ablation.json"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


det = _load(REPO_ROOT / "experiments" / "lsass_detectors.py", "lsass_detectors")
PROCESS_VM_READ = 0x0010


def mask_pred(kind: str, trained: set[int]):
    if kind == "none":
        return lambda a: True
    if kind == "vm_read":
        return lambda a: a is not None and bool(a & PROCESS_VM_READ)
    if kind == "trained_masks":
        return lambda a: a is not None and a in trained
    raise ValueError(kind)


def predict(ev, mask_ok, use_whitelist: bool) -> bool:
    if not det.targets_lsass(ev):
        return False
    if use_whitelist and det.basename(ev.get("SourceImage")) in det.SYSTEM_WHITELIST:
        return False
    return mask_ok(det.access_int(ev))


def main() -> None:
    ap = argparse.ArgumentParser(description="LSASS invariant sensitivity ablation.")
    ap.add_argument("--processed", type=Path, default=REPO_ROOT / "data" / "processed" / "lsass")
    ap.add_argument("--manifest", type=Path, default=REPO_ROOT / "results" / "lsass-slice-manifest.json")
    ap.add_argument("--out", type=Path, default=OUT_PATH)
    args = ap.parse_args()

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    train, holdout = manifest["split"]["train"], manifest["split"]["holdout"]
    data = {c: det.load_campaign(args.processed, c) for c in train + holdout}

    # Masks seen in training attacks (for the trained_masks variant).
    trained = set()
    for c in train:
        events, labels = data[c]
        for e in events:
            if labels.get(e["event_index"]):
                a = det.access_int(e)
                if a is not None:
                    trained.add(a)

    variants = [(mk, wl) for mk in ("none", "vm_read", "trained_masks") for wl in (True, False)]
    out = {"experiment": "lsass-invariant-sensitivity-ablation",
           "split": manifest["split"],
           "trained_masks": sorted(hex(m) for m in trained),
           "paper_rule": "vm_read + whitelist",
           "variants": {}}

    print(f"trained masks: {sorted(hex(m) for m in trained)}")
    print("\nmask pred     | whitelist | holdout rec | train rec | full-stream FP | fp_rate")
    print("--------------+-----------+-------------+-----------+----------------+---------")
    for mk, wl in variants:
        mask_ok = mask_pred(mk, trained)
        split_pairs = {"train": [], "holdout": []}
        fp_total = benign_total = 0
        for c in train + holdout:
            events, labels = data[c]
            split = "train" if c in train else "holdout"
            for e in events:
                truth = bool(labels.get(e["event_index"]))
                pred = predict(e, mask_ok, wl)
                split_pairs[split].append((truth, pred))
                if not truth:
                    benign_total += 1
                    if pred:
                        fp_total += 1
        tr = det.confusion(split_pairs["train"])
        ho = det.confusion(split_pairs["holdout"])
        key = f"{mk}+{'wl' if wl else 'nowl'}"
        out["variants"][key] = {
            "mask_pred": mk, "whitelist": wl,
            "holdout_recall": ho["recall"], "train_recall": tr["recall"],
            "full_stream_fp": fp_total,
            "fp_rate": round(fp_total / benign_total, 8) if benign_total else None,
        }
        hr = "  n/a" if ho["recall"] is None else f"{ho['recall']:.2f}"
        trr = "  n/a" if tr["recall"] is None else f"{tr['recall']:.2f}"
        tag = "  <- paper" if (mk == "vm_read" and wl) else ""
        print(f"{mk:13s} | {('on' if wl else 'off'):9s} | "
              f"   {hr}      |   {trr}    | {fp_total:>10d}     | {out['variants'][key]['fp_rate']}{tag}")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print(f"\nwrote {args.out.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
