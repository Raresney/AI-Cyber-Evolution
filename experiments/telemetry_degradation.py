#!/usr/bin/env python3
"""Detection robustness under degraded telemetry (RQ hypothesis 4 / condition E).

The research question promises an answer under *incomplete and noisy* telemetry;
every other experiment assumes a perfect sensor. This one degrades the holdout
LSASS stream and measures how the two single-event detectors decay.

Both the signature (keys on ``SourceImage``) and the behavioral invariant (keys
on ``GrantedAccess`` + target) fire on a *single* Sysmon EID 10 event, so neither
has multi-event redundancy to fall back on. That makes their failure modes clean
to separate:

* **drop** -- the sensor misses whole events (EDR gap, log-pipeline loss). A
  dropped attack event is an unavoidable miss for *any* single-event detector, so
  this is the shared floor: recall must decay with the drop rate at the same slope
  for both. It marks where only multi-event / chain redundancy could help.

* **field:SourceImage** -- the sensor delivers the event but loses the image path
  (truncation, redaction, ETW field dropout). This is the field the *attacker*
  already controls cheaply (the arms race), so the signature was brittle here all
  along; the invariant ignores it.

* **field:GrantedAccess** -- the sensor loses the access mask. This is the field
  the *invariant* is built on, and it is the one the attacker cannot forge but a
  degraded sensor can still drop. The signature ignores it.

So the invariant does not buy robustness for free: it trades an
attacker-controlled brittleness (image name) for a sensor-controlled one (mask
fidelity). Quantifying that trade is the contribution here.

Degradation is stochastic, so each (mode, severity) is averaged over ``--seeds``
independent draws and the mean is reported. Reuses the fitted detectors and the
leakage-free slice; standard library only.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import random
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT_PATH = REPO_ROOT / "results" / "telemetry-degradation.json"
SEVERITIES = [0.0, 0.1, 0.25, 0.5, 0.75, 0.9]


def _load(rel: str, name: str):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


det = _load("experiments/lsass_detectors.py", "lsass_detectors")


def degrade(event: dict, mode: str, rng: random.Random, p: float):
    """Return a possibly-degraded copy of ``event``, or ``None`` if it is dropped.

    ``drop`` removes the event with probability ``p``. The ``field:*`` modes keep
    the event but, with probability ``p``, blank the named field (the way a sensor
    that loses a field delivers it: present record, empty value).
    """
    if mode == "drop":
        return None if rng.random() < p else event
    field = mode.split(":", 1)[1]
    if rng.random() < p:
        ev = dict(event)
        ev[field] = ""
        return ev
    return event


def eval_once(detector, stream, mode: str, seed: int, p: float) -> dict:
    """One degraded pass. A dropped event keeps its truth label but can never be
    predicted positive, so whole-event loss shows up as a forced miss."""
    rng = random.Random(seed)
    pairs = []
    for truth, event in stream:
        degraded = degrade(event, mode, rng, p)
        pred = False if degraded is None else detector.predict(degraded)
        pairs.append((truth, pred))
    return det.confusion(pairs)


def main() -> None:
    ap = argparse.ArgumentParser(description="Detection robustness under degraded telemetry.")
    ap.add_argument("--processed", type=Path, default=det.DEFAULT_PROC)
    ap.add_argument("--manifest", type=Path, default=det.DEFAULT_MANIFEST)
    ap.add_argument("--seeds", type=int, default=20)
    ap.add_argument("--out", type=Path, default=OUT_PATH)
    args = ap.parse_args()

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    train = manifest["split"]["train"]
    holdout = manifest["split"]["holdout"]

    data = {c: det.load_campaign(args.processed, c) for c in train + holdout}

    # Fit on CLEAN train attacks -- degradation is applied only at evaluation.
    train_attacks = []
    for c in train:
        events, labels = data[c]
        train_attacks += [e for e in events if labels.get(e["event_index"])]
    detectors = [det.SignatureDetector(), det.BehavioralDetector()]
    for d in detectors:
        d.fit(train_attacks)

    # Holdout evaluation stream: (truth, event) over every held-out campaign.
    stream = []
    for c in holdout:
        events, labels = data[c]
        stream += [(bool(labels.get(e["event_index"])), e) for e in events]
    n_attacks = sum(1 for t, _ in stream if t)

    modes = ["drop", "field:SourceImage", "field:GrantedAccess"]
    results = {
        "schema": manifest["schema_version"],
        "technique": manifest["technique_under_test"],
        "holdout_campaigns": holdout,
        "holdout_events": len(stream),
        "holdout_attacks": n_attacks,
        "seeds": args.seeds,
        "severities": SEVERITIES,
        "modes": {},
    }

    for mode in modes:
        results["modes"][mode] = {}
        for d in detectors:
            curve = []
            for p in SEVERITIES:
                runs = [eval_once(d, stream, mode, s, p) for s in range(args.seeds)]
                def mean(key):
                    vals = [r[key] for r in runs if r[key] is not None]
                    return round(sum(vals) / len(vals), 4) if vals else None
                curve.append({
                    "severity": p,
                    "recall": mean("recall"),
                    "precision": mean("precision"),
                    "fp": round(sum(r["fp"] for r in runs) / len(runs), 2),
                })
            results["modes"][mode][d.name] = curve

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")

    # Console report.
    print(f"degraded-telemetry robustness  (T1003.001, holdout {holdout})")
    print(f"holdout stream: {len(stream)} events, {n_attacks} attack events, "
          f"mean over {args.seeds} seeds\n")
    hdr = "severity ->   " + "  ".join(f"{p:>5.2f}" for p in SEVERITIES)
    for mode in modes:
        print(f"[{mode}]  recall")
        print("  " + hdr)
        for d in detectors:
            curve = results["modes"][mode][d.name]
            cells = "  ".join(
                ("  n/a" if c["recall"] is None else f"{c['recall']:5.2f}") for c in curve)
            print(f"  {d.name:26} {cells}")
        print()
    print(f"  wrote {args.out.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
