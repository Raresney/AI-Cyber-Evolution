#!/usr/bin/env python3
"""Adaptive adversary on REAL telemetry: the arms race, measured on the ladder.

The synthetic co-evolution loop (``coevolution.py``) plays Red vs Blue on
generated process events. This one plays the same arms race on the **real** OTRF
LSASS slice (T1003.001): seven campaigns, each a different credential-dumping
tool, 354k real Windows/Sysmon events. The attacker mutates its *tool*; the
defender runs two detectors side by side:

* **signature** -- learns malicious ``SourceImage`` basenames (the realistic IOC
  blocklist). It can only catch a tool whose image it has already seen.
* **behavioral invariant** -- a non-system process opening ``lsass.exe`` with a
  memory-read mask (the technique surface). It is tool-agnostic.

Red deploys one tool per round over the real campaign that tool produced. When
adaptive, if the signature caught the current tool, Red **mints** -- it switches
to a tool whose image the signature has *not* learned (a real unseen dumper from
the slice). When adaptive, the signature Blue learns the current tool's image at
the end of the round (post-incident forensics) -- so it is always one round
behind an escaping Red. The invariant does not learn: it cannot be escaped by a
tool swap, only by changing the technique's telemetry surface.

Conditions (Red adaptive x signature-Blue adaptive):
    A static/static   baseline            B adaptive/static  escape
    C static/adaptive  convergence        D adaptive/adaptive the treadmill

The behavioral invariant is reported in every condition as the arms-race-proof
control. After condition D, the hardened blocklist is probed across the ladder
boundary (NTDS T1003.003) to show arms-race hardening buys nothing off-surface.

Reuses the detector primitives and the leakage-free slice from
``lsass_detectors.py`` / ``otrf_loader.py``. Stdlib only.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = REPO_ROOT / "results"
LOOP_VERSION = "coevolution-real-v1"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


det = _load(REPO_ROOT / "experiments" / "lsass_detectors.py", "lsass_detectors")

CONDITIONS = {
    "A": (False, False),
    "B": (True, False),
    "C": (False, True),
    "D": (True, True),
}

# Signature's starting knowledge: the one tool the SOC already blocks.
SEED_CAMPAIGN = "campaign_02"  # procdump {procdump.exe, procdump64.exe}


def load_slice(processed: Path, manifest: dict):
    """campaign -> {events, labels, attack_events, attack_images}."""
    slice_ = {}
    for c in manifest["campaigns"]:
        cid = c["campaign"]
        events, labels = det.load_campaign(processed, cid)
        attacks = [e for e in events if labels.get(e["event_index"])]
        imgs = {det.basename(e.get("SourceImage")) for e in attacks}
        imgs.discard("")
        slice_[cid] = {
            "events": events, "labels": labels, "attacks": attacks,
            "images": imgs, "procedure": c["procedure"],
            "n_attack": len(attacks),
        }
    return slice_


class RedToolSwapper:
    """Chooses which real dumping tool to deploy each round; mints = tool swap."""

    def __init__(self, adaptive: bool, campaigns: list[str], start: str):
        self.adaptive = adaptive
        self.campaigns = campaigns
        self.current = start
        self.used = {start}
        self.minted = 0

    def render(self) -> str:
        return self.current

    def mint(self, blue_images: set[str], slice_: dict) -> bool:
        """Switch to a tool whose image set the signature has not learned."""
        # Prefer an unseen-signature tool not yet used this run, then any
        # unseen-signature tool, then least-recently the most novel one.
        unseen = [c for c in self.campaigns
                  if slice_[c]["images"] and not (slice_[c]["images"] & blue_images)]
        fresh = [c for c in unseen if c not in self.used]
        pool = fresh or unseen
        if not pool:
            return False
        self.current = pool[0]
        self.used.add(self.current)
        self.minted += 1
        return True

    def adapt(self, caught: bool, blue_images: set[str], slice_: dict) -> bool:
        if not self.adaptive:
            return False
        # If the signature caught the current tool, escape to an unseen one.
        if caught:
            return self.mint(blue_images, slice_)
        return False


class SignatureBlue:
    """Learnable IOC blocklist over malicious tool images (post-incident)."""

    def __init__(self, adaptive: bool, seed_images: set[str]):
        self.adaptive = adaptive
        self.d = det.SignatureDetector()
        self.d.bad_images = set(seed_images)

    @property
    def images(self) -> set[str]:
        return self.d.bad_images

    def predict(self, ev) -> bool:
        return self.d.predict(ev)

    def adapt(self, tool_images: set[str]) -> set[str]:
        """Post-incident: forensics reveal the tool -> add its image."""
        if not self.adaptive:
            return set()
        learned = tool_images - self.d.bad_images
        self.d.bad_images |= tool_images
        return learned


def evaluate(detector, events, labels) -> dict:
    pairs = [(bool(labels.get(e["event_index"])), detector.predict(e)) for e in events]
    return det.confusion(pairs)


def run(condition: str, rounds: int, slice_: dict, campaigns: list[str]) -> dict:
    red_adaptive, blue_adaptive = CONDITIONS[condition]
    red = RedToolSwapper(red_adaptive, campaigns, SEED_CAMPAIGN)
    sig = SignatureBlue(blue_adaptive, slice_[SEED_CAMPAIGN]["images"])

    # The behavioral invariant is fixed: fit masks once on the SEED tool only,
    # exactly as the ladder experiment fits on train. It never adapts.
    inv = det.BehavioralDetector()
    inv.fit(slice_[SEED_CAMPAIGN]["attacks"])

    series = []
    for r in range(rounds):
        tool = red.render()
        events = slice_[tool]["events"]
        labels = slice_[tool]["labels"]

        sig_m = evaluate(sig, events, labels)
        inv_m = evaluate(inv, events, labels)
        caught = (sig_m["recall"] or 0) > 0

        before_imgs = sorted(sig.images)
        learned = sig.adapt(slice_[tool]["images"])          # Blue learns tool (post-incident)
        minted = red.adapt(caught, sig.images, slice_)        # Red escapes if caught

        series.append({
            "round": r,
            "tool": tool,
            "procedure": slice_[tool]["procedure"],
            "tool_images": sorted(slice_[tool]["images"]),
            "signature": {k: sig_m[k] for k in ("recall", "precision", "false_positive_rate", "tp", "fp", "fn")},
            "invariant": {k: inv_m[k] for k in ("recall", "precision", "false_positive_rate", "tp", "fp", "fn")},
            "signature_caught": caught,
            "signature_known_before": before_imgs,
            "signature_learned_this_round": sorted(learned),
            "red_minted": minted,
            "red_next_tool": red.current,
            "red_tools_minted": red.minted,
        })

    return {
        "loop_version": LOOP_VERSION,
        "condition": condition,
        "condition_meaning": {"red_adaptive": red_adaptive, "signature_blue_adaptive": blue_adaptive},
        "rounds": rounds,
        "seed_campaign": SEED_CAMPAIGN,
        "final_signature_images": sorted(sig.images),
        "series": series,
    }


def ladder_probe(slice_images: set[str], processed_ntds: Path) -> dict | None:
    """Hardened LSASS blocklist, tested across the ladder on NTDS (T1003.003)."""
    if not processed_ntds.exists():
        return None
    hardened = det.SignatureDetector()
    hardened.bad_images = set(slice_images)
    campaigns = sorted(p.name for p in processed_ntds.iterdir() if p.is_dir())
    pairs = []
    for c in campaigns:
        events, labels = det.load_campaign(processed_ntds, c)
        pairs += [(bool(labels.get(e["event_index"])), hardened.predict(e)) for e in events]
    m = det.confusion(pairs)
    return {"surface": "NTDS T1003.003 (ladder rung 2)",
            "hardened_images": sorted(slice_images),
            "campaigns": campaigns,
            **{k: m[k] for k in ("recall", "precision", "tp", "fp", "fn")}}


def _f(x):
    return " n/a" if x is None else f"{x:4.2f}"


def print_table(res: dict) -> None:
    cm = res["condition_meaning"]
    print(f"\n=== Condition {res['condition']} "
          f"(Red adaptive={cm['red_adaptive']}, signature Blue adaptive={cm['signature_blue_adaptive']}) ===")
    print("rnd | tool (procedure)          | sig rec/prec | inv rec/prec | mint | sig knows")
    print("----+---------------------------+--------------+--------------+------+----------")
    for s in res["series"]:
        sg, iv = s["signature"], s["invariant"]
        mint = " * " if s["red_minted"] else "   "
        print(f"{s['round']:3d} | {s['procedure']:25.25s} | "
              f"{_f(sg['recall'])}/{_f(sg['precision'])} | "
              f"{_f(iv['recall'])}/{_f(iv['precision'])} | {mint}  | "
              f"{len(s['signature_known_before'])} imgs")


def main() -> None:
    ap = argparse.ArgumentParser(description="Adaptive adversary on real LSASS telemetry.")
    ap.add_argument("--processed", type=Path, default=REPO_ROOT / "data" / "processed" / "lsass")
    ap.add_argument("--manifest", type=Path, default=REPO_ROOT / "results" / "lsass-slice-manifest.json")
    ap.add_argument("--ntds", type=Path, default=REPO_ROOT / "data" / "processed" / "ntds")
    ap.add_argument("--rounds", type=int, default=8)
    ap.add_argument("--condition", choices=list(CONDITIONS), default="D")
    ap.add_argument("--all", action="store_true", help="run A,B,C,D")
    ap.add_argument("--out", type=Path, default=RESULTS_DIR / "coevolution-real.json")
    args = ap.parse_args()

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    slice_ = load_slice(args.processed, manifest)
    campaigns = [c["campaign"] for c in manifest["campaigns"]]

    conditions = list(CONDITIONS) if args.all else [args.condition]
    out = {"loop_version": LOOP_VERSION,
           "technique": manifest["technique_under_test"],
           "source": manifest["source"],
           "n_tools": len(campaigns),
           "total_attack_events": sum(slice_[c]["n_attack"] for c in campaigns),
           "seed_campaign": SEED_CAMPAIGN,
           "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "conditions": {}}

    d_final_images = None
    for cond in conditions:
        res = run(cond, args.rounds, slice_, campaigns)
        print_table(res)
        out["conditions"][cond] = res
        if cond == "D":
            d_final_images = set(res["final_signature_images"])

    # Cross-ladder probe with the arms-race-hardened blocklist.
    probe_images = d_final_images
    if probe_images is None and conditions:
        probe_images = set(out["conditions"][conditions[-1]]["final_signature_images"])
    probe = ladder_probe(probe_images, args.ntds)
    out["ladder_probe"] = probe

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")

    if probe:
        print(f"\n=== Ladder probe: arms-race-hardened LSASS blocklist on {probe['surface']} ===")
        print(f"  hardened images: {probe['hardened_images']}")
        print(f"  NTDS recall={_f(probe['recall'])}  (TP={probe['tp']} FP={probe['fp']} FN={probe['fn']})")
        print("  -> hardening within a surface buys nothing across the ladder boundary.")
    print(f"\nwrote {args.out.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
