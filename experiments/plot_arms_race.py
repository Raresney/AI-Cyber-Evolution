#!/usr/bin/env python3
"""Figure: the real-telemetry arms race (condition D) vs the arms-race-proof invariant.

Reads results/coevolution-real.json (condition D, tool-swap) and plots, per round:
  * the adaptive signature's recall -- oscillating as Red mints a fresh unseen
    tool each time it is caught, until the finite real tool pool is exhausted;
  * the behavioral invariant's recall -- flat 1.00, untouched by any tool swap;
  * mint markers where Red switches tool.

Output: paper/fig-arms-race.pdf (+ .png). Requires matplotlib.
"""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
D = json.loads((REPO / "results" / "coevolution-real.json").read_text(encoding="utf-8"))
series = D["conditions"]["D"]["series"]

rounds = [s["round"] for s in series]
sig = [s["signature"]["recall"] if s["signature"]["recall"] is not None else 0.0 for s in series]
inv = [s["invariant"]["recall"] if s["invariant"]["recall"] is not None else 0.0 for s in series]
mints = [s["round"] for s in series if s["red_minted"]]

fig, ax = plt.subplots(figsize=(6.6, 3.5))
for mx in mints:
    ax.axvline(mx + 0.5, color="#d1495b", ls=":", lw=1.2, alpha=0.6)
ax.plot(rounds, inv, "-D", color="#116530", lw=2.4, ms=6, label="behavioral invariant (arms-race-proof)")
ax.plot(rounds, sig, "-o", color="#1b6ca8", lw=2.2, ms=6, label="adaptive signature (name blocklist)")

# label tool at each round along the bottom
for s in series:
    ax.annotate(s["procedure"].split("_")[0][:9], (s["round"], -0.02),
                rotation=45, ha="right", va="top", fontsize=6.5, color="#555")

ax.plot([], [], color="#d1495b", ls=":", label="Red mints a fresh unseen tool")
ax.set_xticks(rounds)
ax.set_ylim(-0.08, 1.12)
ax.set_xlabel("round")
ax.set_ylabel("recall")
ax.set_title("Arms race on real LSASS telemetry: signature oscillates, invariant holds")
ax.grid(True, axis="y", ls=":", alpha=0.5)
ax.legend(loc="center right", fontsize=8, framealpha=0.95)
fig.tight_layout()

out = REPO / "paper"
fig.savefig(out / "fig-arms-race.pdf")
fig.savefig(out / "fig-arms-race.png", dpi=150)
print("signature recall:", sig)
print("invariant recall:", inv)
print("mint rounds:", mints)
print(f"wrote {(out / 'fig-arms-race.pdf').relative_to(REPO)} and .png")
