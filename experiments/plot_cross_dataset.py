#!/usr/bin/env python3
"""Figure: external validity -- the detectors on a different dataset family.

Reads results/cross-dataset-ladder.json (Splunk attack_data) and plots, per
foreign capture, the matched behavioral invariant's recall against the
OTRF-trained name signature's recall. The headline is the LSASS pair
(invariant 1.00 vs signature 0.16) reproduced off OTRF; injection shows the
injection invariant at 1.00; NTDS is annotated as surface-absent (the capture
dumps via command line, not the file/object surface the invariant keys on).

Output: paper/fig-cross-dataset.pdf (+ .png). Requires matplotlib.
"""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
D = json.loads((REPO / "results" / "cross-dataset-ladder.json").read_text(encoding="utf-8"))
caps = D["captures"]

labels = ["LSASS\n(T1003.001)", "injection\n(T1055)", "NTDS\n(T1003.003)"]
keys = ["LSASS (T1003.001)", "injection (T1055)", "NTDS (T1003.003)"]
inv = [caps[k]["matched_invariant"]["recall"] for k in keys]        # None for NTDS
sig = [caps[k].get("otrf_signature", {}).get("recall") for k in keys]

x = range(len(labels))
w = 0.38
fig, ax = plt.subplots(figsize=(6.6, 3.6))

inv_y = [v if v is not None else 0.0 for v in inv]
sig_y = [v if v is not None else 0.0 for v in sig]

b1 = ax.bar([i - w / 2 for i in x], inv_y, w, color="#116530", label="behavioral invariant")
b2 = ax.bar([i + w / 2 for i in x], sig_y, w, color="#d1495b", label="OTRF name signature")

for i, v in zip(x, inv):
    if v is None:
        ax.annotate("surface\nabsent", (i - w / 2, 0.03), ha="center", va="bottom",
                    fontsize=7.5, color="#116530", style="italic")
    else:
        ax.annotate(f"{v:.2f}", (i - w / 2, v), textcoords="offset points",
                    xytext=(0, 3), ha="center", fontsize=9, color="#116530")
for i, v in zip(x, sig):
    if v is None:
        ax.annotate("n/a", (i + w / 2, 0.03), ha="center", va="bottom", fontsize=7.5, color="#999")
    else:
        ax.annotate(f"{v:.2f}", (i + w / 2, v), textcoords="offset points",
                    xytext=(0, 3), ha="center", fontsize=9, color="#d1495b")

ax.set_xticks(list(x))
ax.set_xticklabels(labels, fontsize=9)
ax.set_ylim(0, 1.15)
ax.set_ylabel("recall on the foreign capture")
ax.set_title("External validity off OTRF: invariant holds, name signature collapses", fontsize=10)
ax.grid(True, axis="y", ls=":", alpha=0.5)
ax.legend(loc="upper right", fontsize=9, framealpha=0.95)
fig.tight_layout()

out = REPO / "paper"
fig.savefig(out / "fig-cross-dataset.pdf")
fig.savefig(out / "fig-cross-dataset.png", dpi=150)
print("invariant recall:", inv, "signature recall:", sig)
print(f"wrote {(out / 'fig-cross-dataset.pdf').relative_to(REPO)} and .png")
