#!/usr/bin/env python3
"""Figure for the paper: how recall and precision move down the ladder with scale.

Two panels, rungs 1-3 (new-instance / new-subtechnique / new-technique):
  * left  -- recall, 3B vs 8B vs 14B: the small-model collapse, and scale
             restoring transfer at every rung.
  * right -- precision at that operating point, 8B vs 14B: the cost that deepens
             with ladder distance at 8B, and how 14B claws it back at short
             distance but only slides along the frontier at the far rung.

Reads the measured results JSONs (3B = llama3.2, 8B = llama3.1:8b,
14B = qwen2.5:14b). Output: paper/fig-ladder.pdf (+ .png). Requires matplotlib.
"""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
RES = REPO / "results"
OUT = REPO / "paper"


def load(name):
    p = RES / name
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def best_recall(zero, few, key):
    """(recall, precision) of the higher-recall mode; ties -> higher precision."""
    cands = []
    for d in (zero, few):
        if d is None:
            continue
        m = d[key]
        r = m["recall"] if m["recall"] is not None else -1.0
        p = m["precision"] if m["precision"] is not None else 0.0
        cands.append((r, p))
    if not cands:
        return (0.0, 0.0)
    cands.sort(key=lambda t: (t[0], t[1]), reverse=True)
    r, p = cands[0]
    return (max(r, 0.0), p)


def series(suffix, key, z, f):
    return best_recall(load(z.format(s=suffix)), load(f.format(s=suffix)), key)


# per rung, per model: (recall, precision) at the best-recall operating point
Z1, F1 = "llm-detection{s}.json", "llm-fewshot-detection{s}.json"
Z2, F2 = "llm-subtechnique-zeroshot{s}.json", "llm-subtechnique-fewshot{s}.json"
Z3, F3 = "llm-technique-zeroshot{s}.json", "llm-technique-fewshot{s}.json"

rows = {
    "3B":  [series("", "holdout", Z1, F1), series("", "overall", Z2, F2), series("", "overall", Z3, F3)],
    "8B":  [series("-8b", "holdout", Z1, F1), series("-8b", "overall", Z2, F2), series("-8b", "overall", Z3, F3)],
    "14B": [series("-14b", "holdout", Z1, F1), series("-14b", "overall", Z2, F2), series("-14b", "overall", Z3, F3)],
}
recall = {k: [t[0] for t in v] for k, v in rows.items()}
prec = {k: [t[1] for t in v] for k, v in rows.items()}
for k in rows:
    print(f"{k}: recall={recall[k]} prec={prec[k]}")

x = [1, 2, 3]
xlab = ["Rung 1\nnew-instance", "Rung 2\nnew-subtech", "Rung 3\nnew-technique"]
C = {"3B": "#7a7a7a", "8B": "#1b6ca8", "14B": "#116530"}

fig, (axr, axp) = plt.subplots(1, 2, figsize=(8.2, 3.5), sharey=True)


def annot(ax, xs, ys, color, dy):
    for xi, yi in zip(xs, ys):
        ax.annotate(f"{yi:.2f}", (xi, yi), textcoords="offset points",
                    xytext=(0, dy), ha="center", color=color, fontsize=8)


# left: recall for all three models
for m, style in (("3B", "--^"), ("8B", "-o"), ("14B", "-D")):
    axr.plot(x, recall[m], style, color=C[m], lw=2.0, ms=6, label=f"{m} recall")
annot(axr, x, recall["14B"], C["14B"], 9)
annot(axr, x, recall["3B"], C["3B"], -15)
axr.set_title("Recall: scale restores transfer")
axr.set_ylabel("score")

# right: precision at that operating point, 8B vs 14B
for m, style in (("8B", "-o"), ("14B", "-D")):
    axp.plot(x, prec[m], style, color=C[m], lw=2.0, ms=6, label=f"{m} precision")
annot(axp, x, prec["8B"], C["8B"], -15)
annot(axp, x, prec["14B"], C["14B"], 9)
axp.set_title("Precision: 14B recovers it near, not far")

for ax in (axr, axp):
    ax.set_xticks(x)
    ax.set_xticklabels(xlab, fontsize=8)
    ax.set_ylim(-0.05, 1.12)
    ax.grid(True, axis="y", ls=":", alpha=0.5)
    ax.legend(loc="lower left", fontsize=8, framealpha=0.9)

fig.suptitle("Down the ladder (3B $\\to$ 8B $\\to$ 14B): recall rises with scale, precision pays with distance",
             fontsize=10)
fig.tight_layout(rect=(0, 0, 1, 0.96))

OUT.mkdir(parents=True, exist_ok=True)
fig.savefig(OUT / "fig-ladder.pdf")
fig.savefig(OUT / "fig-ladder.png", dpi=150)
print(f"wrote {(OUT / 'fig-ladder.pdf').relative_to(REPO)} and .png")
