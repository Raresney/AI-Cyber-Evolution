#!/usr/bin/env python3
"""Figure for the paper: how recall and precision move down the ladder.

Reads the measured results JSONs and plots, per rung:
  * 3B recall (best of zero/few)   -- the small-model collapse,
  * 8B recall (best of zero/few)   -- scale restores transfer,
  * 8B precision at that operating point -- the cost, falling with distance.

Output: paper/fig-ladder.pdf (+ .png for quick viewing). Requires matplotlib.
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


def rec(d, key):
    if d is None:
        return None
    v = d[key]["recall"]
    return v


def prec(d, key):
    if d is None:
        return None
    return d[key]["precision"]


def best_recall(zero, few, key):
    """Return (recall, precision) of the mode with the higher recall; ties -> higher precision."""
    cands = []
    for d in (zero, few):
        if d is None:
            continue
        r = rec(d, key)
        p = prec(d, key)
        cands.append((r if r is not None else -1.0, p if p is not None else 0.0))
    if not cands:
        return (0.0, 0.0)
    cands.sort(key=lambda t: (t[0], t[1]), reverse=True)
    r, p = cands[0]
    return (max(r, 0.0), p)


# Rung 1 (LSASS, holdout), Rung 2 (NTDS, overall), Rung 3 (injection, overall)
r1_3b = best_recall(load("llm-detection.json"), load("llm-fewshot-detection.json"), "holdout")
r1_8b = best_recall(load("llm-detection-8b.json"), load("llm-fewshot-detection-8b.json"), "holdout")
r2_3b = best_recall(load("llm-subtechnique-zeroshot.json"), load("llm-subtechnique-fewshot.json"), "overall")
r2_8b = best_recall(load("llm-subtechnique-zeroshot-8b.json"), load("llm-subtechnique-fewshot-8b.json"), "overall")
r3_3b = best_recall(load("llm-technique-zeroshot.json"), load("llm-technique-fewshot.json"), "overall")
r3_8b = best_recall(load("llm-technique-zeroshot-8b.json"), load("llm-technique-fewshot-8b.json"), "overall")

x = [1, 2, 3]
recall_3b = [r1_3b[0], r2_3b[0], r3_3b[0]]
recall_8b = [r1_8b[0], r2_8b[0], r3_8b[0]]
prec_8b = [r1_8b[1], r2_8b[1], r3_8b[1]]

print("3B recall:", recall_3b)
print("8B recall:", recall_8b)
print("8B prec  :", prec_8b)

fig, ax = plt.subplots(figsize=(6.4, 3.6))
ax.plot(x, recall_8b, "-o", color="#1b6ca8", lw=2.2, ms=7, label="llama3.1 8B — recall")
ax.plot(x, prec_8b, "-s", color="#d1495b", lw=2.2, ms=7, label="llama3.1 8B — precision")
ax.plot(x, recall_3b, "--^", color="#7a7a7a", lw=1.8, ms=7, label="llama3.2 3B — recall")

# annotate values
for xi, yi in zip(x, recall_8b):
    ax.annotate(f"{yi:.2f}", (xi, yi), textcoords="offset points", xytext=(0, 9),
                ha="center", color="#1b6ca8", fontsize=9)
for xi, yi in zip(x, prec_8b):
    ax.annotate(f"{yi:.2f}", (xi, yi), textcoords="offset points", xytext=(0, -15),
                ha="center", color="#d1495b", fontsize=9)
for xi, yi in zip(x, recall_3b):
    ax.annotate(f"{yi:.2f}", (xi, yi), textcoords="offset points", xytext=(10, -2),
                ha="left", color="#7a7a7a", fontsize=8)

ax.set_xticks(x)
ax.set_xticklabels(["Rung 1\nnew-instance", "Rung 2\nnew-subtechnique", "Rung 3\nnew-technique"])
ax.set_ylim(-0.05, 1.12)
ax.set_ylabel("score")
ax.set_title("Down the ladder: scale restores recall, precision pays the cost")
ax.grid(True, axis="y", ls=":", alpha=0.5)
ax.legend(loc="upper right", fontsize=9, framealpha=0.9)
fig.tight_layout()

OUT.mkdir(parents=True, exist_ok=True)
fig.savefig(OUT / "fig-ladder.pdf")
fig.savefig(OUT / "fig-ladder.png", dpi=150)
print(f"wrote {(OUT / 'fig-ladder.pdf').relative_to(REPO)} and .png")
