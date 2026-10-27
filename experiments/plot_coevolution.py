#!/usr/bin/env python3
"""Plots for the CYBER-EVO co-evolution results.

Reads the JSON that the loop and the seed sweep write, and renders two figures
into ``results/plots/``:

* ``coevolution-D-arms-race.png`` -- the condition-D arms race from a single
  seed: strict detection rate oscillating as Red mints fresh obfuscation, with
  Blue's accumulating signature knowledge on a second axis and mint rounds
  marked.
* ``coevolution-conditions-sweep.png`` -- mean detection rate per round with
  95% CI bands for all four conditions, from the seed sweep.

Plotting is the one part of the project that needs third-party packages
(matplotlib); the simulation engine and the seed sweep are stdlib-only. See
``requirements.txt``.
"""
from __future__ import annotations

import glob
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = REPO_ROOT / "results"
PLOTS_DIR = RESULTS_DIR / "plots"

COND_COLORS = {"A": "#6b7280", "B": "#dc2626", "C": "#2563eb", "D": "#7c3aed"}
COND_LABEL = {
    "A": "A static / static",
    "B": "B adaptive Red / static Blue",
    "C": "C static Red / adaptive Blue",
    "D": "D adaptive / adaptive",
}


def _latest(pattern: str) -> Path | None:
    files = sorted(glob.glob(str(RESULTS_DIR / pattern)))
    return Path(files[-1]) if files else None


def plot_arms_race() -> Path | None:
    src = _latest("coevolution-D-*.json")
    if not src:
        print("  (no coevolution-D-*.json; run coevolution.py --condition D first)")
        return None
    data = json.loads(src.read_text(encoding="utf-8"))
    series = data["series"]
    rounds = [s["round"] for s in series]
    det = [s["overall"]["detection_rate"] for s in series]
    ft = [s["final_test"]["detection_rate"] for s in series]
    sigs = [s["blue_knowledge"]["known_signature_count"] for s in series]
    mints = [s["round"] for s in series if s["red_adapt"]["minted_this_round"]]

    fig, ax1 = plt.subplots(figsize=(9, 5))
    ax1.plot(rounds, det, "-o", color=COND_COLORS["D"], lw=2,
             label="detection rate (all cases)")
    ax1.plot(rounds, ft, "--s", color="#a78bfa", lw=1.5, ms=4,
             label="detection rate (held-out final_test)")
    for i, m in enumerate(mints):
        ax1.axvline(m, color="#dc2626", ls=":", alpha=0.6,
                    label="Red mints new token" if i == 0 else None)
    ax1.set_xlabel("round")
    ax1.set_ylabel("detection rate (strict: 'detect')")
    ax1.set_ylim(-0.03, 1.05)
    ax1.set_xticks(rounds)
    ax1.grid(True, alpha=0.3)

    ax2 = ax1.twinx()
    ax2.step(rounds, sigs, where="post", color="#0d9488", lw=1.5, alpha=0.8,
             label="Blue known signatures")
    ax2.set_ylabel("Blue known signatures", color="#0d9488")
    ax2.tick_params(axis="y", labelcolor="#0d9488")
    ax2.set_ylim(0, max(sigs) + 2)

    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc="upper left", fontsize=8)
    ax1.set_title(f"CYBER-EVO condition D arms race (seed {data['seed']})\n"
                  "Red mints obfuscation, detection crashes; Blue learns it, detection spikes")
    fig.tight_layout()
    PLOTS_DIR.mkdir(parents=True, exist_ok=True)
    out = PLOTS_DIR / "coevolution-D-arms-race.png"
    fig.savefig(out, dpi=140)
    plt.close(fig)
    return out


def plot_conditions_sweep() -> Path | None:
    src = RESULTS_DIR / "seed-sweep.json"
    if not src.exists():
        print("  (no seed-sweep.json; run seed_sweep.py first)")
        return None
    data = json.loads(src.read_text(encoding="utf-8"))
    n = data["n_seeds"]

    fig, ax = plt.subplots(figsize=(9, 5))
    for cond, block in data["conditions"].items():
        pr = block["per_round"]
        rounds = [p["round"] for p in pr]
        mean = [p["detection_rate"]["mean"] for p in pr]
        ci = [p["detection_rate"]["ci95"] or 0 for p in pr]
        lo = [m - c for m, c in zip(mean, ci)]
        hi = [m + c for m, c in zip(mean, ci)]
        color = COND_COLORS.get(cond, "#333")
        ax.plot(rounds, mean, "-o", color=color, lw=2, ms=4, label=COND_LABEL.get(cond, cond))
        ax.fill_between(rounds, lo, hi, color=color, alpha=0.15)

    ax.set_xlabel("round")
    ax.set_ylabel("detection rate (mean, strict)")
    ax.set_ylim(-0.03, 1.05)
    ax.set_xticks(rounds)
    ax.grid(True, alpha=0.3)
    ax.legend(loc="center right", fontsize=8)
    ax.set_title(f"CYBER-EVO detection rate by condition "
                 f"(mean +/- 95% CI, {n} seeds)")
    fig.tight_layout()
    PLOTS_DIR.mkdir(parents=True, exist_ok=True)
    out = PLOTS_DIR / "coevolution-conditions-sweep.png"
    fig.savefig(out, dpi=140)
    plt.close(fig)
    return out


def main() -> None:
    print("[plot_coevolution] rendering figures")
    for fn in (plot_arms_race, plot_conditions_sweep):
        out = fn()
        if out:
            print(f"  wrote {out.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
