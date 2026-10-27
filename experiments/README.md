# experiments/

Runners that wire the environment, agents and evaluator into reproducible
experiments.

* `run_slice.py` — the S001 vertical slice end to end (generate → baseline Blue
  → evaluate) with a reproducibility record. Condition A baseline.
* `coevolution.py` — the repeated Red/Blue loop for conditions **A–D**
  (static/adaptive on each side), with per-round metrics, strategy snapshots and
  held-out generalization. `--all --rounds 12 --seed 1337`.

Specs in this directory: `scenario-selection-criteria.md`, `scenarios.md`.
Results and findings: `results/README.md`.

```bash
python experiments/run_slice.py --seed 1337
python experiments/coevolution.py --all --rounds 12 --seed 1337
```
