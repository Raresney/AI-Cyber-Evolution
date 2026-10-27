# evaluation/

Scores Blue decisions against evaluator-only ground truth, joined by
`case_id` after the decision is made.

* `evaluate.py` — confusion matrix (strict: only `detect` is a positive;
  `investigate` tallied separately), precision, recall / detection rate, FPR and
  F1, with **undefined (not zero)** on a zero denominator. Breaks results down by
  split, telemetry condition and generalization category, and runs a
  label-leakage guard on Blue's evidence. `confusion()` is reused per round by
  the co-evolution loop.

Principle: detection rate is never read alone — always with precision, FPR and
the held-out split. See `results/README.md`.
