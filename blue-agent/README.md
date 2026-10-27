# blue-agent/

The AI Blue Team: consumes telemetry (never labels) and returns a structured
decision per case — `detect` / `investigate` / `no_alert`, with a technique
hypothesis, confidence, evidence, and a recommended response.

* `baseline_blue.py` — static heuristic Blue for the S001 slice (substring-token
  model). Deterministic, no model/API cost; the condition-A detection floor.
* `adaptive_blue.py` — `AdaptiveBlue` for the co-evolution loop
  (signature-token model). Strong IOCs alone warrant `detect`, dual-use flags
  only `investigate`. Adaptive mode learns signatures from confirmed attacks in
  the **adaptation split only**, never validation or final_test.

Evaluated on detection effectiveness and operational cost. See
`results/README.md`.
