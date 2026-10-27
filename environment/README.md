# environment/

The controlled environment: it defines scenarios and produces the security
telemetry the Blue agent observes. Nothing here executes a real command — all
telemetry is synthetic.

* `generate_telemetry.py` — one-shot synthetic dataset for the S001 slice
  (`telemetry/events.jsonl` + `telemetry/ground-truth.jsonl`), with splits and
  degraded-telemetry conditions. See `results/README.md` ("S001 Vertical Slice").
* `case_pool.py` — the **stable case pool** used by the co-evolution loop:
  fixed case identity / label / split, shared parent + signature vocabulary, and
  `tokenize_signatures()` shared by Red (emits) and Blue (learns). Benign cases
  are rendered here and held fixed; attacks are rendered per round by the Red
  agent.
