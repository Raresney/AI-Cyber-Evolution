# Results — S001 Vertical Slice

This directory holds experiment outputs and run records. The first working
pipeline is the **S001 PowerShell vertical slice**: it takes the project from
specification-only to an end-to-end run that produces reproducible metrics.

## What the slice does

One round of the CYBER-EVO pipeline, each stage decoupled through on-disk
JSONL (no shared imports between agent directories):

```
environment/generate_telemetry.py   ->  telemetry/events.jsonl        (Blue-visible)
                                         telemetry/ground-truth.jsonl  (evaluator-only)
                                         telemetry/dataset-manifest.json
blue-agent/baseline_blue.py          ->  results/blue-decisions.jsonl
                                         results/blue-config.json
evaluation/evaluate.py               ->  results/metrics.json
experiments/run_slice.py             ->  results/run-<timestamp>.json  (repro record)
                                         results/latest-run.json
```

This is experimental **condition A**: a fixed scenario set vs. a static,
deterministic baseline Blue. It gives the adaptive and co-evolution conditions
a reproducible floor to measure against, with zero model/API cost.

## How to run

```bash
python experiments/run_slice.py --seed 1337
```

Options: `--seed <int>`, `--n-cases <int>`, `--condition <label>`. Each run is
fully determined by its seed and is recorded in `results/run-<timestamp>.json`
(seed, agent version + config, schema version, splits, telemetry config, git
commit, timestamp, metric summary).

Stages can also be run individually; they communicate only through the JSONL
files above.

## Baseline result (seed 1337, 60 cases, 30 attack / 30 benign)

Strict scoring: only a `detect` decision counts as a positive; `investigate`
is a valid third outcome and is tallied separately.

| Slice        | Precision | Recall (detection) | FPR | F1   | investigate (atk/benign) |
| ------------ | --------: | -----------------: | --: | ---: | ------------------------ |
| Overall      |      1.00 |               0.27 | 0.0 | 0.42 | 34 (27 / 7)              |
| final_test   |      1.00 |               0.17 | 0.0 | 0.29 | 6 (5 / 1)                |

By telemetry condition:

| Condition | Recall | Precision | Notes                                            |
| --------- | -----: | --------: | ------------------------------------------------ |
| clean     |   0.40 |      1.00 | best observation quality                         |
| delayed   |   0.40 |      1.00 | outcome unaffected (latency not modelled in v1)  |
| missing   |   0.00 |  undefined | `command_line` nulled → main signal removed      |
| noisy     |   0.00 |  undefined | see small-n caveat below                         |

Label-leakage check: **pass** (Blue evidence references observed fields only).

## Interpretation

- The baseline is high-precision, zero-FP, but low-recall: it routes most
  attacks to `investigate` rather than firing `detect`. That triage load is a
  real operational cost and is reported, not hidden.
- **Missing** telemetry measurably suppresses detection (recall → 0) and pushes
  benign look-alikes into triage — direct evidence for hypothesis 4 (degraded
  observability hurts both teams).
- `undefined` precision under `missing`/`noisy` means zero positive
  predictions, reported as undefined rather than silently 0 (per the schema's
  metric rules).

## Known limitations (v1)

- Per-condition cells are small (n = 8–14), so condition effects are noisy; the
  `noisy` recall of 0.0 is largely a sampling artifact of which attacks drew
  that condition at this seed. Repeat across seeds / raise `--n-cases` for
  stable per-condition estimates (the design doc already requires repeated
  runs).
- Cases are pre-segmented by `case_id`; a later version should make Blue
  segment the raw stream by host/time window itself.
- Detection latency is not modelled (no decision-time), so the `delayed`
  condition is scored on outcome only.
- Single scenario (S001) and a static baseline Blue — Red adaptation, adaptive
  Blue, and additional techniques are the next increments.

## Next

1. Red agent that mutates S001 attacks (encoding, parent, timing) → enables
   conditions B/D and attack-variant generalization.
2. Adaptive Blue (threshold/rule learning on the adaptation split only).
3. Co-evolution loop over multiple rounds (the core research condition).
4. Add scenarios S002–S008 for true unseen-technique / unseen-chain tests.
5. LLM-backed Blue behind the same contract (local llama3.2 first).

---

# Co-Evolution — Conditions A–D

The co-evolution loop (`experiments/coevolution.py`) runs repeated Red/Blue
rounds over a **stable case pool** (`environment/case_pool.py`): each case's
identity, label and split are fixed for the whole experiment, but the Red agent
re-renders attack telemetry every round under its evolving strategy, so a
held-out case stays held out while the observations it produces change.

* **Red** (`red-agent/red_agent.py`) evades along two dimensions — spawn from a
  benign parent (kills Blue's parent signal) and use a freshly obfuscated
  signature Blue does not yet know. When adaptive, it reinforces whatever
  produced a clean `no_alert` and **mints a new obfuscation token** once its
  current one stops slipping past.
* **Blue** (`blue-agent/adaptive_blue.py`) scores `anomalous parent + known
  signature`; a strong IOC (explicit obfuscation marker, hard encoding) alone
  warrants `detect`, a dual-use flag only `investigate`. When adaptive, it
  learns signatures from confirmed attacks **in the adaptation split only** —
  never validation or final_test.

## How to run

```bash
python experiments/coevolution.py --all --rounds 12 --seed 1337   # one seed, 4 conditions
# or one condition: --condition D
python experiments/seed_sweep.py --seeds 20 --rounds 12           # mean +/- 95% CI
python experiments/plot_coevolution.py                            # figures (needs matplotlib)
```

Writes `results/coevolution-<cond>-<timestamp>.json` (full per-round series +
strategy snapshots), `results/coevolution-summary.json`, `results/seed-sweep.json`,
and figures under `results/plots/`.

## Result (seed 1337, 12 rounds, 60 attack / 60 benign)

Detection rate is strict (only `detect` counts); ASR = 1 − detection rate.

| Cond | Red / Blue        | Detection (r0 → r11) | ASR (r0 → r11) | Benign→investigate | Tokens minted |
| ---- | ----------------- | -------------------- | -------------- | ------------------ | ------------- |
| A    | static / static   | 0.45 → 0.65          | 0.55 → 0.35    | 0                  | 0             |
| B    | adaptive / static | 0.45 → **0.03**      | 0.55 → **0.97**| 0                  | 3             |
| C    | static / adaptive | 0.45 → **0.95**      | 0.55 → **0.05**| 10 / round         | 0             |
| D    | adaptive / adaptive | **oscillates 0.02 ⇄ 0.98** | **0.98 ⇄ 0.02** | 10 / round | 8             |

## Findings vs. the hypotheses

1. **Static defense degrades (H1).** Condition B: an adaptive attacker drives a
   fixed Blue to near-zero detection (ASR 0.97) within ~4 rounds by removing the
   parent signal and switching to an unknown obfuscation.
2. **Adaptive defense generalizes (H2).** Condition C: Blue learns the two
   signatures a fixed Red reuses and reaches 0.95 detection — including on the
   held-out final_test split (det_FT → 1.00), so it generalizes rather than
   memorizes.
3. **Adaptation has a cost (H3).** The moment adaptive Blue learns the dual-use
   `-ep_bypass` flag (C and D, round 1), 10 benign cases per round move into
   `investigate`. Precision stays 1.0 — the cost is **analyst triage load**, not
   false positives, because a dual-use indicator only raises suspicion.
4. **Co-evolution oscillates (the arms race, D).** Red mints a fresh token →
   detection crashes to ~0.02; Blue learns it the next round → detection spikes
   to ~0.98; Red mints again → crash. Blue's signature set climbs monotonically
   (4 → 14) while Red mints 8 tokens. Neither side converges; the system cycles.
   The held-out split tracks the same cycle, so generalization itself is only as
   durable as the time since Red's last mutation.

## Seed sweep (20 seeds, 12 rounds)

Single-seed numbers are anecdotes. The sweep (`experiments/seed_sweep.py`) runs
each condition over 20 seeds and reports mean ± 95% CI.

| Cond | Detection (mean, all rounds) | ASR (last round) | Oscillation swing | Tokens minted | Blue sigs |
| ---- | ---------------------------: | ---------------: | ----------------: | ------------: | --------: |
| A    | 0.60 ± 0.01                  | 0.40 ± 0.03      | 0.07 ± 0.01       | 0.0           | 4.0       |
| B    | 0.10 ± 0.01                  | 0.97 ± 0.01      | 0.07 ± 0.00       | 2.2           | 4.0       |
| C    | 0.87 ± 0.01                  | 0.11 ± 0.02      | 0.07 ± 0.01       | 0.0           | 6.0       |
| D    | 0.40 ± 0.02                  | 0.44 ± **0.21**  | **0.52 ± 0.03**   | 8.0           | 13.5      |

The **oscillation swing** (mean absolute round-to-round change in detection)
isolates the arms race: A, B and C sit at ~0.07 (monotone or flat), while D is
**0.52 — about 7× higher**. D's last-round ASR has a wide CI (± 0.21) precisely
because the endpoint lands on a random phase of the oscillation — that variance
*is* the result, not noise to average away.

## Figures

![Condition D arms race](plots/coevolution-D-arms-race.png)

*Condition D, one seed: strict detection (purple) crashes each time Red mints a
fresh obfuscation token (red lines) and spikes when Blue learns it; Blue's known
signatures (teal) ratchet up monotonically. The held-out split tracks the cycle.*

![Detection by condition with CI](plots/coevolution-conditions-sweep.png)

*All four conditions, mean ± 95% CI over 20 seeds. A/B/C converge with tight
bands; D's wide band is the oscillation variance.*

## Known limitations (co-evolution v1)

- Deterministic parametric agents, not LLMs — the strategy space is two evasion
  dials plus token minting. It is enough to produce the dynamics above; an
  LLM-backed Red/Blue behind the same contract is the next step.
- Single scenario (S001) and a single ambiguous indicator. More techniques and
  indicators would let FPR (not just triage load) move.
- Oscillation period is ~1 round because learning and minting are both
  single-step; richer memory/forgetting would change the cycle shape.
- The sweep covers 20 seeds at one pool size / round count; a fuller study would
  also vary pool size, round count and learning rate.
