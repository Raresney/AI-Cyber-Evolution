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

---

# Real-Data Detection — LSASS new-instance generalization (T1003.001)

This moves the project off self-written telemetry onto real host telemetry and
asks the question that motivates the whole thesis on real data: **does a
detector that works on known attack procedures generalize to unseen procedures
of the same technique?**

## Setup

- **Data:** Open Threat Research Forge Security-Datasets (MIT). The seven
  `LSASS_campaign_0X` datasets each run *one tool* for OS Credential Dumping:
  LSASS Memory (T1003.001) — mimikatz, procdump, comsvcs, out-minidump,
  sharpdump, outflank-dumpert, nanodump. **354,229 real Windows/Sysmon events.**
- **Ingest:** `environment/otrf_loader.py` → leakage-free contract
  (detector-visible `events.jsonl` + evaluator-only `labels.jsonl`). Ground
  truth is a documented derived rule (Sysmon EID10 ProcessAccess to lsass.exe
  with a memory-read mask from a non-system source).
- **Split (new-instance):** train on procedures 01–03, hold out 04–07 — unseen
  tools of the *same* technique.
- **Detectors:** `experiments/lsass_detectors.py` (signature, behavioral),
  `experiments/llm_detector.py` (local llama3.2 via Ollama, zero-shot),
  `experiments/llm_fewshot_detector.py` (same model, few-shot: labeled train
  exemplars in context, excluded from the train eval).

## Result — held-out (unseen) procedures

| Detector | Approach | Holdout recall | Holdout precision |
| --- | --- | ---: | ---: |
| signature | learns malicious tool image names from training | **0.29** | 1.00 |
| behavioral | technique invariant (non-system proc reads lsass w/ VM_READ) | **1.00** | 1.00 |
| llm (zero-shot) | llama3.2 3B judges each access event | 0.57 | 1.00 |
| llm (few-shot, 3+3) | same model, 6 labeled train exemplars in context | 0.71 | 1.00 |

Per-procedure recall (01–03 train, 04–07 holdout):

| | 01 | 02 | 03 | 04 | 05 | 06 | 07 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| signature | 1.0 | 1.0 | 1.0 | 1.0 | **0.0** | **0.0** | **0.0** |
| behavioral | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| llm (zero-shot) | 1.0 | **0.0** | 0.5 | 1.0 | **0.0** | 0.5 | 1.0 |
| llm (few-shot) | –¹ | **0.0** | **0.0** | 1.0 | 0.5 | 1.0 | **0.0** |

¹ few-shot exemplars are drawn from the training procedures and excluded from
the training eval, so `campaign_01`'s only remaining attack events became
exemplars (no train-01 events left to score). Train recall is therefore
measured on 02/03 alone, where it is **0.00** (see finding 5).

## Findings

1. **Signature detection memorizes, it does not generalize.** Recall falls from
   1.00 to **0.29** on unseen tools — it catches only `campaign_04`, which
   reuses a training payload (`winx64_payload.exe`), and misses
   sharpdump/dumpert/nanodump entirely. It also pays a precision cost on
   training (0.50): it learned `rundll32.exe` — a LOLBin that legitimately
   accesses lsass — as an IOC, producing false positives.
2. **The technique invariant generalizes.** The behavioral detector holds at
   1.00 / 1.00 across all unseen tools. (Honest caveat: this rule encodes the
   same invariant used to derive ground truth, so its high recall is partly by
   construction; the scientific weight is on the signature collapse.)
3. **A small zero-shot LLM is unreliable — and fails in a mixed way.** llama3.2
   (3B) reaches only ~0.46 recall overall and is inconsistent: it **missed
   procdump at GrantedAccess `0x1fffff`** — the most blatant case — yet caught
   the obscure nanodump. It also produced a name-bias false positive (flagged a
   benign `0x1400` query because the image was named `winx64_payload`). So it
   neither reasons reliably on the access mask nor purely memorizes tool fame.
4. **A ten-line behavioral rule beats the 3B LLM here.** This tempers the "LLMs
   solve detection" framing and sets a concrete bar for the LLM experiments.
5. **Few-shot raises recall but does *not* teach the invariant.** Given six
   labeled training exemplars (3 dumps + 3 benign), holdout recall rises
   0.57 → **0.71** and precision stays 1.00 — on the face of it, in-context
   examples help. But the *error pattern* shows why they do not help where it
   matters. The model still catches unseen tools with *suspicious-looking
   names* (`winx64_payload`, `outflank-dumpert`) and still **misses the
   dangerous cases**: it judged `procdump.exe`/`procdump64.exe` at full access
   `0x1fffff` benign *even though it was shown procdump dumps as malicious
   exemplars*, missed the `rundll32.exe`+comsvcs LOLBin (`0x1410`), and missed
   stealthy `nanodump` (`0x1010`). Train recall on the non-exemplar seen tools
   (02/03) is **0.00** for exactly this reason: those are the legit-binary /
   LOLBin cases, and the model's prior ("procdump and rundll32 are legitimate
   signed tools") overrides the in-context examples. The few-shot gains are
   *name semantics*, not technique reasoning — so the LLM fails precisely on
   living-off-the-land abuse and low-footprint tooling, which is where real
   adversaries operate and where the behavioral invariant still holds 1.00.

## Honest caveats

- Few-shot now has a real train/holdout meaning (exemplars from training
  procedures, excluded from the training eval). The result is reported above;
  the headline is that few-shot improves raw recall without fixing the failure
  mode (finding 5).
- Only 13 attack events total (a dump is a handful of events), so recall is
  coarse; precision/FPR for the LLM are on a benign subsample.
- llama3.2 3B is small; a larger model may well do better — this is a result
  about *this* model, not "LLMs in general".
- Ground truth is a derived rule, not hand annotation; mild label noise possible.

# Ladder rung 2 — new-subtechnique (T1003.001 LSASS → T1003.003 NTDS)

The new-instance rung above changed the *tool* and kept the sub-technique. This
rung changes the **sub-technique**: train/exemplify everything on LSASS memory
dumping (T1003.001) and test on NTDS — stealing the Active Directory database
`ntds.dit` (T1003.003) — a different footprint of the *same* technique family
(OS Credential Dumping). The question: does anything that worked on LSASS carry
over to a sibling sub-technique it never saw?

## Setup

- **Data:** three OTRF atomic datasets, one tool each — `ntdsutil` (IFM
  snapshot), `volume_shadow_copy` (vssadmin + copy off the shadow), `ninjacopy`
  (Empire Invoke-NinjaCopy). **41,996 real Windows/Sysmon/Security events, 14
  attack events.**
- **Ingest:** `environment/ntds_loader.py` → same leakage-free contract. Ground
  truth: a Sysmon FileCreate(11) or Security object-access(4663) whose path
  basename is `ntds*.dit`, from a process other than `lsass.exe` (the legit DC
  directory-service owner).
- **Detectors:** the LSASS-trained signature + behavioral detectors, evaluated
  **unchanged** on NTDS (`experiments/ladder_subtechnique.py`); the LLM asked a
  **general** T1003 question (not LSASS-specific) on the NTDS surface, zero-shot
  and few-shot with LSASS exemplars (`experiments/llm_subtechnique_detector.py`).

## Result — transfer to the unseen sub-technique

| Detector | Trained / exemplified on | NTDS recall | NTDS precision |
| --- | --- | ---: | ---: |
| signature | LSASS tool names | **0.00** | n/a |
| behavioral (LSASS invariant) | LSASS EID10+VM_READ | **0.00** | n/a |
| llm (zero-shot, general T1003) | pretraining | 0.07 | 0.25 |
| llm (few-shot, general T1003) | LSASS exemplars | 0.07 | 1.00 |
| behavioral (NTDS invariant) | — *(separate, surface-matched rule)* | 1.00 | 1.00 |

## Findings

6. **The invariant that generalized across tools does NOT generalize across
   sub-techniques.** The behavioral detector that held 1.00 on every unseen
   LSASS tool scores **0.00** on NTDS — it is bound to the LSASS *surface*
   (EID10 ProcessAccess to lsass.exe with a memory-read mask), and NTDS leaves a
   file-copy footprint instead. The signature detector likewise scores 0.00.
   Generalization across instances is real but **surface-local**: it buys
   nothing across the sub-technique boundary. Only a *separate*, NTDS-matched
   invariant recovers detection (1.00) — i.e. each sub-technique needs its own
   rule.
7. **The LLM does not transfer either — and leans on lexical cues.** Given a
   general "is this OS Credential Dumping (T1003)?" prompt, llama3.2 reaches only
   **0.07** recall on NTDS. Its single catch is the one event whose path is
   literally `...\ntds.dit` being *created* (Sysmon EID11); it misses every
   Security-log object-access (4663) read of `ntds.dit` off a shadow copy, and
   misses VSS and NinjaCopy entirely. Few-shot LSASS exemplars change nothing on
   recall (still 0.07) and only clean up false positives (precision 0.25 → 1.00).
   So semantic reasoning keys on the surface string, not the technique — it does
   not connect a raw access handle on `ntds.dit` to credential theft.
8. **No approach dominates the ladder.** New-instance rewards the behavioral
   invariant; new-subtechnique punishes it (surface lock-in) and the LLM alike.
   The honest takeaway is that **detection generalization is bounded by the
   telemetry surface**: invariants transfer across tools within a surface,
   nothing here transfers across surfaces, and a small LLM substitutes lexical
   recognition for technique reasoning at both rungs. This is the paper's spine —
   a measured map of *where* each approach's generalization ends.

## Honest caveats (rung 2)

- Both NTDS invariants (the ground-truth rule and the NTDS-specific detector)
  encode the same observable, so the 1.00 is by construction; the weight is on
  the **0.00 transfer** of the LSASS detectors and the **0.07** LLM, which are
  not by construction.
- 14 attack events; recall is coarse. The LLM's NTDS precision is on a benign
  subsample of same-type file/object events.
- NTDS datasets are OTRF *atomic* (single-technique) captures, so there is no
  train split within NTDS — the whole sub-technique is held out, which is the
  point of the rung.

## Next

1. ~~Few-shot LLM — invariant or memorize?~~ **Done** (finding 5): name
   semantics, not the invariant. `experiments/llm_fewshot_detector.py`.
2. ~~Extend the ladder to a new sub-technique (T1003.003 NTDS).~~ **Done**
   (findings 6–8): nothing trained on LSASS transfers;
   `experiments/ladder_subtechnique.py`, `llm_subtechnique_detector.py`.
3. Larger / tool-calling LLM — does scale fix the LOLBin/stealth blind spot
   (rung 1) and the cross-surface lexical lock-in (rung 2), or persist them?
4. Next rungs: new-*technique* (e.g. T1055 injection), multi-step chains (OTRF
   `apt29`, `Log4Shell`) — does the ladder keep punishing surface-bound rules?
5. Cross-dataset test on Windows-APT 2025 (CC BY) — real unseen environment.
6. Add the adaptive adversary: a Red that mutates the tool/access to evade a
   signature Blue that keeps learning names — the co-evolution arms race on real
   telemetry.
