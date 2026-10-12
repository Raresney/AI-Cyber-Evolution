# Telemetry Schema — S001: PowerShell

## 1. Purpose

This document defines the first telemetry contract for the AI Cyber Evolution research project. It describes what the Blue agent can observe in the S001 PowerShell scenario and separates observable telemetry from evaluator-only ground truth.

The initial events are synthetic. They are intended for a controlled, authorized research environment and do not require executing real attack commands.

## 2. Design principles

1. **No label leakage:** the Blue agent must not receive the scenario ID, ground-truth technique ID, or the evaluator's expected answer as part of telemetry.
2. **Observable evidence only:** telemetry should represent events or fields that a defensive sensor could plausibly collect.
3. **Reproducibility:** events should use a consistent schema and stable field meanings.
4. **Degradation must be explicit:** missing, noisy, or delayed telemetry should be introduced as controlled experimental conditions.
5. **Keep ground truth separate:** the evaluator stores labels independently and joins them to outcomes only after the Blue agent has made its decision.

## 3. Initial telemetry event schema

| Field               | Type            | Required initially | Meaning                                                       |
| ------------------- | --------------- | -----------------: | ------------------------------------------------------------- |
| `timestamp`         | ISO 8601 string |                Yes | Time the event occurred or was recorded; document which       |
| `host`              | string          |                Yes | Host that generated the event                                 |
| `user`              | string          |                Yes | Account associated with the event                             |
| `process`           | string          |                Yes | Process image/name                                            |
| `parent_process`    | string          |                Yes | Parent process image/name                                     |
| `process_id`        | integer         |        Recommended | Process identifier                                            |
| `parent_process_id` | integer         |        Recommended | Parent process identifier                                     |
| `command_line`      | string or null  |                Yes | Command line if collected; may be null in degraded conditions |
| `integrity_level`   | string or null  |        Recommended | Process integrity context when available                      |
| `event_source`      | string          |                Yes | Sensor or source that produced the event                      |

**Important:** a required field in the schema may still be `null` in a deliberately degraded experiment. The dataset must record whether the null was natural or introduced by the experiment.

## 4. Example telemetry event

This is a synthetic example, not a claim that a real endpoint generated the event.

```json
{
  "timestamp": "2026-10-13T10:31:42Z",
  "host": "WIN-01",
  "user": "alice",
  "process": "powershell.exe",
  "parent_process": "explorer.exe",
  "process_id": 4120,
  "parent_process_id": 1840,
  "command_line": "powershell.exe -Command <benign_test>",
  "integrity_level": "Medium",
  "event_source": "synthetic_process_telemetry"
}
```

The command line is deliberately a placeholder. Do not treat the example as a real malicious command.

## 5. Keep telemetry and ground truth separate

### Blue-visible telemetry

The Blue agent receives only the event fields defined in the telemetry schema, plus any additional observations explicitly allowed by the experiment.

### Evaluator-only ground truth

The evaluator maintains labels outside the Blue agent's input:

| Field                 | Meaning                                                               |
| --------------------- | --------------------------------------------------------------------- |
| `scenario_id`         | Stable scenario identifier, e.g. `S001-A`                             |
| `technique_id`        | Ground-truth ATT&CK technique label, where applicable                 |
| `attack_present`      | Whether the scenario contains the behavior under evaluation           |
| `expected_detection`  | Whether the behavior should be detected under the experiment's rubric |
| `expected_response`   | Expected response category, if response is being evaluated            |
| `telemetry_condition` | Clean, noisy, missing, or delayed                                     |
| `split`               | Adaptation, validation, or final test                                 |

Do not include these evaluator-only fields in telemetry sent to Blue. The evaluator may use them after the decision to score the result.

## 6. Benign and suspicious examples

The process name alone is not sufficient evidence to classify an event.

### Example A — benign administrative activity

```json
{
  "timestamp": "2026-10-13T10:31:42Z",
  "host": "WIN-01",
  "user": "alice",
  "process": "powershell.exe",
  "parent_process": "explorer.exe",
  "process_id": 4120,
  "parent_process_id": 1840,
  "command_line": "<benign administrative action>",
  "integrity_level": "Medium",
  "event_source": "synthetic_process_telemetry"
}
```

### Example B — activity requiring investigation

```json
{
  "timestamp": "2026-10-13T10:32:05Z",
  "host": "WIN-01",
  "user": "alice",
  "process": "powershell.exe",
  "parent_process": "winword.exe",
  "process_id": 4196,
  "parent_process_id": 2332,
  "command_line": "<synthetic suspicious behavior>",
  "integrity_level": "Medium",
  "event_source": "synthetic_process_telemetry"
}
```

These are illustrative examples only. Parent process and command line provide context, but no single field should automatically determine the verdict. Blue should use the available evidence and be allowed to return an uncertain or investigate decision.

## 7. Initial telemetry conditions

| Condition | Change                                                                | Research question                                               |
| --------- | --------------------------------------------------------------------- | --------------------------------------------------------------- |
| `clean`   | All available fields are provided; no added irrelevant events         | How well does Blue perform with complete observations?          |
| `missing` | A predefined field, such as `command_line`, is removed or set to null | Does performance degrade when key evidence is absent?           |
| `noisy`   | Benign, irrelevant events are added to the event stream               | Does Blue produce more false positives or miss relevant events? |
| `delayed` | Events are delivered after a controlled delay                         | How does delay affect detection and response time?              |

Apply one controlled change at a time when isolating its effect. If multiple degradations are combined, document the combination as a separate condition.

## 8. Blue agent output contract

For each evaluated case, Blue should return a structured decision similar to:

```json
{
  "decision": "detect | no_alert | investigate",
  "technique_hypothesis": "T1059.001 or unknown",
  "confidence": 0.0,
  "evidence": ["parent process context", "command-line context"],
  "recommended_response": "investigate | contain | no_action"
}
```

This is a proposed interface, not a final model implementation. Define the allowed values and scoring rubric before running experiments. The `evidence` field should reference observed fields or events, not hidden ground-truth labels.

## 9. Initial evaluation

Compare Blue's output with evaluator-only ground truth after each decision.

Track at minimum:

- True positives (TP)
- False positives (FP)
- True negatives (TN)
- False negatives (FN)
- Precision
- Recall / detection rate
- False-positive rate
- Detection latency, when timestamps make it measurable
- Performance on known versus held-out scenarios

Use consistent metric definitions. For example:

- `Precision = TP / (TP + FP)`
- `Recall = TP / (TP + FN)`
- `False Positive Rate = FP / (FP + TN)`

If a denominator is zero, report the metric as undefined for that run rather than silently substituting zero.

A higher detection rate alone does not establish a better defense. Interpret it alongside false positives, response quality, latency, and performance on held-out scenarios.

## 10. Dataset and reproducibility requirements

For each event/scenario, record:

- stable scenario and event identifiers;
- telemetry schema version;
- scenario split (`adaptation`, `validation`, or `final_test`);
- telemetry condition and exact degradation applied;
- random seed, where randomness is used;
- Blue agent/model version and configuration;
- decision output and evaluator score;
- timestamp convention and any simulated delay.

Keep the final test set held out from adaptation and tuning. Do not use final-test outcomes to change the system and then report those same outcomes as an unbiased final evaluation.

## 11. Safety boundaries

- Use synthetic events or an isolated, explicitly authorized lab.
- Do not run credential dumping, persistence, or other real attack actions on production systems.
- Keep simulation labels and evaluator metadata separate from Blue-visible telemetry.
- Document any real telemetry source and obtain authorization before collecting it.

## 12. Next step

Implement a small synthetic event dataset for S001 with both benign and suspicious examples. Validate the schema and the separation between telemetry and ground truth before implementing the Blue agent.
