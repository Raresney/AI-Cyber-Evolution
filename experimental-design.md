Experimental Design



Purpose



This document defines the initial experimental methodology for CYBER-EVO.

The goal is to evaluate whether continuous adaptation between AI Red and Blue

Teams improves defensive robustness and generalization.



Core Research Question



How does adaptive interaction between autonomous AI Red and Blue Teams affect

attack success, defensive generalization, and detection robustness under

incomplete, noisy, or delayed telemetry?



Experimental Variables



Independent Variables



Red adaptation: static or adaptive



Blue adaptation: static or adaptive



Telemetry quality: clean, noisy, incomplete, delayed



Attack novelty: known, new instance, new sub-technique, new technique,

and new attack chain



Dependent Variables



Detection rate



False positive rate



Unseen attack detection rate



Mean time to detection (MTTD)



Mean time to containment (MTTC)



Technique coverage



Investigation accuracy



Response quality



Operational cost



Experimental Conditions



Condition



Red



Blue



Purpose



A



Static



Static



Baseline



B



Adaptive



Static



Measure impact of adaptive Red



C



Static



Adaptive



Measure impact of adaptive Blue



D



Adaptive



Adaptive



Main co-evolution condition



E



Adaptive



Adaptive



Evaluate degraded telemetry



Dataset Separation



The experiment must separate adaptation data from evaluation data.



Adaptation set: scenarios available during interaction and learning



Validation set: used to check whether changes are improving performance



Final test set: held out until the end and never used for adaptation



A possible initial split is:



60% adaptation



20% validation



20% final test



The final split should be adjusted after the scenario dataset is defined.



Generalization Levels



Known technique: the same technique appears in adaptation and testing.



New instance: the same technique is used in a different scenario.



New sub-technique: a related but unseen sub-technique is tested.



New technique: the technique was not present during adaptation.



New attack chain: known techniques appear in a previously unseen sequence.



Telemetry Conditions



Clean telemetry: complete and timely events



Noisy telemetry: irrelevant events are added



Incomplete telemetry: some relevant events are missing



Delayed telemetry: events arrive after a defined delay



Conflicting telemetry: sources contain inconsistent observations



Evaluation Principles



Detection rate must not be evaluated in isolation. Every experiment should

also report false positives, generalization, detection speed, response quality,

and operational cost.



Individual metrics must be retained even if a combined score is later used.

A combined score must not hide important trade-offs.



Reproducibility Requirements



Each run should record:



Random seed



Model and model version



Agent configuration



Environment version



Scenario identifiers



Telemetry configuration



Adaptation settings



Evaluation version



Timestamp



Experiments should be repeated multiple times to measure variability.



Safety Constraints



All experiments must run in an isolated, authorized environment using

synthetic data, public datasets, or explicitly permitted laboratory systems.

Agents must use controlled action spaces and must not receive unrestricted

access to external systems.

