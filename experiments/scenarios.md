ATT&CK Scenario Specification

Purpose

Initial scenario specification for CYBER-EVO. The first scenario set is intentionally
small and representative so the methodology can be validated before scaling the
dataset.

Selected Techniques

ID

Technique

Tactic

Experimental role

T1059.001

PowerShell

Execution

Execution baseline and variation

T1059.003

Windows Command Shell

Execution

Cross-sub-technique generalization

T1087.001

Account Discovery: Local Account

Discovery

Discovery behavior

T1049

System Network Connections Discovery

Discovery

Network-related telemetry

T1003.001

OS Credential Dumping: LSASS Memory

Credential Access

Credential-access baseline

T1003.003

OS Credential Dumping: NTDS

Credential Access

Unseen sibling sub-technique

T1047

Windows Management Instrumentation

Execution

Alternate execution mechanism

T1053.005

Scheduled Task/Job: Scheduled Task

Execution / Persistence / Privilege Escalation

Persistence and temporal behavior

MITRE ATT&CK currently documents these techniques/sub-techniques and their
associated tactics. The exact ATT&CK version used for a formal experiment must
be pinned and recorded.

Scenario S001 — PowerShell

ATT&CK ID: T1059.001

Role: known execution technique

Red objective: perform a controlled PowerShell-based action in the lab

Blue objective: identify suspicious PowerShell execution from telemetry

Expected telemetry: process creation, PowerShell/script telemetry, parent-child
process relationships, command-line information

Generalization role: known technique and new-instance testing

Scenario S002 — Windows Command Shell

ATT&CK ID: T1059.003

Role: related execution technique

Red objective: perform a controlled command-shell action in the lab

Blue objective: identify suspicious command-shell execution

Expected telemetry: process creation, command-line information, parent-child
relationships, EDR observations

Generalization role: compare with the PowerShell sub-technique family

Scenario S003 — Local Account Discovery

ATT&CK ID: T1087.001

Role: discovery behavior

Red objective: enumerate local accounts in the controlled environment

Blue objective: identify account-enumeration behavior

Expected telemetry: process/command execution and endpoint observations

Generalization role: known discovery behavior and new-instance testing

Scenario S004 — System Network Connections Discovery

ATT&CK ID: T1049

Role: network-related discovery

Red objective: enumerate local network connections in the controlled environment

Blue objective: identify network-connection discovery behavior

Expected telemetry: process/command execution and relevant network/endpoint
observations

Generalization role: discovery behavior with different telemetry characteristics

Scenario S005 — LSASS Memory

ATT&CK ID: T1003.001

Role: credential-access baseline

Red objective: perform a controlled credential-access simulation

Blue objective: identify suspicious access to LSASS-related credential material

Expected telemetry: endpoint process/access observations and EDR telemetry

Generalization role: known credential-access behavior

Scenario S006 — NTDS

ATT&CK ID: T1003.003

Role: unseen sibling sub-technique

Red objective: perform a controlled NTDS-related credential-access simulation

Blue objective: identify suspicious access to the Active Directory database

Expected telemetry: file/access observations, process activity, and relevant
endpoint telemetry

Generalization role: unseen sub-technique within the T1003 family

Scenario S007 — Windows Management Instrumentation

ATT&CK ID: T1047

Role: alternate execution mechanism

Red objective: perform a controlled WMI action in the lab

Blue objective: identify suspicious WMI-based execution

Expected telemetry: process creation, command execution, WMI-related activity,
and network observations when applicable

Generalization role: unseen execution mechanism

Scenario S008 — Scheduled Task

ATT&CK ID: T1053.005

Role: persistence and temporal behavior

Red objective: create a controlled scheduled task that performs a benign lab action

Blue objective: identify suspicious scheduled-task creation or execution

Expected telemetry: scheduled-task activity, process creation, and related endpoint
observations

Generalization role: unseen persistence behavior

Initial Generalization Design

The first dataset should support at least these categories:

Known technique — same ATT&CK technique, different instance.

New instance — same technique, different scenario characteristics.

New sub-technique — e.g. T1003.003 after adaptation involving T1003.001.

New technique — technique not present during adaptation.

New attack chain — previously unseen ordering/combination of known techniques.

Telemetry Design

Blue must not receive the ATT&CK label directly. The environment should expose
controlled observations from which Blue must infer suspicious behavior.

Telemetry conditions will later include:

Clean

Noisy

Incomplete

Delayed

Conflicting

Evaluation

Each scenario should record:

Detection outcome

False positive outcome

Detection time

Investigation accuracy

Response outcome

Technique coverage

Generalization category

Results must retain individual metrics; a single combined score must not replace
the underlying measurements.

Safety

All scenarios are intended for isolated, authorized laboratory environments.
Actions should be controlled and benign where possible. The agents must not have
unrestricted access to external systems.
