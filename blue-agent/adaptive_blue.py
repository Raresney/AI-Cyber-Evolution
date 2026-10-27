#!/usr/bin/env python3
"""Adaptive Blue agent for CYBER-EVO co-evolution.

Same decision contract as the static baseline, but with a *mutable* set of
known signatures. In adaptive mode it learns new signatures from confirmed
attacks in the adaptation split only -- never from validation or final_test,
so held-out generalization stays honest.

Scoring (signature-token model, see ``environment/case_pool.py``):

    score = (anomalous parent ? 1 : 0)
          + (command line carries a *known* signature ? 1 : 0)

    score >= 2 -> detect       (contain)
    score == 1 -> investigate  (investigate)
    score == 0 -> no_alert     (no_action)
    missing command_line with score < 2 -> investigate (incomplete evidence)

Adaptation closes the gap Red opens: once Blue has seen a novel signature in a
confirmed attack, it detects it thereafter -- forcing adaptive Red to mint a
new one. Learning the ambiguous flag also lights up benign look-alikes that
share it, so recall and false positives move together (the cost of adaptation).
"""
from __future__ import annotations

try:
    from case_pool import tokenize_signatures, ANOMALOUS_PARENTS, KNOWN_FLAGS
except ImportError:  # pragma: no cover - resolved via loader in the loop
    ANOMALOUS_PARENTS = ["winword.exe", "excel.exe", "outlook.exe", "wscript.exe", "mshta.exe"]
    KNOWN_FLAGS = ["-enc", "-encodedcommand", "-w", "-nop"]

    def tokenize_signatures(cmdline):
        if not cmdline:
            return set()
        return {t for t in cmdline.lower().split()
                if t.startswith("-") or t.startswith("obf_")}

BLUE_VERSION = "blue-adaptive-v1"
DETECT_AT = 2
INVESTIGATE_AT = 1


class AdaptiveBlue:
    def __init__(self, adaptive: bool):
        self.adaptive = adaptive
        self.known = set(f.lower() for f in KNOWN_FLAGS)
        self.suspicious_parents = set(p.lower() for p in ANOMALOUS_PARENTS)
        self.learned: list[str] = []  # signatures acquired through adaptation

    def _assess(self, events: list[dict]) -> dict:
        score = 0
        evidence: list[str] = []
        missing = False
        shells = [e for e in events if e.get("process") == "powershell.exe"] or events
        for e in shells:
            parent = (e.get("parent_process") or "").lower()
            if parent in self.suspicious_parents:
                score += 1
                evidence.append(f"anomalous parent {e.get('parent_process')}")
            cmd = e.get("command_line")
            if cmd is None:
                missing = True
                continue
            sigs = tokenize_signatures(cmd)
            hit = sigs & self.known
            if hit:
                # Strong IOCs (explicit obfuscation markers, hard encoding)
                # warrant a detect on their own; dual-use flags only add
                # suspicion.
                strong = any(s.startswith("-obf_") or s in ("-enc", "-encodedcommand")
                             for s in hit)
                score += 2 if strong else 1
                evidence.append(f"{'strong ' if strong else ''}known signature {sorted(hit)}")
        if missing and score < DETECT_AT:
            evidence.append("command_line missing -- evidence incomplete")

        if score >= DETECT_AT:
            decision, response = "detect", "contain"
        elif score >= INVESTIGATE_AT or missing:
            decision, response = "investigate", "investigate"
        else:
            decision, response = "no_alert", "no_action"

        confidence = min(1.0, 0.3 + 0.35 * score)
        if missing:
            confidence = min(confidence, 0.5)
        if decision == "no_alert":
            confidence = 0.6
        return {
            "decision": decision,
            "technique_hypothesis": "T1059.001" if decision != "no_alert" else "unknown",
            "confidence": round(confidence, 2),
            "evidence": evidence or ["no known indicators in observed events"],
            "recommended_response": response,
        }

    def decide(self, events_by_case: dict[str, list[dict]]) -> dict[str, dict]:
        out = {}
        for cid, evs in events_by_case.items():
            d = self._assess(evs)
            d["case_id"] = cid
            out[cid] = d
        return out

    def adapt(self, events_by_case: dict[str, list[dict]],
              cases_by_id: dict) -> dict:
        """Learn signatures from confirmed attacks in the adaptation split only."""
        if not self.adaptive:
            return self.snapshot(new=[])
        newly: set[str] = set()
        for cid, case in cases_by_id.items():
            if not case.attack_present or case.split != "adaptation":
                continue
            for e in events_by_case.get(cid, []):
                for sig in tokenize_signatures(e.get("command_line")):
                    if sig not in self.known:
                        newly.add(sig)
        for sig in sorted(newly):
            self.known.add(sig)
            self.learned.append(sig)
        return self.snapshot(new=sorted(newly))

    def snapshot(self, new=None) -> dict:
        return {
            "blue_version": BLUE_VERSION,
            "adaptive": self.adaptive,
            "known_signature_count": len(self.known),
            "known_signatures": sorted(self.known),
            "learned_this_round": new or [],
            "learned_total": list(self.learned),
        }
