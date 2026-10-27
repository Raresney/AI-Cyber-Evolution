#!/usr/bin/env python3
"""Red agent for CYBER-EVO co-evolution.

Renders attack cases into observable telemetry under a strategy, and (when
adaptive) shifts that strategy toward whatever evaded Blue, minting fresh
obfuscation when its current novel signature stops working.

Strategy (two evasion dimensions):

* ``p_benign_parent`` -- probability of spawning from an ordinary parent
  (explorer/cmd) instead of an anomalous one (winword/mshta). Benign parent
  removes Blue's parent signal.
* ``p_novel_token``   -- probability of using a freshly obfuscated signature
  Blue does not yet know, instead of a known flag.

The attack is always ``attack_present = True`` regardless of how benign it
looks: that is the point -- Blue must detect intent from evasive observables,
and Red's job is to make the observables look innocent (stealth).

Adaptation (adaptive mode only), after each round, over the attack cases in
the adaptation + validation splits:

* reinforce the parent / token choice that evaded more often;
* if the current novel signature no longer evades (Blue has learned it),
  mint a new one -- this drives the arms-race oscillation in condition D.

Static mode holds a fixed, representative (mostly detectable) distribution.
No real commands are emitted; signatures are inert flag strings.
"""
from __future__ import annotations

import random

# Imported-by-path by the loop; fall back to a direct import when run as a
# sibling for ad-hoc testing.
try:
    from case_pool import KNOWN_FLAGS, ANOMALOUS_PARENTS, BENIGN_PARENTS, AMBIGUOUS_FLAG
except ImportError:  # pragma: no cover - resolved via loader in the loop
    KNOWN_FLAGS = ["-enc", "-encodedcommand", "-w", "-nop"]
    ANOMALOUS_PARENTS = ["winword.exe", "excel.exe", "outlook.exe", "wscript.exe", "mshta.exe"]
    BENIGN_PARENTS = ["explorer.exe", "cmd.exe", "powershell_ise.exe", "services.exe", "taskeng.exe"]
    AMBIGUOUS_FLAG = "-ep_bypass"

RED_VERSION = "red-evasion-v1"


class RedAgent:
    def __init__(self, adaptive: bool, lr: float = 0.3,
                 p_ambiguous: float = 0.4):
        self.adaptive = adaptive
        self.lr = lr
        self.p_ambiguous = p_ambiguous  # chance an attack also carries the ambiguous flag
        self.novel_version = 1
        self.minted = 0
        if adaptive:
            # Start obvious, learn to hide.
            self.p_benign_parent = 0.3
            self.p_novel_token = 0.3
        else:
            # Static Red: fixed, mostly detectable.
            self.p_benign_parent = 0.3
            self.p_novel_token = 0.3
        # last render choices, for adaptation
        self._choices: dict[str, dict] = {}

    @property
    def current_novel(self) -> str:
        return f"-obf_v{self.novel_version}"

    def _clamp(self, x: float) -> float:
        return max(0.05, min(0.95, x))

    def render(self, attack_cases, round_seed: int) -> list[dict]:
        """Produce events for the attack cases; record choices for adaptation."""
        rng = random.Random(round_seed)
        events: list[dict] = []
        self._choices = {}
        base_min = 0
        for c in attack_cases:
            benign_parent = rng.random() < self.p_benign_parent
            novel_token = rng.random() < self.p_novel_token
            parent = (rng.choice(BENIGN_PARENTS) if benign_parent
                      else rng.choice(ANOMALOUS_PARENTS))
            primary = self.current_novel if novel_token else rng.choice(KNOWN_FLAGS)
            parts = ["powershell.exe", primary, "<payload>"]
            if rng.random() < self.p_ambiguous:
                parts.insert(2, AMBIGUOUS_FLAG)
            cmdline = " ".join(parts)

            self._choices[c.case_id] = {
                "benign_parent": benign_parent,
                "novel_token": novel_token,
                "split": c.split,
            }
            events.append({
                "case_id": c.case_id,
                "timestamp": f"2026-10-13T10:{base_min % 60:02d}:00Z",
                "host": rng.choice(["WIN-01", "WIN-02", "FIN-07"]),
                "user": rng.choice(["alice", "bob", "carol"]),
                "process": "powershell.exe",
                "parent_process": parent,
                "process_id": rng.randint(3000, 9000),
                "parent_process_id": rng.randint(1000, 3000),
                "command_line": cmdline,
                "integrity_level": rng.choice(["Medium", "High"]),
                "event_source": "synthetic_process_telemetry",
            })
            base_min += 3
        return events

    def adapt(self, decisions: dict[str, dict]) -> dict:
        """Shift strategy toward evasive choices; mint when novel is burned.

        ``decisions`` maps case_id -> Blue decision dict. Only adaptation +
        validation attack cases are used (never final_test).
        """
        if not self.adaptive:
            return self.snapshot(minted=False)

        def evasion_rates(key: str):
            yes_e = yes_n = no_e = no_n = 0
            for cid, ch in self._choices.items():
                if ch["split"] == "final_test":
                    continue
                d = decisions.get(cid)
                if not d:
                    continue
                # Full evasion = slipped past entirely. 'investigate' means Blue
                # caught the scent, so Red keeps pushing (and will mint when its
                # novel signature stops producing clean no_alerts).
                evaded = d["decision"] == "no_alert"
                if ch[key]:
                    yes_n += 1
                    yes_e += int(evaded)
                else:
                    no_n += 1
                    no_e += int(evaded)
            r_yes = yes_e / yes_n if yes_n else None
            r_no = no_e / no_n if no_n else None
            return r_yes, r_no

        # Reinforce parent choice.
        ry, rn = evasion_rates("benign_parent")
        if ry is not None and rn is not None:
            self.p_benign_parent = self._clamp(
                self.p_benign_parent + self.lr * (ry - rn))

        # Reinforce token choice; capture novel evasion rate for minting.
        ry_t, rn_t = evasion_rates("novel_token")
        if ry_t is not None and rn_t is not None:
            self.p_novel_token = self._clamp(
                self.p_novel_token + self.lr * (ry_t - rn_t))

        minted = False
        # Novel signature burned (Blue learned it) -> mutate to a new one.
        if ry_t is not None and ry_t < 0.5:
            self.novel_version += 1
            self.minted += 1
            minted = True
            # Keep leaning on novelty after minting.
            self.p_novel_token = self._clamp(self.p_novel_token + 0.2)

        return self.snapshot(minted=minted)

    def snapshot(self, minted: bool = False) -> dict:
        return {
            "red_version": RED_VERSION,
            "adaptive": self.adaptive,
            "p_benign_parent": round(self.p_benign_parent, 3),
            "p_novel_token": round(self.p_novel_token, 3),
            "current_novel": self.current_novel,
            "tokens_minted": self.minted,
            "minted_this_round": minted,
        }
