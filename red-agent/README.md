# red-agent/

The AI Red Team: turns attack intent into observable telemetry and, when
adaptive, evolves its strategy to evade Blue.

* `red_agent.py` — `RedAgent`. Two evasion dials (benign parent, novel
  obfuscation token) plus **token minting** when its current obfuscation is
  burned. Static mode holds a fixed, mostly-detectable distribution (baseline
  Red for conditions A and C); adaptive mode reinforces whatever produced a
  clean `no_alert` (conditions B and D).

Evaluated on stealth / attack success. No real commands are emitted —
signatures are inert flag strings. See `results/README.md` ("Co-Evolution").
