# INVARIANTS.md — invariant packs (v1)

## Definition
An invariant is an explicit security rule about system behavior or implementation constraints.
SCA uses invariants to drive consistent auditing and to detect drift.

## Types
- **Global invariants**: apply to all repos
- **Language invariants**: apply to specific languages
- **Domain invariants**: web, crypto/KMS, LLM/agents, etc.
- **Local overrides**: repo-specific exceptions in `sec-ctrl/invariants/`

## Requirements
- Invariants MUST be human-readable.
- Any local override MUST include justification and scope.
- Findings MUST reference evidence (paths, functions, configs).

## Where invariants live
- Agent packs: `invariants/`
- Repo-local overrides: `sec-ctrl/invariants/`

## Drift
Drift is defined as a change in invariant satisfaction over time.
SCA records prior run fingerprints and compares results in reports.

