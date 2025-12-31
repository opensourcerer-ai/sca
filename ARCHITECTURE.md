# ARCHITECTURE.md — SCA architecture (v1)

## Core separation
SCA enforces a strict separation between:

1. **Agent tool** (this project)
   - versioned, ideally installed externally (e.g. `/opt/sca`)
   - treated as immutable during audits

2. **Subject repo** (the repository being audited)
   - never modified by SCA

3. **Control directory** (`sec-ctrl/`)
   - the only place SCA writes repo-specific artifacts:
     - reports, state, cache, local overrides

## Why this separation exists
- Prevent accidental PRs or tool drift
- Make audits repeatable and comparable
- Keep local policy overrides explicitly documented

## Deployment modes
- External install: `--agent-dir /opt/sca` (recommended)
- Submodule: repo-local `tools/sec-audit-agent/` pinned and enforced clean
- Vendored snapshot: release bundle unpacked repo-local and locked read-only

## Control directory structure
SCA writes the following categories:
- `state/`: last run metadata + drift anchors
- `reports/`: human-readable + machine-readable outputs
- `config/`: ignore rules + severity mapping
- `invariants/`: local overrides (must include justification)
- `cache/`: optional summaries for speed

## Model integration
The LLM is used as a reasoning engine constrained by:
- runbook
- invariant packs
- report templates
- explicit evidence requirements

