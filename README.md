# Security Control Agent (SCA)

SCA is a **read-only, invariant-driven security auditing tool** for code repositories and LLM/agent systems.

- **Read-only**: never modifies the audited repo.
- **Evidence-based**: every finding points to concrete code/config evidence.
- **Invariant-driven**: explicit rules per language + domain (web, crypto, LLM).
- **Drift-aware**: compares current results against prior runs in `sec-ctrl/`.

## What SCA is (and is not)
- SCA is a *control system* for security review.
- SCA is **not** an autonomous fixer, PR bot, or runtime security product.

## Quick start (local)
1. Install Claude Code (or set your model runner).
2. Put SCA somewhere read-only (recommended): `/opt/sca`
3. In the target repo, create `sec-ctrl/` (SCA will populate it).
4. Run:
   - `sca audit --repo .`
   - or `bin/sec-audit.sh --repo .`

## Deployment modes (supported)
- External install (recommended): `/opt/sca`
- Git submodule pinned in the target repo
- Vendored release snapshot (tarball) in the target repo

SCA refuses to run if the agent checkout is writable or dirty (when applicable).

## License
Apache-2.0
