# Local invariant overrides (repo-specific)

Rules:
- Keep overrides minimal.
- Each override must include a justification and scope.
- Prefer fixing the code over weakening invariants.

Example:
- Override: allow shell=True for a specific script
  Scope: scripts/legacy_migrate.py
  Justification: legacy vendor tooling requires shell parsing; input is not user-controlled.
  Owner: security@team
  Expiry: 2026-03-01
