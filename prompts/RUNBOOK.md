Steps:
1. Inventory entrypoints (CLI, HTTP, RPC, workers, cron jobs).
2. Identify trust boundaries and sensitive assets.
3. Review authn/authz design and enforcement points.
4. Review input validation and output handling.
5. Review secrets/key material handling and storage.
6. Review dependency risk and supply-chain posture (lockfiles, pinning).
7. Apply language invariants for detected languages.
8. If LLM components exist, apply LLM invariants.
9. Produce report and prioritized fix plan.
