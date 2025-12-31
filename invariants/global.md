# Global Security Invariants (v1)

- No committed secrets (tokens, private keys, seed words, credentials, session secrets).
- No logging of credentials, tokens, session IDs, or sensitive PII.
- All outbound network calls must have timeouts.
- Crypto must use approved primitives and safe modes (no ECB; no homebrew crypto).
- Authorization must be explicit at every privileged operation.
- Inputs must be validated and bounded (size, type, format).
- Dependencies must be pinned/locked (lockfiles required where applicable).
- Build/release pipelines must not run unpinned remote scripts without verification.
