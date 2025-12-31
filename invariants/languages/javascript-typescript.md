# JavaScript/TypeScript Invariants (v1)
- No eval/new Function with untrusted input.
- No string concatenation into SQL/NoSQL queries; use parameterization.
- SSRF protections for any fetch/proxy component (block internal ranges).
- XSS: ensure output encoding/sanitization at render boundaries.
- Secrets must not be embedded in client bundles.
