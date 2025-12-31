# Rust Invariants (v1)
- Unsafe blocks must be documented and reviewed.
- Avoid panics in network-facing parsing paths (DoS risk).
- Constant-time comparisons for secrets where relevant.
- Command execution must not be built from untrusted input.
- TLS must validate certificates by default.
