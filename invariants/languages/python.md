# Python Invariants (v1)
- No eval/exec on user-controlled input.
- No pickle.loads on untrusted input.
- subprocess: avoid shell=True; validate arguments; prefer list form.
- HTTP clients must set timeouts; do not disable TLS verification.
- JWT: enforce algorithm; validate exp; validate iss/aud where relevant.
