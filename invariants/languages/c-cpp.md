# C/C++ Invariants (v1)
- No unsafe string functions (strcpy/strcat/sprintf) without bounds checks.
- All buffer operations must be size-checked.
- No homebrew crypto.
- Public interfaces must document ownership/lifetime rules.
- Prefer hardened builds where applicable (PIE/RELRO/stack protector).
