# PROJECT.md — Security Control Agent (SCA)

## Project name
**Security Control Agent (SCA)**

## One-line description
SCA is a **read-only, invariant-driven security auditing tool** for source code repositories and LLM/agent systems. It uses an LLM as a **constrained reasoning engine** to produce **repeatable, evidence-based reports**.

## Problem statement
Security reviews often fail because tools lack system context, do not track drift over time, and cannot test code against declared intent. SCA treats a repository as a **system under control** and evaluates it against **explicit invariants**, tracking regression and drift across runs.

## Non-negotiable principles
1. **Read-only**: SCA never modifies the audited repo and never opens PRs.
2. **Invariants first**: all checks are explicit, versioned, and reviewable.
3. **Constrained AI**: the LLM is a reasoning component, not an autonomous actor.
4. **Evidence-based**: every finding references concrete repo evidence (paths, snippets, configs).
5. **Drift-aware**: track changes in security posture across time.

## Scope (v1)
**In scope**
- Static repo analysis (code + docs + configs)
- OWASP-style application security review (architecture + code paths)
- Dependency/CVE *risk identification* (with optional external scanners)
- Language-specific invariant packs
- LLM / agent security review mapped to OWASP LLM Top 10
- Report generation + drift comparison

**Out of scope (v1)**
- Modifying code / auto-fixes / auto-PRs
- Runtime protection
- Exploitation, fuzzing, DAST
- Autonomous remediation and enforcement (humans decide)

## Architecture overview
SCA separates three concerns:
- **Agent tool**: immutable, pinned, ideally installed externally and read-only.
- **Subject repo**: the repository being audited (never modified).
- **Control state**: repo-specific state and artifacts, stored under `sec-ctrl/` (or `--ctrl-dir`).

## Control directory
Repo-specific artifacts MUST live under `sec-ctrl/` by default:
- reports, drift state, ignore rules, local overrides, cache
- optional alternate path via `--ctrl-dir` or `SEC_CTRL_DIR`

## Use of AI (explicit disclosure)
SCA uses an LLM internally as a reasoning engine under strict constraints:
- no write access to the audited repo
- no execution authority
- prompts/runbooks/invariants are visible and versioned
- uncertainty must be stated explicitly

## License
Apache License 2.0
