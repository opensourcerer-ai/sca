# CLI.md — SCA CLI contract (v1)

## Commands

### `sca audit`
Runs a security audit against a repository and writes artifacts to the control directory.

**Flags**
- `--repo <path>`: repo root (default: current git root)
- `--ctrl-dir <path>`: control directory (default: `<repo>/sec-ctrl`)
- `--agent-dir <path>`: location of SCA agent checkout (default resolution: flag, env, /opt/sca, repo-local)
- `--readonly-agent` / `--no-readonly-agent`: enforce agent immutability (default: on)
- `--format md|json|both` (default: md)
- `--profile baseline|web|crypto|llm|all` (default: all)

**Exit codes**
- `0`: audit completed; no Critical/High confirmed findings
- `2`: audit completed; Critical/High confirmed findings exist
- `3`: audit incomplete (missing tool / permissions / scope failure)
- `4`: agent checkout violates read-only policy (writable or dirty)
- `5`: internal error

### `sca scope`
Prints the file list used for analysis (excludes `sec-ctrl/` and agent directory).

### `sca diff`
Compares latest report to previous report and summarizes drift.

## Environment variables
- `SEC_CTRL_DIR`: default control directory override
- `SEC_AUDIT_AGENT_HOME`: default agent directory
- `CLAUDE_CODE_BIN`: path to Claude Code binary (optional)

