# Security Control Agent (SCA)

**Production-grade v1**

SCA is a **read-only, invariant-driven security auditing tool** for code repositories and LLM/agent systems. It uses an LLM as a **constrained reasoning engine** to produce **repeatable, evidence-based security reports**.

---

## Key Features

✅ **Read-only**: Never modifies the audited repository
✅ **Evidence-based**: Every finding cites file paths and context
✅ **Invariant-driven**: Explicit, versioned security rules per language
✅ **Drift-aware**: Track security posture changes over time
✅ **Immutable agent**: Enforces tool integrity during audits (exit 4 if violated)
✅ **CI/CD ready**: Deterministic exit codes for pipeline integration

---

## Quick Start

### 1. Install SCA
```bash
# Recommended: system-wide install
sudo make install PREFIX=/opt/sca
sudo chown -R root:root /opt/sca
sudo chmod -R a-w /opt/sca
sudo ln -s /opt/sca/bin/sca /usr/local/bin/sca
```

See [INSTALL.md](INSTALL.md) for all installation methods.

### 2. Initialize Control Directory
```bash
cd /path/to/your/repo
sca bootstrap
```

### 3. Run Audit
```bash
sca audit
```

Reports are written to `sec-ctrl/reports/security-audit.latest.md`.

### 4. Review Findings
```bash
cat sec-ctrl/reports/security-audit.latest.md
```

### 5. Track Drift & Manage Findings
```bash
# After making changes
sca audit
sca diff

# Review remediation suggestions
cat sec-ctrl/SUGGESTIONS.md

# Suppress accepted findings (with justification)
vim sec-ctrl/OVERRIDE.md
```

---

## CLI Reference

### Commands
- **`sca audit`** - Run security audit (exit 0 if clean, 2 if critical/high findings)
- **`sca scope`** - Print file list analyzed (excludes sec-ctrl/, agent-dir, etc.)
- **`sca diff`** - Compare current vs previous report (drift summary)
- **`sca bootstrap`** - Initialize sec-ctrl/ directory (includes OVERRIDE.md template)

### Common Options
```bash
sca audit --repo /path/to/repo      # Specify repo root
sca audit --enable-deps             # Run npm-audit, pip-audit, etc.
sca audit --incremental             # Skip if repo unchanged
sca audit --verbose                 # Show detailed progress
```

See [CLI.md](CLI.md) for full specification.

---

## Exit Codes (CI/CD Integration)

| Code | Meaning | CI Action |
|------|---------|-----------|
| **0** | No critical/high findings | ✅ Pass |
| **2** | Critical/high findings exist | ❌ Fail (block merge) |
| **3** | Audit incomplete (config error) | ⚠️ Warn |
| **4** | Agent not immutable (security violation) | ❌ Fail |
| **5** | Internal error | ⚠️ Warn |

**Example GitHub Actions:**
```yaml
- name: Security Audit
  run: sca audit --verbose
  # Exit code 2 will fail the job
```

---

## Architecture

SCA enforces strict separation between:
1. **Agent tool** (SCA itself, installed to `/opt/sca` - immutable)
2. **Subject repo** (your code - never modified by SCA)
3. **Control directory** (`sec-ctrl/` - SCA's workspace for reports/state)

See [ARCHITECTURE.md](ARCHITECTURE.md) for details.

---

## What SCA Audits

### Language-Specific Checks
- **C/C++**: Buffer overflows, stack overflows, use-after-free, double-free, format strings, race conditions, uninitialized variables
- **Go**: Error handling, SQL injection, path traversal
- **Java**: Deserialization, XXE, SQL injection
- **JavaScript/TypeScript**: XSS, prototype pollution, eval usage
- **Python**: SQL injection, pickle usage, subprocess injection
- **Rust**: Unsafe blocks, FFI boundaries

### Cross-Cutting Concerns
- Authentication & authorization design
- Secrets in code (API keys, tokens, credentials)
- Cryptography misuse (weak algorithms, ECB mode, non-PQC, key exposure)
- Input validation and sanitization
- Dependency risk (lockfiles, CVEs via optional scanners)
- LLM/Agent security (prompt injection, tool boundaries, data leakage)

---

## Deployment Modes

### A) External Install (Recommended)
Install to `/opt/sca`, owned by root, read-only.

**Pros**: Clear separation, enforced immutability
**Cons**: Requires sudo for install

### B) Git Submodule
Pin SCA as `tools/sec-audit-agent/` in your repo.

**Pros**: Versioned with repo, no external dependencies
**Cons**: Must keep clean (git status enforced)

### C) Vendored Release
Unpack SCA tarball into repo, make read-only.

**Pros**: Fully self-contained
**Cons**: Manual updates

---

## Dependency Scanning (Optional)

Enable with `--enable-deps`:
```bash
sca audit --enable-deps
```

Runs ecosystem scanners:
- `npm audit` (JavaScript)
- `pip-audit` (Python)
- `cargo audit` (Rust)
- `govulncheck` (Go)

Raw outputs saved to `sec-ctrl/reports/deps/`.

---

## Security Posture

SCA itself is designed to be safe:
- **No write access** to audited repos
- **No code execution** of analyzed code
- **No auto-fixes or PRs**
- **LLM outputs are advisory** (human review required)

See [SECURITY.md](SECURITY.md) for threat model.

---

## Development

### Run Tests
```bash
make test
```

### Lint Scripts
```bash
make lint
```

### Self-Audit (Dogfooding)
```bash
cd /opt/sca
sca audit --repo /opt/sca
```

---

## License

Apache License 2.0 - See [LICENSE](LICENSE)

---

## Support

- **Issues**: https://github.com/your-org/sca/issues
- **Docs**: See `docs/` directory
- **Contributing**: See `CONTRIBUTING.md` (if applicable)

---

## Acknowledgments

Built with Claude Code and designed for safety-critical environments.
