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

### Language-Specific Security (150+ Invariants)
- **C/C++**: Buffer overflows, stack overflows, use-after-free, double-free, format strings, race conditions, uninitialized variables, memory leaks, integer overflows
- **Go**: Error handling, memory leaks (goroutines, timers, HTTP bodies), data races, GC pressure, SQL injection, path traversal
- **Java**: Deserialization, XXE, SQL injection, GC leaks (listeners, ThreadLocal, classloaders), threading issues
- **JavaScript/TypeScript**: XSS, prototype pollution, eval usage, timing attacks
- **Python**: SQL injection, pickle deserialization, subprocess injection, GIL issues, circular references
- **Rust**: Unsafe blocks, FFI boundaries, memory safety

### Authentication & Authorization (SCA-301 to SCA-310, 870-880)
- **Authentication**: Hard-coded credentials, weak passwords, insecure storage, missing MFA, session management
- **Access Control**: Missing authorization checks, IDOR, privilege escalation, path traversal, CORS misconfigurations
- **API Security** (OWASP API Security Top 10 2023):
  - Broken object/function level authorization
  - Broken authentication, mass assignment
  - Unrestricted resource consumption, rate limiting
  - Security misconfiguration, API versioning
  - SSRF in webhooks and third-party integrations

### Network Security (SCA-870 to SCA-880)
- **Protocol Security**: HTTP vs HTTPS, TLS certificate validation, weak TLS (1.0/1.1), cipher suites
- **Server Configuration**: Insecure bindings (0.0.0.0), missing timeouts, hardcoded IPs
- **WebSocket/gRPC**: Missing TLS, authentication, DNS rebinding
- **SSRF Protection**: URL validation, IP range blocking, metadata service protection

### Cryptography (SCA-100 to SCA-199)
- **Weak Algorithms**: DES, 3DES, RC4, MD5, SHA-1, RSA <2048
- **Key Management**: Hard-coded keys, key exposure, missing rotation, TPM usage
- **Modes & Padding**: ECB mode, insecure random, timing attacks
- **Post-Quantum**: PQC migration readiness (ML-KEM, ML-DSA)
- **Format-Preserving Encryption**: FF1/FF3 vulnerabilities

### Data Protection & Privacy (SCA-200 to SCA-299)
- **Logging**: Secrets in logs, PII exposure, sanitization
- **Database**: Unencrypted connections, plaintext sensitive data
- **Privacy Compliance**: GDPR (consent, minimization, retention, DSARs), CCPA, HIPAA
- **PII Handling**: Collection, storage, cross-border transfers

### Container & Kubernetes Security (SCA-851 to SCA-861)
- **Container Hardening**: Root users, privileged mode, capabilities, host mounts
- **Secrets Management**: Secrets in images, environment variables
- **Network Policies**: Missing policies, overly permissive rules
- **RBAC**: Cluster-admin bindings, wildcard permissions
- **Resource Limits**: CPU/memory limits, Pod Security Standards

### TPM & Attestation (SCA-801 to SCA-807)
- **Hardware Security**: TPM 2.0 usage, Secure Boot, remote attestation
- **Confidential Computing**: SGX, SEV, TDX attestation
- **Platform Integrity**: PCR usage, attestation key provisioning

### Supply Chain Security (SCA-900 to SCA-999)
- **Dependencies**: Vulnerable packages, unpinned versions, malicious packages
- **SBOM**: Missing Software Bill of Materials, EO 14028 compliance
- **Integrity**: Hash verification, reproducible builds, registry security

### AI Agent Security (SCA-1000 to SCA-2000)
- **MCP Security**: Unrestricted tool access, prompt injection via tools, missing auth
- **In-Repo Agents**: Secrets in prompts, PII in examples, unsafe tool implementations
- **Model Security**: Model integrity checks, conversation history sanitization
- **LLM Attacks**: Jailbreaking (DAN, roleplay, encoding), token smuggling, context stuffing

### Documentation & Compliance (SCA-500 to SCA-599)
- **Missing Documentation**: Security-critical functions, API endpoints, CLI commands
- **Configuration**: Environment variables, schemas, examples
- **Standards Compliance**: NIST 800-53, OWASP Top 10, PCI-DSS, HIPAA, GDPR, ISO 27001

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
