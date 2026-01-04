# Security Control Agent (SCA)

[![Tests](https://img.shields.io/badge/tests-passing-brightgreen)](https://github.com/opensourcerer-ai/sca)
[![Version](https://img.shields.io/badge/version-0.8.8-blue)](https://github.com/opensourcerer-ai/sca/releases)
[![License](https://img.shields.io/badge/license-Apache%202.0-green)](LICENSE)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010%202021-orange)](https://owasp.org/Top10/)
[![OWASP API](https://img.shields.io/badge/OWASP-API%20Top%2010%202023-orange)](https://owasp.org/API-Security/)

> **AI-Powered Security Auditing for Modern Codebases**
>
> Find vulnerabilities before they reach production. SCA analyzes your code with 150+ security invariants across 6 languages, using AI as a constrained reasoning engine to produce repeatable, evidence-based audit reports.

**🎯 What makes SCA different:**
- ✅ **Zero false trust**: Read-only operation, never modifies your code
- 🧠 **AI-guided analysis**: LLM finds complex vulnerabilities pattern-matching misses
- 📊 **Evidence-based reports**: Every finding cites exact file locations and context
- 🔒 **Immutable agent**: Cryptographically verifiable tool integrity
- 🚀 **CI/CD native**: Deterministic exit codes, drift tracking, automated tickets

---

## 📦 Prerequisites

SCA runs via **Claude Code** to provide AI-powered analysis with filesystem access:

1. **Install Claude Code**: Follow [Claude Code installation guide](https://claude.com/claude-code)
2. **Install SCA invariants**:

```bash
git clone https://github.com/opensourcerer-ai/sca.git
cd sca
sudo make install PREFIX=/opt/sca
sudo chown -R root:root /opt/sca
sudo chmod -R a-w /opt/sca
```

This installs security invariants (markdown files) and wrapper scripts that Claude Code uses to analyze your repositories.

See [INSTALL.md](INSTALL.md) for detailed installation options.

---

## 🚀 Quick Start

### Interactive Mode (Recommended)

```bash
# Navigate to your repository
cd /path/to/your/repo

# Run Claude Code with SCA
claude-code

# In the Claude Code session:
> "Please run a security audit using the SCA invariants in /opt/sca/invariants/.
   Create a sec-ctrl/ directory for reports."
```

### Command-Line Mode (Cron/Automation)

```bash
# Direct execution via SCA wrapper
/opt/sca/bin/sca audit /path/to/your/repo

# Or schedule via cron
# /etc/cron.d/sca-audit
0 2 * * * user /opt/sca/bin/sca audit /path/to/repo
```

**What happens:**
- Claude Code reads your repository files
- Applies 150+ security invariants from SCA
- Generates:
  - 📄 Detailed security audit report (`sec-ctrl/reports/security-audit.latest.md`)
  - 🔧 Actionable remediation suggestions (`sec-ctrl/SUGGESTIONS.md`)
  - 📊 JSON-formatted findings (`sec-ctrl/reports/security-audit.latest.json`)

See the [Getting Started Guide](docs/USAGE.md) for detailed workflows.

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

SCA uses a hybrid execution model:

1. **Claude Code** - Execution engine providing:
   - AI-powered analysis and reasoning
   - Filesystem access to read your repository
   - API integration with Anthropic

2. **SCA Wrapper Scripts** - Orchestration:
   - `bin/sca` (Python) - CLI argument parser
   - `bin/sec-audit.sh` (Bash) - Constructs prompts, invokes Claude
   - Command: `claude code < prompt.txt > report.md`

3. **SCA Invariants** - Security knowledge base:
   - 150+ security rules across 6 languages (markdown files)
   - Located at `/opt/sca/invariants/` (immutable, read-only)
   - Prompts and workflows in `/opt/sca/prompts/`

4. **Your Repository** - Subject of analysis (never modified):
   - SCA only reads files, never writes to source
   - All output goes to `sec-ctrl/` directory

5. **Control Directory** (`sec-ctrl/`) - SCA's workspace:
   - Reports, suggestions, state tracking
   - Created in your repository but `.gitignore`-able

**Execution Flow**:
```
sca audit → sec-audit.sh → claude code < prompt → Analysis → sec-ctrl/reports/
```

The prompt file includes: invariants, file list, overrides, runbook, and report template.

See [ARCHITECTURE.md](ARCHITECTURE.md) for details.

---

## 🆚 Why Choose SCA?

### Comparison with Other Tools

| Feature | SCA | Semgrep | Snyk | SonarQube | CodeQL |
|---------|-----|---------|------|-----------|--------|
| **AI-Powered Analysis** | ✅ Claude-powered | ❌ | ❌ | ❌ | ❌ |
| **Pattern Matching** | ✅ 150+ invariants | ✅ | ✅ | ✅ | ✅ |
| **Zero False Trust** | ✅ Read-only | ⚠️ | ⚠️ | ⚠️ | ✅ |
| **Evidence Citations** | ✅ Every finding | ✅ | ✅ | ✅ | ✅ |
| **Cost** | 💰 API costs | 🆓/💰 | 💰 Expensive | 💰 | 🆓 GitHub only |
| **Execution Model** | Claude Code | Standalone | Standalone/Cloud | Server | GitHub Actions |
| **Structured Suppression** | ✅ Justification required | ⚠️ Comments | ⚠️ | ⚠️ | ⚠️ |
| **Drift Tracking** | ✅ Built-in | ❌ | ⚠️ | ✅ | ❌ |
| **Setup Complexity** | ⭐ Install invariants | ⭐ Simple | ⭐⭐ | ⭐⭐⭐ | ⭐⭐ |

**SCA's Sweet Spot**: Teams wanting **AI-assisted deep analysis** with **strong governance** (justifications, drift tracking) who already use **Claude Code** for development.

---

## 🔍 What SCA Audits

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

### A) System-Wide Install (Recommended)
Install to `/opt/sca`, owned by root, read-only.

```bash
sudo make install PREFIX=/opt/sca
sudo chown -R root:root /opt/sca
sudo chmod -R a-w /opt/sca
```

**Pros**:
- Available to all users
- Single source of truth for invariants
- Enforced immutability
- Easy cron job setup

**Cons**: Requires sudo for install

### B) User-Local Install
Install to `~/.local/sca` (no sudo required).

```bash
make install PREFIX=~/.local/sca
```

**Pros**: No sudo needed, per-user customization
**Cons**: Each user maintains their own copy

### C) Git Submodule (Per-Repository)
Pin SCA as `tools/sca/` in your specific repo.

```bash
git submodule add https://github.com/you/sca tools/sca
```

**Pros**: Versioned with repo, portable
**Cons**: Duplicate copies across repos, manual updates

---


## Security Posture

SCA's security model:

**Read-Only Analysis**:
- Claude Code reads your repository files
- SCA invariants guide analysis (markdown files only)
- No write access to your source code
- All output goes to `sec-ctrl/` directory

**No Code Execution**:
- Analyzed code is never executed
- Static analysis only
- Pattern matching + AI reasoning

**Human-in-the-Loop**:
- LLM outputs are advisory (human review required)
- No auto-fixes or automatic PRs
- Findings require human validation

**Immutable Invariants**:
- SCA knowledge base (`/opt/sca/`) is read-only
- Owned by root, cannot be tampered with
- Ensures consistent, trustworthy analysis

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
# Use SCA to audit itself
cd /path/to/sca
claude-code
> "Use the invariants in ./invariants/ to audit this repository"
```

---

## License

Apache License 2.0 - See [LICENSE](LICENSE)

---

## 📚 Documentation

- **[Installation Guide](INSTALL.md)** - Deployment modes and setup
- **[Usage Guide](docs/USAGE.md)** - Workflows and best practices
- **[Architecture](ARCHITECTURE.md)** - System design and security model
- **[CLI Reference](CLI.md)** - Complete command documentation
- **[GA Roadmap](docs/GA_ROADMAP.md)** - v1.0 release timeline

---

## 🤝 Contributing

We welcome contributions! Areas where you can help:

- 🐛 **Bug reports**: [Open an issue](https://github.com/opensourcerer-ai/sca/issues/new)
- 📝 **New invariants**: Add security rules for more languages/frameworks
- 🧪 **Test coverage**: Expand unit/integration tests
- 📖 **Documentation**: Tutorials, examples, translations
- 🎨 **Tooling**: Package managers, IDE plugins, dashboards

See our [GA Roadmap](docs/GA_ROADMAP.md) for current priorities.

---

## 📄 License

Apache License 2.0 - See [LICENSE](LICENSE)

Free for commercial and non-commercial use. No vendor lock-in.

---

## 🙏 Acknowledgments

Built with [Claude Code](https://claude.com/claude-code) and designed for safety-critical environments.

**Made with ❤️ for the open-source security community**
