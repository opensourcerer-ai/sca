# SCA (Security Control Agent) - Complete User Guide

## Table of Contents

1. [Overview](#overview)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Commands Reference](#commands-reference)
5. [Security Invariants](#security-invariants)
6. [Workflows](#workflows)
7. [CI/CD Integration](#cicd-integration)
8. [Troubleshooting](#troubleshooting)
9. [Best Practices](#best-practices)

---

## Overview

**SCA (Security Control Agent)** is a production-grade, read-only security auditing tool that uses AI-driven analysis with predefined security invariants to identify vulnerabilities in your codebase.

### Key Features

- ✅ **Read-Only**: Never modifies subject repository
- ✅ **AI-Driven**: Uses Claude Code for intelligent analysis
- ✅ **Invariant-Based**: 150+ security patterns across 6 languages
- ✅ **Comprehensive Coverage**: OWASP, NIST, PCI-DSS, CWE compliance
- ✅ **Command-Line Filtering**: Filter by standards and severity
- ✅ **Interactive Suppression**: Structured finding management
- ✅ **Ticket Integration**: Auto-create GitHub/Jira tickets
- ✅ **Drift Tracking**: Compare audits over time
- ✅ **Dependency Scanning**: Optional npm/pip/cargo/go vulnerability checks

### Supported Languages

- C/C++ (Memory safety, buffer overflows, concurrency)
- Go (Memory leaks, goroutines, GC pressure)
- Java (GC leaks, threading, deserialization)
- JavaScript/TypeScript (Prototype pollution, XSS, injection)
- Python (Injection, pickle, GIL issues)
- Rust (Unsafe blocks, FFI boundaries)

### Architecture

```
┌─────────────────┐
│  Subject Repo   │  (Read-only, never modified)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   SCA Agent     │  (Immutable, read-only installation)
│  /opt/sca       │
│   ├── bin/      │  CLI tools
│   ├── prompts/  │  AI prompts
│   ├── invariants│  Security rules
│   └── lib/      │  Shared functions
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Control Dir    │  (All outputs written here)
│  sec-ctrl/      │
│   ├── reports/  │  Audit reports
│   ├── state/    │  Tracking data
│   ├── config/   │  Exclusion rules
│   ├── OVERRIDE.md  │  Suppressions
│   └── SUGGESTIONS.md  │  Remediations
└─────────────────┘
```

---

## Installation

### Option 1: System-Wide Installation (Recommended for Production)

```bash
# Download and extract
curl -L https://github.com/your-org/sca/releases/latest/download/sca.tar.gz | tar xz

# Install to /opt/sca (requires sudo)
sudo mv sca /opt/sca

# Make read-only and immutable
sudo chown -R root:root /opt/sca
sudo chmod -R a-w /opt/sca

# Add to PATH
sudo ln -s /opt/sca/bin/sca /usr/local/bin/sca

# Verify installation
sca --help
```

### Option 2: User Installation (Development)

```bash
# Clone or extract to user directory
git clone https://github.com/your-org/sca.git ~/sca

# Make read-only
chmod -R a-w ~/sca

# Add to PATH in ~/.bashrc or ~/.zshrc
export PATH="$HOME/sca/bin:$PATH"

# Verify
sca --help
```

### Option 3: Docker Container

```dockerfile
FROM python:3.11-slim

# Install dependencies
RUN apt-get update && apt-get install -y \
    git jq curl sqlite3 && \
    rm -rf /var/lib/apt/lists/*

# Install SCA
COPY sca /opt/sca
RUN chmod -R a-w /opt/sca && \
    ln -s /opt/sca/bin/sca /usr/local/bin/sca

WORKDIR /workspace
ENTRYPOINT ["sca"]
```

```bash
# Build and run
docker build -t sca:latest .
docker run -v $(pwd):/workspace sca audit
```

### Prerequisites

- **Python 3.8+**: For CLI wrapper
- **Bash 4.0+**: For shell scripts
- **jq**: JSON parsing
- **git**: Repository fingerprinting
- **Claude Code CLI**: AI analysis (`claude` command)

Install dependencies:

```bash
# macOS
brew install jq git python3
brew install --cask claude

# Ubuntu/Debian
sudo apt-get install jq git python3
# Install Claude Code from: https://claude.com/claude-code

# Fedora/RHEL
sudo dnf install jq git python3
```

---

## Configuration

### 1. Environment Variables

Create a `.env` file or set system environment variables:

```bash
# Optional: Override default paths
export SEC_AUDIT_AGENT_HOME=/opt/sca
export SEC_CTRL_DIR=./sec-ctrl

# GitHub integration (for ticket creation)
export GITHUB_TOKEN=ghp_xxxxxxxxxxxxx
export GITHUB_REPO=mycompany/myapp

# Jira integration (for ticket creation)
export JIRA_URL=https://company.atlassian.net
export JIRA_USER=security-team@company.com
export JIRA_API_TOKEN=ATATTxxx...
export JIRA_PROJECT=SEC
export JIRA_ISSUE_TYPE=Bug

# Claude Code configuration
export CLAUDE_CODE_BIN=claude  # Path to claude CLI
```

### 2. Control Directory Structure

Initialize control directory (one-time setup):

```bash
cd /path/to/your/repo
sca bootstrap
```

This creates:

```
sec-ctrl/
├── README.md                  # Overview
├── OVERRIDE.md                # Suppressed findings
├── SUGGESTIONS.md             # Auto-generated fixes (regenerated each audit)
├── config/
│   ├── ignore.paths           # Files to exclude from analysis
│   └── local-overrides.md     # Custom security rules
├── state/
│   ├── last-run.txt           # Last audit timestamp
│   ├── repo-fingerprint.txt   # Git SHA
│   ├── scope-hash.txt         # Scope checksum
│   └── created-tickets.json   # Ticket tracker
├── reports/
│   ├── security-audit.latest.md     # Latest report (markdown)
│   ├── security-audit.latest.json   # Latest report (JSON)
│   ├── security-audit.TIMESTAMP.md  # Timestamped reports
│   └── deps/                  # Dependency scan results
└── cache/
    └── last-scope.txt         # Cached file list
```

### 3. Exclusion Patterns (`config/ignore.paths`)

Customize which files are excluded from analysis:

```bash
# Default exclusions (always applied)
sec-ctrl/
tools/sec-audit-agent/
.git/
node_modules/
dist/
build/
target/
vendor/
.venv/
__pycache__/

# Custom exclusions (add your own)
third_party/
external/
generated/
*.min.js
```

### 4. Custom Security Invariants

Add project-specific security rules:

```bash
# sec-ctrl/config/local-overrides.md
# Custom Security Invariants

## Project-Specific Rules

### CRITICAL: Custom Authentication Check
- Pattern: `auth_bypass_mode = True`
- Description: Authentication bypass mode must never be enabled in production code
- File: `src/auth/config.py`
- Reason: This is a debug-only flag that disables all authentication
```

### 5. Override Configuration

Define accepted risks and false positives in `sec-ctrl/OVERRIDE.md`:

```markdown
# Override: Test fixture API key (Test/Development Only)
# Category: Test/Development Only
# Finding: CRIT-001 - Hardcoded API key
# Reason: Mock credential for integration tests, never deployed to production
# Approved-By: Security Team
# Date: 2026-01-03
# Review-Date: 2027-01-03
tests/fixtures/mock_api_key.json
```

**Valid Categories**:
1. False Positive
2. Accepted Risk
3. Compensating Controls
4. Not Applicable
5. Planned for Future
6. Third-Party Code
7. Test/Development Only
8. Performance Trade-off
9. Legacy Compatibility
10. Custom Justification

---

## Commands Reference

### `sca audit` - Run Security Audit

Execute a comprehensive security audit of your repository.

**Syntax**:
```bash
sca audit [OPTIONS]
```

**Options**:

| Option | Description | Default |
|--------|-------------|---------|
| `--repo PATH` | Repository root | Current directory |
| `--ctrl-dir PATH` | Control directory | `<repo>/sec-ctrl` |
| `--agent-dir PATH` | SCA agent location | Auto-detect |
| `--readonly-agent` | Enforce agent immutability | Enabled |
| `--no-readonly-agent` | Disable immutability check | - |
| `--format md\|json\|both` | Output format | `both` |
| `--enable-deps` | Run dependency scanners | Disabled |
| `--incremental` | Skip if unchanged | Disabled |
| `--verbose` | Detailed logging | Disabled |

**Filtering Options**:

| Option | Description | Example |
|--------|-------------|---------|
| `--exclude-standards LIST` | Exclude standards | `OWASP,PCI-DSS` |
| `--include-standards LIST` | Include only these | `NIST,CWE` |
| `--severity-min LEVEL` | Minimum severity | `HIGH`, `CRITICAL` |
| `--exclude-severity LIST` | Exclude severities | `LOW,MEDIUM` |
| `--interactive` | Interactive suppression | - |

**Examples**:

```bash
# Basic audit
sca audit

# With dependency scanning
sca audit --enable-deps

# NIST Critical/High only
sca audit --include-standards NIST --severity-min HIGH

# Exclude OWASP findings
sca audit --exclude-standards OWASP

# Interactive mode (prompts to suppress findings)
sca audit --interactive

# Incremental mode (skip if unchanged)
sca audit --incremental

# Development mode (bypass readonly check)
sca audit --no-readonly-agent
```

**Exit Codes**:

| Code | Meaning | Action |
|------|---------|--------|
| 0 | No Critical/High findings | ✅ Pass |
| 2 | Critical/High findings exist | ❌ Fail (block merge) |
| 3 | Incomplete/config error | ⚠️ Warn |
| 4 | Agent not immutable | ❌ Fail (security violation) |
| 5 | Internal error | ⚠️ Warn |

### `sca scope` - View File Scope

Display which files will be analyzed.

**Syntax**:
```bash
sca scope [OPTIONS]
```

**Options**:

| Option | Description | Default |
|--------|-------------|---------|
| `--format paths\|stats` | Output mode | `paths` |

**Examples**:

```bash
# List all files in scope
sca scope

# Show statistics
sca scope --format stats
```

**Output**:

```
Scope Statistics:
  Total files: 620
  By language:
    C/C++: 45 files
    Go: 12 files
    Python: 8 files
  Excluded: 1,234 files (node_modules, vendor, etc.)
```

### `sca diff` - Compare Audits

Compare current audit with previous to track drift.

**Syntax**:
```bash
sca diff [OPTIONS]
```

**Options**:

| Option | Description | Default |
|--------|-------------|---------|
| `--format summary\|detailed` | Output format | `summary` |

**Examples**:

```bash
# Summary of changes
sca diff

# Detailed diff
sca diff --format detailed
```

**Output**:

```
Drift Summary
=============
Commit: abc1234 → def5678

Findings:
  Critical: 2 → 1 (Δ -1) ✓
  High:     5 → 3 (Δ -2) ✓
  Medium:   3 → 3 (Δ  0)
  Low:      1 → 2 (Δ +1)

New Findings:
  LOW-002: Verbose error messages in API responses

Resolved Findings:
  CRIT-001: JWT signature validation bypass (FIXED)
  HIGH-002: Unsafe strcpy() usage (FIXED)
```

### `sca bootstrap` - Initialize Control Directory

Create and initialize the `sec-ctrl/` directory structure.

**Syntax**:
```bash
sca bootstrap [OPTIONS]
```

**Options**:

| Option | Description |
|--------|-------------|
| `--force` | Overwrite existing ctrl-dir |

**Examples**:

```bash
# Initialize in current repo
sca bootstrap

# Force reinitialize
sca bootstrap --force

# Initialize in specific repo
sca bootstrap --repo /path/to/repo
```

### `sca suppress` - Interactive Suppression

Interactively review and suppress findings with structured justifications.

**Syntax**:
```bash
sca suppress [OPTIONS]
```

**Options**:

| Option | Description |
|--------|-------------|
| `--report PATH` | Audit report JSON (default: latest) |
| `--batch FILE` | Batch suppress from file |
| `--auto-commit` | Auto-commit OVERRIDE.md changes |
| `--non-interactive` | Batch mode only, no prompts |

**Examples**:

```bash
# Interactive suppression
sca suppress

# Batch mode from file
cat > suppressions.txt <<EOF
CRIT-001|7|Test fixture only
HIGH-002|1|False positive
MED-003|2|Accepted risk
EOF

sca suppress --batch suppressions.txt

# Auto-commit changes
sca suppress --auto-commit

# From specific report
sca suppress --report sec-ctrl/reports/security-audit.20260103T043000Z.json
```

**Interactive Workflow**:

```
Finding #1
─────────────────────────────────────────
ID:       CRIT-001
Title:    Incomplete JWT Signature Validation
File:     src/auth/session_token.c
Lines:    292-294
Severity: CRITICAL

Action: [s]uppress [k]eep [v]iew details [q]uit: s

Select justification category:
 1. False Positive
 2. Accepted Risk
 3. Compensating Controls
 4. Not Applicable
 5. Planned for Future
 6. Third-Party Code
 7. Test/Development Only
 8. Performance Trade-off
 9. Legacy Compatibility
10. Custom Justification

Select category [1-10]: 7
Additional reason/notes: Mock JWT for integration tests
Approved by (name/team): Security Team

✓ Suppressed
```

### `sca create-tickets` - Create GitHub/Jira Tickets

Automatically create issue tickets from audit findings.

**Syntax**:
```bash
sca create-tickets [OPTIONS]
```

**Options**:

| Option | Description | Default |
|--------|-------------|---------|
| `--platform github\|jira` | Ticket platform | `github` |
| `--report PATH` | Audit report JSON | Latest |
| `--env-file PATH` | Credentials file | `.env` |
| `--severity-min LEVEL` | Minimum severity | `HIGH` |
| `--dry-run` | Preview without creating | - |
| `--create-all` | Create even if exist | - |

**Examples**:

```bash
# Create GitHub issues (Critical/High)
sca create-tickets --platform github

# Create Jira tickets (all severities)
sca create-tickets --platform jira --severity-min LOW

# Dry run to preview
sca create-tickets --dry-run

# Force create duplicates
sca create-tickets --create-all

# Custom env file
sca create-tickets --platform jira --env-file ~/.sca-prod.env
```

**Prerequisites**:

- **GitHub**: `gh` CLI authenticated, or `GITHUB_TOKEN` in `.env`
- **Jira**: `JIRA_URL`, `JIRA_USER`, `JIRA_API_TOKEN`, `JIRA_PROJECT` in `.env`

---

## Security Invariants

SCA includes 150+ built-in security patterns across multiple domains:

### Global Invariants

**File**: `invariants/global.md`

- Injection attacks (SQL, command, LDAP, XPath, NoSQL, SSTI, XXE)
- Environment variable security
- SSL/TLS requirements
- Sensitive data on disk
- Authorization, input validation, SSRF, XSS, CSRF
- Deserialization vulnerabilities

### Cryptography

**Files**: `invariants/crypto/*.md`

- **secrets.md**: Key material exposure (20+ patterns, PQC migration)
- **WEAK_ALGORITHMS.md**: Deprecated crypto (DES, MD5, SHA-1, RSA<2048)
- **FPE.md**: Format-Preserving Encryption (FF1/FF3)

**Detects**:
- Hardcoded API keys, private keys, secrets
- Weak algorithms (DES, 3DES, RC4, MD5, SHA-1)
- Insecure modes (ECB)
- Key storage violations
- Missing TLS/certificate validation

### Data Protection

**Files**: `invariants/data-protection/*.md`

- **logging.md**: Sensitive data in logs (passwords, tokens, PII)
- **database.md**: Unencrypted DB connections, plaintext sensitive data

### Authentication & Access Control

**Files**: `invariants/authentication.md`, `invariants/access-control.md`

- Hard-coded credentials (CWE-798)
- Weak password requirements (NIST SP 800-63B)
- Insecure password storage (bcrypt, Argon2id)
- Missing MFA for privileged access
- Session management issues
- Broken authorization (IDOR, privilege escalation)

### Network Security

**File**: `invariants/network-security.md`

- HTTP instead of HTTPS
- TLS certificate validation bypass
- Weak TLS configuration (TLS 1.0/1.1)
- Server-Side Request Forgery (SSRF)
- Insecure server binding (0.0.0.0)
- Missing network timeouts

### API Security

**File**: `invariants/api-security.md`

Based on **OWASP API Security Top 10 (2023)**:

- API1: Broken Object Level Authorization
- API2: Broken Authentication
- API3: Broken Object Property Level Authorization
- API4: Unrestricted Resource Consumption
- API5: Broken Function Level Authorization
- API6: Unrestricted Access to Business Flows
- API7: Server Side Request Forgery
- API8: Security Misconfiguration
- API9: Improper Inventory Management
- API10: Unsafe Consumption of APIs

### Language-Specific

**C/C++** (`invariants/languages/c-cpp.md`):
- Memory safety (buffer/stack overflows, use-after-free)
- Uninitialized variables, integer overflows
- Format string bugs
- Concurrency (race conditions, deadlocks, TOCTOU)
- Banned functions (gets, strcpy, sprintf, system)

**Go** (`invariants/languages/go.md`):
- Error handling (check all errors, no panics)
- Memory leaks (goroutine, timer, HTTP body leaks)
- Concurrency (data races, mutex, channels, WaitGroup)
- GC pressure optimization

**Java** (`invariants/languages/java.md`):
- Injection (SQL, command, XXE, deserialization)
- GC memory leaks (listeners, ThreadLocal, classloader)
- Threading (race conditions, deadlocks)
- Resource management (try-with-resources)

**Python** (`invariants/languages/python.md`):
- Injection (SQL, command, pickle, YAML, template)
- Memory leaks (circular references, weakref)
- GIL & concurrency
- Timing attacks (hmac.compare_digest)

---

## Workflows

### 1. Initial Security Assessment

```bash
# 1. Initialize control directory
cd /path/to/your/repo
sca bootstrap

# 2. Run first audit
sca audit --verbose

# 3. Review findings
cat sec-ctrl/reports/security-audit.latest.md

# 4. Review remediation suggestions
cat sec-ctrl/SUGGESTIONS.md

# 5. Fix critical issues or suppress false positives
sca suppress --interactive

# 6. Re-audit to verify fixes
sca audit
```

### 2. Continuous Security Monitoring

```bash
# Weekly scheduled audit
0 9 * * 1 cd /srv/myapp && sca audit --incremental

# Fail if Critical/High found
sca audit --severity-min HIGH || exit 1
```

### 3. Pre-Commit Hook

```bash
# .git/hooks/pre-commit
#!/bin/bash
sca audit --incremental --exclude-standards OWASP --severity-min HIGH
if [ $? -eq 2 ]; then
    echo "❌ Security audit failed: Critical/High findings detected"
    echo "Review: sec-ctrl/reports/security-audit.latest.md"
    exit 1
fi
```

### 4. Pull Request Workflow

```bash
# On PR creation
sca audit --verbose

# Create GitHub issues for new findings
sca create-tickets --platform github --severity-min HIGH

# Add suppressions if false positives
sca suppress --interactive

# Commit suppressions
git add sec-ctrl/OVERRIDE.md sec-ctrl/state/created-tickets.json
git commit -m "chore: Security audit suppressions and tickets"
```

### 5. Compliance Audit

```bash
# NIST SP 800-53 compliance check
sca audit --include-standards NIST --severity-min MEDIUM

# PCI-DSS assessment
sca audit --include-standards PCI-DSS --severity-min HIGH

# Generate compliance report
sca audit --include-standards NIST > compliance-report.md
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Audit

on:
  pull_request:
  schedule:
    - cron: '0 9 * * 1'  # Weekly

jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install SCA
        run: |
          curl -L https://github.com/your-org/sca/releases/latest/download/sca.tar.gz | tar xz
          sudo mv sca /opt/sca
          sudo ln -s /opt/sca/bin/sca /usr/local/bin/sca

      - name: Run Security Audit
        run: sca audit --severity-min HIGH --verbose

      - name: Create GitHub Issues
        if: failure()
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: sca create-tickets --platform github --severity-min HIGH

      - name: Upload Report
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: sec-ctrl/reports/security-audit.latest.md
```

### GitLab CI

```yaml
security-audit:
  stage: security
  image: python:3.11
  before_script:
    - apt-get update && apt-get install -y jq git
    - curl -L https://github.com/your-org/sca/releases/latest/download/sca.tar.gz | tar xz
    - mv sca /opt/sca
    - ln -s /opt/sca/bin/sca /usr/local/bin/sca
  script:
    - sca audit --severity-min HIGH
  artifacts:
    when: always
    paths:
      - sec-ctrl/reports/
  allow_failure: false
```

### Jenkins

```groovy
pipeline {
    agent any

    stages {
        stage('Security Audit') {
            steps {
                sh 'sca audit --severity-min HIGH'
            }
        }

        stage('Create Jira Tickets') {
            when {
                expression { currentBuild.result == 'FAILURE' }
            }
            steps {
                withCredentials([
                    string(credentialsId: 'jira-api-token', variable: 'JIRA_API_TOKEN')
                ]) {
                    sh '''
                        export JIRA_URL=https://company.atlassian.net
                        export JIRA_USER=security-bot@company.com
                        export JIRA_PROJECT=SEC
                        sca create-tickets --platform jira --severity-min HIGH
                    '''
                }
            }
        }

        stage('Archive Report') {
            steps {
                archiveArtifacts artifacts: 'sec-ctrl/reports/*.md'
            }
        }
    }
}
```

---

## Troubleshooting

### Agent Immutability Errors

**Error**: `Agent dir is writable`

```bash
# Make agent read-only
sudo chmod -R a-w /opt/sca

# Or bypass for development
sca audit --no-readonly-agent
```

**Error**: `Agent checkout is dirty`

```bash
# Check git status
cd /opt/sca
git status

# Reset if needed
git reset --hard HEAD
git clean -fd
```

### Scope Issues

**Error**: `Scope: 0 files`

```bash
# Check exclusion rules
cat sec-ctrl/config/ignore.paths

# View scope
sca scope

# Debug
sca audit --verbose
```

### Finding Not Suppressed

**Problem**: Override not working

```bash
# Verify file path matches exactly
cat sec-ctrl/OVERRIDE.md
# Path must match: src/auth/session_token.c:292-294

# Re-run audit
sca audit
```

### Ticket Creation Fails

**GitHub**: `gh: command not found`

```bash
# Install GitHub CLI
brew install gh  # macOS
# Or: https://cli.github.com/

# Authenticate
gh auth login
```

**Jira**: `HTTP 401 Unauthorized`

```bash
# Verify credentials
cat .env | grep JIRA

# Test connection
curl -u "$JIRA_USER:$JIRA_API_TOKEN" "$JIRA_URL/rest/api/2/myself"
```

---

## Best Practices

### 1. Regular Audits

```bash
# Weekly scheduled audits
0 9 * * 1 cd /srv/app && sca audit --incremental
```

### 2. Review Overrides Quarterly

```bash
# Find expiring overrides
grep "Review-Date:" sec-ctrl/OVERRIDE.md | \
  awk -F": " '{print $2}' | sort
```

### 3. Commit Suppressions to Git

```bash
git add sec-ctrl/OVERRIDE.md
git commit -m "chore: Suppress test fixture findings (approved)"
```

### 4. Use Filtering for Targeted Checks

```bash
# PCI-DSS compliance check
sca audit --include-standards PCI-DSS --severity-min HIGH

# Internal security review
sca audit --exclude-standards OWASP --severity-min MEDIUM
```

### 5. Integrate with Issue Tracking

```bash
# Auto-create tickets for new findings
sca audit && sca create-tickets --platform github --severity-min HIGH
```

### 6. Document Accepted Risks

```markdown
# In OVERRIDE.md, always include:
# - Category (from predefined list)
# - Finding ID
# - Detailed reason
# - Approver name
# - Review date
```

### 7. Track Metrics

```bash
# Count findings over time
git log --pretty=format:"%h %ai" -- sec-ctrl/reports/ | \
  while read commit date; do
    git show $commit:sec-ctrl/reports/security-audit.latest.md | \
      grep "^##.*CRITICAL" | wc -l
  done
```

---

## Configuration Files Summary

| File | Purpose | When to Edit |
|------|---------|--------------|
| `.env` | Credentials for GitHub/Jira | Setup ticket integration |
| `sec-ctrl/config/ignore.paths` | File exclusions | Add project-specific excludes |
| `sec-ctrl/OVERRIDE.md` | Suppressed findings | Suppress false positives |
| `sec-ctrl/config/local-overrides.md` | Custom invariants | Add project-specific rules |

---

## Quick Reference Card

```bash
# Initial setup
sca bootstrap

# Run audit
sca audit

# Filter findings
sca audit --exclude-standards OWASP --severity-min HIGH

# Interactive suppression
sca audit --interactive

# Create tickets
sca create-tickets --platform github

# Compare audits
sca diff

# View scope
sca scope

# Help
sca --help
sca audit --help
```

---

## Additional Resources

- [FILTERING_GUIDE.md](FILTERING_GUIDE.md) - Filtering and suppression details
- [TICKET_CREATION.md](TICKET_CREATION.md) - GitHub/Jira integration
- [QUICKSTART_FILTERING.md](QUICKSTART_FILTERING.md) - Quick filtering reference
- [OVERRIDE_GUIDE.md](OVERRIDE_GUIDE.md) - Managing suppressions
- [USAGE.md](USAGE.md) - Basic usage guide

---

**Version**: 1.0
**Last Updated**: 2026-01-03
**Maintainer**: Security Team
