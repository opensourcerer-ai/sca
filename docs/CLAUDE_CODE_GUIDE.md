# Claude Code Integration Guide

## Table of Contents

1. [Overview](#overview)
2. [Installation](#installation)
3. [Authentication](#authentication)
4. [Usage Patterns](#usage-patterns)
5. [Troubleshooting](#troubleshooting)
6. [Performance Considerations](#performance-considerations)
7. [Security Best Practices](#security-best-practices)

---

## Overview

### Why SCA Requires Claude Code

**SCA (Security Control Agent)** is not a standalone tool. It's a collection of security invariants (150+ markdown files) and orchestration scripts that leverage **Claude Code CLI** to perform AI-powered security analysis.

**Architecture**:
```
┌─────────────┐      ┌──────────────┐      ┌───────────────┐
│   sca CLI   │─────▶│ sec-audit.sh │─────▶│  Claude Code  │
│  (wrapper)  │      │ (orchestrator)│      │  (AI engine)  │
└─────────────┘      └──────────────┘      └───────┬───────┘
                                                    │
                                                    ▼
                                            ┌───────────────┐
                                            │ Anthropic API │
                                            │  (Claude AI)  │
                                            └───────────────┘
                                                    │
                                                    ▼
                                            ┌───────────────┐
                                            │ sec-ctrl/     │
                                            │ reports/      │
                                            └───────────────┘
```

**What Claude Code Provides**:
- **AI-powered reasoning**: Applies security invariants using Claude Sonnet/Opus models
- **Filesystem access**: Reads your repository files securely
- **API integration**: Handles authentication with Anthropic API
- **Tool execution**: Provides tools for file reading, grepping, code analysis

**What SCA Provides**:
- **Security knowledge**: 150+ invariants covering OWASP, NIST, PCI-DSS, CWE
- **Orchestration**: Constructs prompts, manages state, generates reports
- **Workflow**: Override management, drift tracking, ticket creation

**Execution Flow**:
```bash
# User runs:
sca audit

# Which executes:
bin/sca → sec-audit.sh → claude code < prompt.txt > report.md

# Prompt contains:
# - Runbook (analysis instructions)
# - Report template (output format)
# - Invariants (security patterns)
# - File list (what to analyze)
# - Overrides (findings to suppress)
# - Filters (severity, standards)
```

---

## Installation

### Prerequisites

- **Operating System**: Linux, macOS, or Windows (WSL2)
- **Python**: 3.7 or higher
- **Bash**: 4.0 or higher
- **Internet access**: Required for Claude API calls

### Step 1: Install Claude Code CLI

#### Option A: Official Installer (Recommended)

**Linux / macOS**:
```bash
# Download and install
curl -fsSL https://claude.com/download/cli/linux | bash

# Verify installation
claude --version
```

**macOS via Homebrew** (if available):
```bash
brew install anthropic/tap/claude-code
claude --version
```

**Windows (WSL2)**:
```bash
# Same as Linux
curl -fsSL https://claude.com/download/cli/linux | bash
claude --version
```

#### Option B: Manual Installation

Visit [https://claude.com/claude-code](https://claude.com/claude-code) and follow platform-specific instructions.

#### Option C: From Source (Advanced)

```bash
git clone https://github.com/anthropics/claude-code.git
cd claude-code
make install PREFIX=$HOME/.local
export PATH="$HOME/.local/bin:$PATH"
```

### Step 2: Verify Installation

Run the diagnostic command:
```bash
sca diagnose
```

**Expected output**:
```
Core Dependencies:
------------------
✓ Python 3.11.5 (required: 3.7+)
✓ Bash 5.2.15 (required: 4.0+)
✓ jq installed: jq-1.6
✓ git installed: git version 2.39.2

Claude Code Integration:
------------------------
✓ Claude Code CLI installed: claude 1.2.3
  Binary: /usr/local/bin/claude
⚠ ANTHROPIC_API_KEY not set (optional)
  Claude Code will prompt for API key when running sca audit
```

**Troubleshooting**:
- If `✗ Claude Code CLI not found`, revisit installation steps
- If `✗ Python 3 not found`, install Python 3.7+
- If `✗ Bash version unknown`, check Bash version: `bash --version`

---

## Authentication

### How Claude Code Handles API Keys

**Important**: Claude Code manages API authentication automatically. SCA does **not** require you to manually set `ANTHROPIC_API_KEY` (though you can for automation).

### Interactive Mode (First-Time Setup)

When you run `sca audit` for the first time:

1. **Claude Code will prompt you**:
   ```
   Welcome to Claude Code!

   To use Claude Code, you'll need an Anthropic API key.
   You can get one at: https://console.anthropic.com/settings/keys

   Enter your API key: [paste here]
   ```

2. **Enter your API key**: Paste the key and press Enter

3. **Claude Code stores it securely**:
   - Linux/macOS: `~/.config/claude/credentials`
   - Windows: `%APPDATA%\claude\credentials`

4. **Subsequent runs**: No prompt needed, uses stored credentials

### Non-Interactive Mode (Automation / CI/CD)

For cron jobs or CI/CD pipelines, set the environment variable:

```bash
export ANTHROPIC_API_KEY="sk-ant-api03-..."
```

#### Persistent Configuration

**Linux/macOS** (`~/.bashrc` or `~/.zshrc`):
```bash
# Anthropic API key for SCA audits
export ANTHROPIC_API_KEY="sk-ant-api03-YOUR-KEY-HERE"
```

**Cron job**:
```bash
# /etc/cron.d/sca-nightly
ANTHROPIC_API_KEY=sk-ant-api03-YOUR-KEY-HERE
0 2 * * * user /opt/sca/bin/sca audit --repo /srv/myapp
```

**GitHub Actions**:
```yaml
- name: Run SCA audit
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
  run: sca audit --verbose
```

### Obtaining an API Key

1. **Sign up**: Go to [https://console.anthropic.com/](https://console.anthropic.com/)
2. **Navigate to API Keys**: Settings → API Keys
3. **Create a new key**: Click "Create Key"
4. **Copy the key**: It starts with `sk-ant-api03-...`
5. **Secure storage**: Store in password manager or secrets vault

**Security Note**: Never commit API keys to Git. Add to `.gitignore`:
```bash
echo ".env" >> .gitignore
echo "*.key" >> .gitignore
```

### API Key Permissions

Claude Code requires:
- **Read access**: To analyze repository files
- **API access**: To call Claude models (Sonnet 3.5, Opus 3)

**No write permissions needed**: SCA only reads your code, never modifies it.

---

## Usage Patterns

### Pattern 1: Interactive Analysis (Learning / Exploration)

**Best for**: Learning SCA, exploring findings, iterative refinement

```bash
cd /path/to/your/repo

# Launch Claude Code
claude-code

# In the Claude Code session:
> "Please run a security audit using the SCA invariants in /opt/sca/invariants/.
   Create a sec-ctrl/ directory for reports and follow the workflow in /opt/sca/prompts/RUNBOOK.md"
```

**Advantages**:
- Real-time interaction with Claude
- Can ask follow-up questions
- Iterate on findings immediately
- Learn how SCA analyzes code

**Disadvantages**:
- Manual process
- Not suitable for automation

### Pattern 2: Command-Line Automation (Cron / CI/CD)

**Best for**: Scheduled audits, CI/CD pipelines, batch processing

```bash
# One-time audit
sca audit

# Verbose output for debugging
sca audit --verbose

# Enable dependency scanning
sca audit --enable-deps

# Skip if repository unchanged (incremental mode)
sca audit --incremental

# Filter by severity
sca audit --severity-min HIGH

# Exclude standards
sca audit --exclude-standards OWASP,NIST
```

**Advantages**:
- Fully automated
- Deterministic exit codes (CI/CD friendly)
- No human interaction required
- Repeatable and consistent

**Disadvantages**:
- Less interactive
- Can't ask follow-up questions during analysis

### Pattern 3: Scheduled Audits (Cron)

**Example**: Nightly audits with email notifications

```bash
# /etc/cron.d/sca-nightly-audit
ANTHROPIC_API_KEY=sk-ant-api03-YOUR-KEY
MAILTO=security-team@example.com

# Run at 2 AM daily
0 2 * * * user /opt/sca/bin/sca audit --repo /srv/myapp --verbose >> /var/log/sca-audit.log 2>&1 || echo "CRITICAL FINDINGS DETECTED"
```

**Best practices**:
- Set `ANTHROPIC_API_KEY` in cron environment
- Redirect output to log file
- Use email notifications for failures
- Run during low-traffic hours (API cost optimization)

### Pattern 4: CI/CD Integration (GitHub Actions)

**Example**: Fail PR on Critical/High findings

```yaml
name: Security Audit

on:
  pull_request:
    branches: [main, develop]
  push:
    branches: [main]

jobs:
  security-audit:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v3

      - name: Install Claude Code
        run: |
          curl -fsSL https://claude.com/download/cli/linux | bash
          echo "$HOME/.local/bin" >> $GITHUB_PATH

      - name: Install SCA
        run: |
          git clone https://github.com/opensourcerer-ai/sca.git /tmp/sca
          sudo mv /tmp/sca /opt/sca
          sudo chown -R root:root /opt/sca
          sudo chmod -R a-w /opt/sca
          sudo ln -s /opt/sca/bin/sca /usr/local/bin/sca

      - name: Run security audit
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          sca audit --verbose
        # Exit code 2 will fail the job if critical/high findings exist

      - name: Upload report
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: security-audit-report
          path: sec-ctrl/reports/security-audit.latest.md

      - name: Upload suggestions
        if: failure()
        uses: actions/upload-artifact@v3
        with:
          name: remediation-suggestions
          path: sec-ctrl/SUGGESTIONS.md
```

**Exit code behavior**:
- **0**: No critical/high findings → CI passes ✅
- **2**: Critical/high findings exist → CI fails ❌
- **3**: Audit incomplete (config error) → CI warns ⚠️
- **4**: Agent not immutable → CI fails ❌
- **5**: Internal error → CI warns ⚠️

### Pattern 5: Pre-Commit Hook (Developer Workflow)

**Example**: Run audit before committing sensitive changes

```bash
# .git/hooks/pre-commit
#!/bin/bash

echo "Running security audit on staged files..."

# Run audit on current working directory
sca audit --incremental --severity-min HIGH

EXIT_CODE=$?

if [ $EXIT_CODE -eq 2 ]; then
  echo "❌ Security audit found critical/high findings."
  echo "Review sec-ctrl/reports/security-audit.latest.md before committing."
  exit 1
elif [ $EXIT_CODE -ne 0 ]; then
  echo "⚠️  Security audit encountered an issue (exit code $EXIT_CODE)."
  echo "Allowing commit, but review sec-ctrl/reports/ before pushing."
fi

exit 0
```

**Make executable**:
```bash
chmod +x .git/hooks/pre-commit
```

---

## Troubleshooting

### Issue 1: "Claude Code CLI not found"

**Error**:
```
✗ Claude Code CLI not found (REQUIRED)
  Install: https://claude.com/claude-code
```

**Solutions**:

1. **Verify installation**:
   ```bash
   which claude
   # Should output: /usr/local/bin/claude or similar
   ```

2. **Check PATH**:
   ```bash
   echo $PATH
   # Ensure it includes /usr/local/bin or ~/.local/bin
   ```

3. **Set custom binary location**:
   ```bash
   export CLAUDE_CODE_BIN=/path/to/claude
   sca diagnose
   ```

4. **Reinstall Claude Code**:
   ```bash
   curl -fsSL https://claude.com/download/cli/linux | bash
   ```

### Issue 2: "API key not set" (Interactive Mode)

**Error**:
```
⚠ ANTHROPIC_API_KEY not set (optional)
  Claude Code will prompt for API key when running sca audit
```

**This is normal** for interactive usage. Claude Code will prompt you when needed.

**If you want to suppress the prompt**, set the key:
```bash
export ANTHROPIC_API_KEY="sk-ant-api03-YOUR-KEY"
```

### Issue 3: "API request failed" or "Rate limit exceeded"

**Error**:
```
Error: Anthropic API request failed: 429 Rate Limit Exceeded
```

**Causes**:
- Too many API calls in short period
- Repository too large (100K+ files analyzed)
- Burst of concurrent audits

**Solutions**:

1. **Reduce scope** with `sec-ctrl/config/ignore.paths`:
   ```bash
   # Add to ignore.paths
   node_modules/
   vendor/
   .venv/
   dist/
   build/
   *.min.js
   *.bundle.js
   ```

2. **Use incremental mode**:
   ```bash
   sca audit --incremental
   # Skips audit if repository hasn't changed
   ```

3. **Retry with exponential backoff** (in scripts):
   ```bash
   for i in {1..3}; do
     sca audit && break
     sleep $((2 ** i))
   done
   ```

4. **Contact Anthropic support** for rate limit increases (enterprise customers)

### Issue 4: "Agent directory is writable" (Exit 4)

**Error**:
```
[ERROR] Agent directory is writable (security violation)
```

**Cause**: SCA requires `/opt/sca` to be read-only (immutability guarantee)

**Solution**:
```bash
sudo chmod -R a-w /opt/sca
sca diagnose
# Should show: ✓ Agent directory is read-only
```

### Issue 5: "Could not resolve agent directory" (Exit 3)

**Error**:
```
[ERROR] Could not resolve agent directory
```

**Solutions**:

1. **Set environment variable**:
   ```bash
   export SEC_AUDIT_AGENT_HOME=/opt/sca
   sca audit
   ```

2. **Use --agent-dir flag**:
   ```bash
   sca audit --agent-dir /opt/sca
   ```

3. **Check installation**:
   ```bash
   ls -la /opt/sca
   # Should show: bin/ invariants/ prompts/ lib/ etc.
   ```

### Issue 6: "Audit hangs or takes too long"

**Symptoms**: `sca audit` runs for hours without completing

**Causes**:
- Very large repository (100K+ files)
- Complex codebase with many invariant matches
- Network issues (slow API responses)

**Solutions**:

1. **Enable verbose mode** to see progress:
   ```bash
   sca audit --verbose
   ```

2. **Reduce scope** with ignore.paths:
   ```bash
   # Add large directories to sec-ctrl/config/ignore.paths
   third_party/
   generated/
   ```

3. **Check network connectivity**:
   ```bash
   ping api.anthropic.com
   curl -I https://api.anthropic.com/v1/messages
   ```

4. **Increase timeout** (if using scripted retry logic):
   ```bash
   timeout 30m sca audit
   ```

### Issue 7: "Findings seem incorrect or incomplete"

**Symptoms**: Report has false positives or misses known vulnerabilities

**Remember**: SCA uses AI for analysis, which is probabilistic, not deterministic. Results may vary.

**Best practices**:

1. **Use OVERRIDE.md** for false positives:
   ```bash
   vim sec-ctrl/OVERRIDE.md
   # Document why finding is not a real issue
   ```

2. **Refine invariants** (advanced users):
   ```bash
   # Add custom local overrides
   vim sec-ctrl/invariants/local-overrides.md.example
   ```

3. **Report missing patterns**:
   - Open issue: https://github.com/opensourcerer-ai/sca/issues
   - Include example code that should be flagged

4. **Try different models** (future feature):
   ```bash
   # Currently uses default model (Sonnet 3.5)
   # Future: --model opus-3 for deeper analysis
   ```

---

## Performance Considerations

### Repository Size Limits

**Tested scale**:
- ✅ Small repos (< 1K files): 2-5 minutes
- ✅ Medium repos (1K-10K files): 10-30 minutes
- ⚠️ Large repos (10K-50K files): 30-90 minutes
- ❌ Very large repos (50K+ files): May timeout or hit rate limits

**Recommendations**:
- Use `sec-ctrl/config/ignore.paths` to exclude generated code, dependencies, build artifacts
- Run audits during low-traffic hours to avoid rate limits
- Consider splitting monorepos into smaller modules

### API Cost Optimization

**Claude API pricing** (as of 2024):
- Claude Sonnet 3.5: ~$3-15 per 1M input tokens, ~$15-75 per 1M output tokens
- Claude Opus 3: ~$15-75 per 1M input tokens, ~$75-225 per 1M output tokens

**Typical audit costs** (10K file repo):
- Small codebase (1K files): $0.50 - $2
- Medium codebase (10K files): $5 - $20
- Large codebase (50K files): $25 - $100

**Cost reduction strategies**:

1. **Use incremental mode**:
   ```bash
   sca audit --incremental
   # Skips audit if repository unchanged (scope hash check)
   ```

2. **Exclude non-security-critical code**:
   ```bash
   # sec-ctrl/config/ignore.paths
   tests/
   docs/
   examples/
   scripts/
   ```

3. **Run audits less frequently**:
   ```bash
   # Weekly instead of nightly
   0 2 * * 1 /opt/sca/bin/sca audit --repo /srv/myapp
   ```

4. **Filter by severity in regular runs**:
   ```bash
   # Daily: only critical/high
   sca audit --severity-min HIGH

   # Weekly: full audit
   sca audit
   ```

### Network Requirements

**Bandwidth**:
- Upload: ~1-10 MB per audit (compressed prompts)
- Download: ~100 KB - 1 MB per audit (reports)

**Latency**:
- API calls: 2-10 seconds per request
- Total audit time: Scales with repo size and complexity

**Offline usage**: Not supported (requires API access)

---

## Security Best Practices

### 1. API Key Protection

**Do**:
- ✅ Store in environment variables or secure credential stores
- ✅ Use GitHub Secrets, HashiCorp Vault, AWS Secrets Manager
- ✅ Rotate keys periodically (every 90 days recommended)
- ✅ Use separate keys for dev/staging/production
- ✅ Restrict key permissions (if Anthropic supports RBAC)

**Don't**:
- ❌ Commit API keys to Git
- ❌ Share keys via email or Slack
- ❌ Hardcode in scripts or config files
- ❌ Use the same key across teams/environments

**Example**: Using AWS Secrets Manager
```bash
# Store key
aws secretsmanager create-secret \
  --name sca-anthropic-api-key \
  --secret-string "sk-ant-api03-YOUR-KEY"

# Retrieve in script
export ANTHROPIC_API_KEY=$(aws secretsmanager get-secret-value \
  --secret-id sca-anthropic-api-key \
  --query SecretString \
  --output text)

sca audit
```

### 2. Agent Immutability

**Why it matters**: If an attacker can modify `/opt/sca/invariants/`, they can bypass security checks.

**Enforcement**:
```bash
# Make read-only
sudo chown -R root:root /opt/sca
sudo chmod -R a-w /opt/sca

# Verify
sca diagnose
# Should show: ✓ Agent directory is read-only
```

**Exit code 4**: SCA will refuse to run if agent directory is writable.

### 3. Report Confidentiality

**Reports may contain sensitive information**:
- File paths revealing architecture
- Code snippets showing implementation details
- Configuration values
- Internal API endpoints

**Best practices**:
- ❌ Do NOT commit `sec-ctrl/reports/` to public Git repos
- ✅ Add to `.gitignore`:
  ```bash
  echo "sec-ctrl/reports/" >> .gitignore
  echo "sec-ctrl/cache/" >> .gitignore
  ```
- ✅ Store reports in secure locations (internal wikis, S3 with encryption)
- ✅ Restrict access to security team only

### 4. Override Governance

**OVERRIDE.md should be auditable**:
- ✅ Commit OVERRIDE.md to Git (tracks suppression history)
- ✅ Require approval for overrides (PR review)
- ✅ Include justification, approver, review date
- ✅ Quarterly review of overrides (remove stale ones)

**Example override entry**:
```markdown
# Override: Test API key in fixture
# File: tests/fixtures/mock_api.json
# Reason: Mock credential for unit tests, not used in production
# Approved: Security Team, 2024-01-15
# Review: 2025-01-15
tests/fixtures/mock_api.json
```

### 5. Least Privilege (SCA Execution)

**Recommendations**:
- Run SCA as non-root user
- Use dedicated service account for cron jobs
- Limit filesystem access to repository and `/opt/sca`
- Use containers with read-only mounts (future feature)

**Example**: Dedicated user
```bash
# Create sca user
sudo useradd -r -s /bin/bash sca-audit

# Grant read access to repos
sudo setfacl -R -m u:sca-audit:rx /srv/repos

# Run as sca-audit user
sudo -u sca-audit sca audit --repo /srv/repos/myapp
```

### 6. Audit Logging

**Track SCA execution**:
- Who ran audits
- When audits were run
- What repositories were analyzed
- Exit codes and findings

**Example**: Centralized logging
```bash
# /etc/cron.d/sca-audit-with-logging
ANTHROPIC_API_KEY=sk-ant-api03-KEY

0 2 * * * sca-audit /opt/sca/bin/sca audit --repo /srv/myapp 2>&1 | \
  logger -t sca-audit -p local0.info
```

**Splunk/ELK query**:
```
sourcetype=sca-audit severity=CRITICAL
```

---

## Next Steps

1. **Install Claude Code**: Follow [Installation](#installation) section
2. **Run diagnostics**: `sca diagnose` to verify setup
3. **First audit**: `sca audit` on a test repository
4. **Review reports**: Check `sec-ctrl/reports/security-audit.latest.md`
5. **Configure CI/CD**: Integrate with GitHub Actions or GitLab CI
6. **Schedule audits**: Set up cron jobs for regular scanning

**Further Reading**:
- [Usage Guide](USAGE.md) - Workflows and best practices
- [CLI Reference](../CLI.md) - Complete command documentation
- [GA Roadmap](GA_ROADMAP.md) - Upcoming features
- [Architecture](../ARCHITECTURE.md) - System design details

**Support**:
- GitHub Issues: https://github.com/opensourcerer-ai/sca/issues
- Documentation: https://github.com/opensourcerer-ai/sca/tree/master/docs
