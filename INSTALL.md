# SCA Installation Guide

## Prerequisites

**Required:**
- **Claude Code CLI** - [Installation guide](https://claude.com/claude-code)
- Bash 4.0+
- Git
- Python 3.7+ (for wrapper scripts)

**How SCA Works:**
SCA is a collection of security invariants (markdown files) and wrapper scripts that Claude Code uses to perform AI-powered security audits. The execution flow is:

```
User/Cron → bin/sca (Python) → bin/sec-audit.sh (Bash) → claude code < prompt.txt → report.md
```

**Components:**
- `bin/sca` - Python CLI wrapper (parses arguments, dispatches to shell scripts)
- `bin/sec-audit.sh` - Bash orchestrator (constructs prompt from invariants + file list)
- `claude code` - Claude Code CLI (AI analysis with filesystem access)
- `/opt/sca/invariants/` - 150+ security patterns (markdown)
- `/opt/sca/prompts/` - Runbook, report template, system guidance

**Prompt Construction:**
The wrapper builds a prompt file containing:
1. Runbook (RUNBOOK.md) - Step-by-step analysis instructions
2. Report template (REPORT_TEMPLATE.md) - Output format
3. Invariants (bundled from invariants/*.md) - Security patterns
4. File list (from repo-scope.sh) - What to analyze
5. Overrides (OVERRIDE.md) - Findings to suppress
6. Filtering instructions (if --exclude-standards, --severity-min, etc.)

**Execution:**
```bash
claude code < /tmp/prompt_file.txt > sec-ctrl/reports/security-audit.md
```

Claude Code provides:
- AI reasoning and analysis
- Filesystem access to read your repository
- API integration with Anthropic

## Installation Methods

### Method A: External Install (Recommended for Production)

**1. Clone or download SCA:**
```bash
git clone https://github.com/your-org/sca.git /tmp/sca
cd /tmp/sca
```

**2. Install to /opt/sca (requires sudo):**
```bash
sudo make install PREFIX=/opt/sca
```

**3. Make agent read-only (CRITICAL for immutability):**
```bash
sudo chown -R root:root /opt/sca
sudo chmod -R a-w /opt/sca
```

**4. Add to PATH:**
```bash
sudo ln -s /opt/sca/bin/sca /usr/local/bin/sca
```

**5. Verify installation:**
```bash
# Check SCA wrapper exists
sca --help

# Test Claude Code integration
cd /path/to/test/repo
claude-code
> "Use the SCA invariants in /opt/sca/invariants to audit this repository"
```

---

### Method B: User-local Install (No sudo required)

**1. Install to ~/.local/sca:**
```bash
make install-user
```

**2. Add to PATH (add to ~/.bashrc or ~/.zshrc):**
```bash
export PATH="$HOME/.local/sca/bin:$PATH"
```

**3. Make read-only:**
```bash
chmod -R a-w ~/.local/sca
```

**4. Verify:**
```bash
sca --help
```

---

### Method C: Git Submodule (Repo-local)

**1. Add SCA as submodule in target repo:**
```bash
cd /path/to/your/repo
git submodule add https://github.com/your-org/sca.git tools/sec-audit-agent
git submodule update --init
```

**2. Pin to specific version (recommended):**
```bash
cd tools/sec-audit-agent
git checkout v1.0.0
cd ../..
git add tools/sec-audit-agent
git commit -m "Pin SCA to v1.0.0"
```

**3. Make read-only:**
```bash
chmod -R a-w tools/sec-audit-agent
```

**4. Run from repo root:**
```bash
tools/sec-audit-agent/bin/sca audit
```

---

## Post-Installation Setup

### Running Your First Audit

**Option 1: Interactive with Claude Code (Recommended for learning)**
```bash
cd /path/to/your/repo
claude-code

# In Claude Code session:
> "Please run a security audit using the SCA invariants in /opt/sca/invariants/.
   Create a sec-ctrl/ directory for reports and follow the workflow in /opt/sca/prompts/"
```

**Option 2: Automated with wrapper script**
```bash
# The sca wrapper calls claude with the right prompt
cd /path/to/your/repo
/opt/sca/bin/sca audit

# Or if symlinked to PATH:
sca audit
```

**What happens:**
1. SCA wrapper script constructs prompt for Claude Code
2. Claude Code reads repository files
3. Applies security invariants from `/opt/sca/invariants/`
4. Writes findings to `sec-ctrl/reports/`

Results will be in `sec-ctrl/reports/security-audit.latest.md`.

### Configure Ignore Patterns (Optional)
After first run, edit `sec-ctrl/config/ignore.paths` to exclude paths:
```bash
vim sec-ctrl/config/ignore.paths
```

---

## CI/CD Integration

**Important**: CI/CD environments need Claude Code CLI and Anthropic API key.

### GitHub Actions Example
```yaml
name: Security Audit

on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install Claude Code
        run: |
          # Install Claude Code CLI
          curl -L https://claude.com/download/cli/linux | tar xz
          sudo mv claude /usr/local/bin/claude

      - name: Install SCA
        run: |
          git clone https://github.com/your-org/sca.git /tmp/sca
          sudo mv /tmp/sca /opt/sca
          sudo chown -R root:root /opt/sca
          sudo chmod -R a-w /opt/sca
          sudo ln -s /opt/sca/bin/sca /usr/local/bin/sca

      - name: Run audit
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          sca audit --verbose

      - name: Upload report
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: sec-ctrl/reports/security-audit.latest.md

      - name: Fail on Critical/High findings
        run: |
          # sca audit exits with code 2 if critical/high findings exist
          # GitHub Actions will fail the job automatically
```

### Cron Example (Nightly Audits)
```bash
# /etc/cron.d/sca-nightly-audit
# Run nightly audit at 2 AM and email results

0 2 * * * user ANTHROPIC_API_KEY=your-key /opt/sca/bin/sca audit --repo /srv/myapp && \
  mail -s "Security Audit - No Issues" team@example.com < /srv/myapp/sec-ctrl/reports/security-audit.latest.md || \
  mail -s "Security Audit - CRITICAL FINDINGS" team@example.com < /srv/myapp/sec-ctrl/reports/security-audit.latest.md
```

**Cron Setup Notes:**
- Set `ANTHROPIC_API_KEY` environment variable
- Ensure `claude` CLI is in PATH or set `CLAUDE_CODE_BIN`
- Test with `claude --version` before scheduling

---

## Troubleshooting

### Claude Code not found
**Error**: `claude: command not found`

**Solution**: Install Claude Code CLI or set path:
```bash
# Check if installed
which claude

# Set custom path if needed
export CLAUDE_CODE_BIN=/path/to/claude
```

### API Key Issues
**Error**: `Anthropic API key not found`

**Solution**: Set environment variable:
```bash
export ANTHROPIC_API_KEY=your-api-key-here

# For cron jobs, add to crontab:
ANTHROPIC_API_KEY=your-key
0 2 * * * /opt/sca/bin/sca audit --repo /srv/myapp
```

### "Agent dir is writable" (Exit 4)
Ensure SCA directory is read-only:
```bash
sudo chmod -R a-w /opt/sca
```

### "Could not resolve agent dir" (Exit 3)
Set environment variable:
```bash
export SEC_AUDIT_AGENT_HOME=/opt/sca
```

### Claude Code rate limiting
If you hit API rate limits during audits:
- Reduce repository size with `sec-ctrl/config/ignore.paths`
- Run audits less frequently
- Split large repos into smaller modules

---

## Uninstallation

### External install:
```bash
sudo rm -rf /opt/sca
sudo rm /usr/local/bin/sca
```

### User install:
```bash
rm -rf ~/.local/sca
# Remove from PATH in ~/.bashrc
```

### Submodule:
```bash
git submodule deinit tools/sec-audit-agent
git rm tools/sec-audit-agent
```
