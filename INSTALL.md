# SCA Installation Guide

## Prerequisites
- Bash 4.0+
- Git
- Python 3.7+ (for CLI wrapper)
- Claude Code CLI or equivalent model runner

Optional (for dependency scanning):
- npm (for JavaScript projects)
- pip-audit (for Python projects)
- cargo-audit (for Rust projects)
- govulncheck (for Go projects)

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
sca --help
sca scope --repo /path/to/your/repo
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

### Initialize Control Directory
In your target repository:
```bash
cd /path/to/your/repo
sca bootstrap
```

This creates `sec-ctrl/` with default configuration.

### Configure Ignore Patterns
Edit `sec-ctrl/config/ignore.paths` to exclude paths from analysis:
```bash
vim sec-ctrl/config/ignore.paths
```

### Run First Audit
```bash
sca audit
```

Results will be in `sec-ctrl/reports/security-audit.latest.md`.

---

## CI/CD Integration

### GitHub Actions Example
```yaml
name: Security Audit

on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install SCA
        run: |
          curl -L https://github.com/your-org/sca/releases/latest/download/sca.tar.gz | tar xz
          sudo mv sca /opt/sca
          sudo chown -R root:root /opt/sca
          sudo chmod -R a-w /opt/sca
          sudo ln -s /opt/sca/bin/sca /usr/local/bin/sca

      - name: Run audit
        env:
          CLAUDE_CODE_BIN: claude  # Configure your model runner
        run: |
          sca audit --verbose

      - name: Upload report
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: sec-ctrl/reports/security-audit.latest.md

      - name: Fail on Critical/High findings
        run: exit 0  # Exit code 2 will fail the job
```

### Cron Example (Nightly Audits)
```bash
# Run nightly audit and email results
0 2 * * * /opt/sca/bin/sca audit --repo /srv/myapp && mail -s "Security Audit OK" team@example.com < /srv/myapp/sec-ctrl/reports/security-audit.latest.md
```

---

## Troubleshooting

### "Agent dir is writable" (Exit 4)
Ensure agent directory is read-only:
```bash
sudo chmod -R a-w /opt/sca
```

### "Could not resolve agent dir" (Exit 3)
Set environment variable:
```bash
export SEC_AUDIT_AGENT_HOME=/path/to/sca
```

### Model runner not found
Set `CLAUDE_CODE_BIN`:
```bash
export CLAUDE_CODE_BIN=/path/to/claude
```

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
