# SCA Usage Guide

## Quick Reference

```bash
# Initialize control directory
sca bootstrap

# Run security audit
sca audit

# Run with dependency scanning
sca audit --enable-deps

# View file scope (what will be analyzed)
sca scope

# Compare with previous audit (drift)
sca diff

# Verbose mode
sca audit --verbose
```

## Control Directory Structure

After `sca bootstrap`, your repository will have:

```
sec-ctrl/
├── README.md                           # Overview
├── OVERRIDE.md                         # Accepted risks (you maintain)
├── SUGGESTIONS.md                      # Auto-generated fixes (regenerated)
├── config/
│   └── ignore.paths                    # Files to exclude from analysis
├── invariants/
│   └── local-overrides.md.example      # Custom security rules
├── state/
│   ├── last-run.txt                    # Last audit timestamp
│   ├── repo-fingerprint.txt            # Git SHA
│   └── scope-hash.txt                  # Scope checksum
├── reports/
│   ├── security-audit.latest.md        # Most recent report
│   ├── security-audit.TIMESTAMP.md     # Timestamped reports
│   └── deps/                           # Dependency scan results
└── cache/
    └── last-scope.txt                  # Cached file list
```

## Workflow: First Audit

### 1. Bootstrap
```bash
cd /path/to/your/repo
sca bootstrap
```

This creates `sec-ctrl/` with default configuration.

### 2. Customize Scope (Optional)
Edit `sec-ctrl/config/ignore.paths` to exclude additional paths:
```bash
# Add custom exclusions
echo "vendor/" >> sec-ctrl/config/ignore.paths
echo "third_party/" >> sec-ctrl/config/ignore.paths
```

### 3. Run Audit
```bash
sca audit
```

### 4. Review Report
```bash
less sec-ctrl/reports/security-audit.latest.md
```

### 5. Review Suggestions
```bash
cat sec-ctrl/SUGGESTIONS.md
```

Contains concrete fixes for each finding.

## Managing Findings

### Option 1: Fix Issues
Implement remediations from SUGGESTIONS.md, then re-audit:
```bash
# Fix code
git commit -m "Fix: Remove hardcoded API key"

# Verify fix
sca audit
```

### Option 2: Accept Risk (Override)
If a finding is an accepted risk or false positive:

1. **Edit OVERRIDE.md**:
```bash
vim sec-ctrl/OVERRIDE.md
```

2. **Add override entry**:
```markdown
# Override: Mock API key in test fixture
# File: tests/fixtures/mock_api.json
# Reason: Test-only credential, not used in production
# Approved: Security Team, 2024-01-15
# Review: 2025-01-15
tests/fixtures/mock_api.json
```

3. **Re-run audit**:
```bash
sca audit
```

The finding will no longer appear in reports or SUGGESTIONS.md.

## Drift Tracking

### Compare Audits
```bash
sca diff
```

Output:
```
Drift Summary
=============
Commit: abc1234 → def5678

Findings:
  Critical: 2 → 1 (Δ -1)
  High:     5 → 3 (Δ -2)
```

### Detailed Diff
```bash
sca diff --format detailed
```

Shows line-by-line diff of reports.

## Dependency Scanning

Enable optional dependency scanners:
```bash
sca audit --enable-deps
```

Runs:
- `npm audit` (if package.json exists)
- `pip-audit` (if requirements.txt exists)
- `cargo audit` (if Cargo.toml exists)
- `govulncheck` (if go.mod exists)

Results stored in `sec-ctrl/reports/deps/`.

## CI/CD Integration

### GitHub Actions
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
          # Install SCA (adjust for your install method)
          curl -L https://github.com/your-org/sca/releases/latest/download/sca.tar.gz | tar xz
          sudo mv sca /opt/sca
          sudo ln -s /opt/sca/bin/sca /usr/local/bin/sca
      
      - name: Run Audit
        run: sca audit --verbose
      
      - name: Upload Report
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: sec-ctrl/reports/security-audit.latest.md
      
      - name: Upload Suggestions
        if: failure()
        uses: actions/upload-artifact@v3
        with:
          name: remediation-suggestions
          path: sec-ctrl/SUGGESTIONS.md
```

### GitLab CI
```yaml
security-audit:
  stage: test
  script:
    - sca audit --verbose
  artifacts:
    when: always
    paths:
      - sec-ctrl/reports/
      - sec-ctrl/SUGGESTIONS.md
  allow_failure: false  # Fail pipeline on Critical/High findings
```

## Advanced Usage

### Incremental Mode
Skip audit if repository unchanged:
```bash
sca audit --incremental
```

Exit 0 if scope hash unchanged since last run.

### Custom Control Directory
```bash
sca audit --ctrl-dir /var/security/audit
```

### Custom Agent Directory
```bash
sca audit --agent-dir /custom/path/to/sca
```

### Output Formats
```bash
# Markdown only
sca audit --format md

# JSON only
sca audit --format json

# Both (default)
sca audit --format both
```

## Troubleshooting

### "Agent dir is writable" (Exit 4)
Make agent directory read-only:
```bash
sudo chmod -R a-w /opt/sca
```

### "Could not resolve agent dir" (Exit 3)
Set environment variable:
```bash
export SEC_AUDIT_AGENT_HOME=/path/to/sca
```

### "No critical/high findings but exit 2"
Check OVERRIDE.md - ensure overrides have correct syntax.

### Scope too large (slow audit)
Add exclusions to `sec-ctrl/config/ignore.paths`:
```
node_modules/
vendor/
.venv/
dist/
build/
```

## Best Practices

### 1. Regular Audits
Run weekly or on every PR:
```bash
# Cron: Weekly
0 9 * * 1 cd /srv/myapp && /opt/sca/bin/sca audit
```

### 2. Review Overrides
Quarterly review of `OVERRIDE.md`:
```bash
# Find expiring overrides
grep "Review: 2024" sec-ctrl/OVERRIDE.md
```

### 3. Track Fixes
Use SUGGESTIONS.md to create tasks:
```bash
# Convert to GitHub issues
gh issue create --title "Security: Fix API key in logs" --body "$(cat sec-ctrl/SUGGESTIONS.md)"
```

### 4. Commit Control Directory
```bash
# Track security posture in git
git add sec-ctrl/OVERRIDE.md sec-ctrl/config/
git commit -m "chore: Update security overrides"
```

Do NOT commit `sec-ctrl/reports/` (may contain sensitive code snippets).

### 5. Separate Dev/Prod
Use different control directories:
```bash
# Development
sca audit --ctrl-dir sec-ctrl-dev

# Production
sca audit --ctrl-dir sec-ctrl-prod
```
