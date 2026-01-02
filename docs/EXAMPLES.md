# SCA Examples Guide

Comprehensive examples for real-world usage of Security Control Agent.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Basic Workflows](#basic-workflows)
3. [CI/CD Integration](#cicd-integration)
4. [Advanced Usage](#advanced-usage)
5. [Troubleshooting Examples](#troubleshooting-examples)
6. [Real-World Scenarios](#real-world-scenarios)

---

## Quick Start

### First-Time Setup

```bash
# 1. Install SCA (system-wide, requires sudo)
cd /path/to/sca
sudo make install PREFIX=/opt/sca

# 2. Make agent immutable
sudo chown -R root:root /opt/sca
sudo chmod -R a-w /opt/sca

# 3. Add to PATH
echo 'export PATH="/opt/sca/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

# 4. Verify installation
sca --help
```

### First Audit

```bash
# 1. Navigate to your repository
cd /path/to/your/project

# 2. Initialize control directory
sca bootstrap

# 3. Run your first audit
sca audit --verbose

# 4. Review findings
cat sec-ctrl/SUGGESTIONS.md

# 5. Review detailed report
less sec-ctrl/reports/security-audit.latest.md
```

---

## Basic Workflows

### Workflow 1: Fix Security Issues

```bash
# 1. Run audit
$ sca audit
Exit code: 2 (Critical/High findings exist)

# 2. Review suggestions
$ cat sec-ctrl/SUGGESTIONS.md

### Critical: Hardcoded API Key
**Evidence**: `src/config.py:15`
```python
API_KEY = "sk_live_abc123def456"
```

**Remediation**:
```python
import os
API_KEY = os.environ['API_KEY']
```

# 3. Implement fix
$ vim src/config.py
# ... make changes ...

# 4. Verify fix
$ sca audit
Exit code: 0 (No critical/high findings)

# 5. Commit
$ git add src/config.py
$ git commit -m "fix: Move API key to environment variable"
```

### Workflow 2: Accept Risk (Override)

```bash
# 1. Run audit
$ sca audit
Exit code: 2

# 2. Review finding
$ cat sec-ctrl/SUGGESTIONS.md

### High: Potential SQL injection
**Evidence**: `tests/integration/test_db.py:45`
```python
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
```

# 3. Determine this is test code with controlled input
$ cat tests/integration/test_db.py
# ... inspect code ...
# user_id is always an integer constant in tests

# 4. Add override
$ vim sec-ctrl/OVERRIDE.md

# Add:
# Override: SQL injection in integration tests
# File: tests/integration/test_db.py:45
# Reason: Test code only, user_id is hardcoded integer constant
#         Not executed in production environment
# Approved: Security Team (Alice), 2024-01-15
# Review: 2024-07-15
tests/integration/test_db.py:45

# 5. Re-audit (finding suppressed)
$ sca audit
Exit code: 0

# 6. Commit override
$ git add sec-ctrl/OVERRIDE.md
$ git commit -m "chore: Accept SQL injection in integration tests"
```

### Workflow 3: Track Security Drift

```bash
# 1. Audit on main branch
$ git checkout main
$ sca audit

# 2. Audit on feature branch
$ git checkout feature/new-api
$ sca audit

# 3. Compare
$ sca diff

Drift Summary
=============
Commit: a1b2c3d → e4f5g6h

Findings:
  Critical: 0 → 1 (Δ +1)  ← New critical finding!
  High:     2 → 2 (Δ 0)
  Medium:   5 → 6 (Δ +1)
  Low:      8 → 8 (Δ 0)

Status: Degraded (net +1 critical)

# 4. Investigate new critical finding
$ cat sec-ctrl/SUGGESTIONS.md | grep -A 20 "### Critical"

# 5. Fix before merging
$ git checkout feature/new-api
# ... fix issue ...
$ sca audit
Exit code: 0

# 6. Merge to main
$ git checkout main
$ git merge feature/new-api
```

---

## CI/CD Integration

### Example 1: GitHub Actions

```yaml
# .github/workflows/security-audit.yml
name: Security Audit

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  security-audit:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v3
        with:
          fetch-depth: 0  # Full history for drift tracking

      - name: Install SCA
        run: |
          curl -L https://github.com/your-org/sca/releases/latest/download/sca-linux-amd64.tar.gz | tar xz
          sudo mv sca /opt/sca
          sudo chown -R root:root /opt/sca
          sudo chmod -R a-w /opt/sca
          echo "/opt/sca/bin" >> $GITHUB_PATH

      - name: Verify SCA installation
        run: sca --help

      - name: Initialize control directory
        run: sca bootstrap

      - name: Run security audit
        id: audit
        run: |
          sca audit --enable-deps --verbose
          echo "exit_code=$?" >> $GITHUB_OUTPUT
        continue-on-error: true

      - name: Upload audit report
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: security-audit-report
          path: |
            sec-ctrl/reports/security-audit.latest.md
            sec-ctrl/reports/security-audit.latest.json

      - name: Upload remediation suggestions
        if: steps.audit.outputs.exit_code == '2'
        uses: actions/upload-artifact@v3
        with:
          name: security-suggestions
          path: sec-ctrl/SUGGESTIONS.md

      - name: Check for critical/high findings
        run: |
          if [ "${{ steps.audit.outputs.exit_code }}" -eq 2 ]; then
            echo "::error::Critical or High security findings detected"
            echo "Review the suggestions artifact for remediation steps"
            exit 1
          elif [ "${{ steps.audit.outputs.exit_code }}" -eq 4 ]; then
            echo "::error::Agent immutability violated"
            exit 1
          elif [ "${{ steps.audit.outputs.exit_code }}" -ne 0 ]; then
            echo "::warning::Audit completed with warnings (exit code ${{ steps.audit.outputs.exit_code }})"
          fi

      - name: Post PR comment with findings
        if: github.event_name == 'pull_request' && steps.audit.outputs.exit_code == '2'
        uses: actions/github-script@v6
        with:
          script: |
            const fs = require('fs');
            const suggestions = fs.readFileSync('sec-ctrl/SUGGESTIONS.md', 'utf8');

            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: `## ⚠️ Security Audit Failed\n\nCritical or High severity findings detected:\n\n${suggestions}\n\n**Action Required**: Fix these issues before merging.`
            });
```

### Example 2: GitLab CI

```yaml
# .gitlab-ci.yml
stages:
  - security

security-audit:
  stage: security
  image: ubuntu:22.04
  before_script:
    - apt-get update && apt-get install -y curl tar git
    - curl -L https://github.com/your-org/sca/releases/latest/download/sca-linux-amd64.tar.gz | tar xz
    - mv sca /opt/sca
    - chmod -R a-w /opt/sca
    - export PATH="/opt/sca/bin:$PATH"
  script:
    - sca bootstrap
    - sca audit --enable-deps --verbose
  after_script:
    - |
      if [ -f "sec-ctrl/SUGGESTIONS.md" ]; then
        echo "=== Security Remediation Suggestions ==="
        cat sec-ctrl/SUGGESTIONS.md
      fi
  artifacts:
    when: always
    paths:
      - sec-ctrl/reports/
      - sec-ctrl/SUGGESTIONS.md
    expire_in: 30 days
  allow_failure: false  # Fail pipeline on Critical/High findings
```

### Example 3: Jenkins

```groovy
// Jenkinsfile
pipeline {
    agent any

    environment {
        SCA_HOME = '/opt/sca'
        PATH = "${SCA_HOME}/bin:${env.PATH}"
    }

    stages {
        stage('Install SCA') {
            steps {
                script {
                    if (!fileExists("${SCA_HOME}")) {
                        sh '''
                            curl -L https://github.com/your-org/sca/releases/latest/download/sca-linux-amd64.tar.gz | tar xz
                            sudo mv sca ${SCA_HOME}
                            sudo chown -R root:root ${SCA_HOME}
                            sudo chmod -R a-w ${SCA_HOME}
                        '''
                    }
                }
            }
        }

        stage('Security Audit') {
            steps {
                sh 'sca bootstrap'
                sh 'sca audit --enable-deps --verbose'
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'sec-ctrl/reports/**', allowEmptyArchive: true
        }
        failure {
            script {
                def suggestions = readFile('sec-ctrl/SUGGESTIONS.md')
                slackSend(
                    color: 'danger',
                    message: "Security Audit Failed for ${env.JOB_NAME} #${env.BUILD_NUMBER}\n\nSuggestions:\n${suggestions}\n\nDetails: ${env.BUILD_URL}"
                )
            }
        }
    }
}
```

---

## Advanced Usage

### Example 1: Multi-Repository Batch Audit

```bash
#!/bin/bash
# batch-audit.sh - Audit multiple repositories

REPOS=(
    "/path/to/repo1"
    "/path/to/repo2"
    "/path/to/repo3"
)

RESULTS_DIR="/var/security/batch-audit-$(date +%Y%m%d)"
mkdir -p "$RESULTS_DIR"

for repo in "${REPOS[@]}"; do
    repo_name=$(basename "$repo")
    echo "=== Auditing $repo_name ==="

    cd "$repo"

    # Initialize if needed
    [ ! -d "sec-ctrl" ] && sca bootstrap

    # Run audit
    sca audit --enable-deps > "$RESULTS_DIR/$repo_name.log" 2>&1
    exit_code=$?

    # Copy reports
    cp sec-ctrl/reports/security-audit.latest.md "$RESULTS_DIR/$repo_name-report.md"
    cp sec-ctrl/SUGGESTIONS.md "$RESULTS_DIR/$repo_name-suggestions.md" 2>/dev/null || true

    echo "$repo_name: Exit code $exit_code"
done

# Generate summary
echo "=== Batch Audit Summary ===" > "$RESULTS_DIR/SUMMARY.txt"
for log in "$RESULTS_DIR"/*.log; do
    repo_name=$(basename "$log" .log)
    critical=$(grep -c "### Critical" "$RESULTS_DIR/$repo_name-report.md" 2>/dev/null || echo 0)
    high=$(grep -c "### High" "$RESULTS_DIR/$repo_name-report.md" 2>/dev/null || echo 0)
    echo "$repo_name: Critical=$critical, High=$high" >> "$RESULTS_DIR/SUMMARY.txt"
done

cat "$RESULTS_DIR/SUMMARY.txt"
```

### Example 2: Custom Dependency Scanner

```bash
# Add to sec-ctrl/hooks/post-audit.sh
#!/bin/bash
# Custom dependency scanner for internal packages

echo "=== Running custom dependency audit ==="

# Check for internal package vulnerabilities
if [ -f "internal-packages.txt" ]; then
    while IFS= read -r package; do
        version=$(grep "^$package==" requirements.txt | cut -d= -f3)
        # Check against internal vulnerability DB
        vuln=$(curl -s "https://vulndb.internal.company.com/check?pkg=$package&ver=$version")
        if [ -n "$vuln" ]; then
            echo "WARNING: $package $version has known vulnerabilities: $vuln"
        fi
    done < internal-packages.txt
fi
```

### Example 3: Incremental Audit in Development

```bash
#!/bin/bash
# dev-audit-watch.sh - Watch for changes and auto-audit

# Initial audit
sca audit --incremental

# Watch for file changes
inotifywait -m -r -e modify,create,delete --exclude 'sec-ctrl/' . | while read path action file; do
    echo "Detected $action on $file"

    # Debounce (wait for changes to settle)
    sleep 2

    # Run incremental audit
    echo "Running security audit..."
    sca audit --incremental

    if [ $? -eq 2 ]; then
        # Desktop notification on findings
        notify-send "Security Alert" "New security findings detected!" --urgency=critical
    fi
done
```

### Example 4: Custom Invariant for Project-Specific Rules

```markdown
<!-- sec-ctrl/invariants/local-overrides.md -->

# Project-Specific Security Invariants

## Invariant: License Header Required

All source files MUST include the company license header.

**Pattern to detect**: Files without "Copyright (c) 2024 ACME Corp" in first 10 lines

**Severity**: Low

**Languages**: All

---

## Invariant: No Hard-Coded Database Credentials

Database credentials MUST NOT be hardcoded in application code.

**Pattern to detect**:
- `db_password = "..."`
- `DB_PASS = "..."`
- Connection strings with embedded passwords

**Exception**: Test fixtures with clearly marked mock credentials

**Severity**: Critical

**Languages**: Python, Java, Go, JavaScript
```

---

## Troubleshooting Examples

### Problem: Scope Too Large (Slow Audit)

```bash
# 1. Check scope size
$ sca scope | wc -l
15234  # Too many files!

# 2. Identify large directories
$ sca scope | cut -d/ -f1 | sort | uniq -c | sort -rn | head
   8234 vendor
   3421 node_modules
   2100 build
    987 dist

# 3. Add exclusions
$ echo "vendor/" >> sec-ctrl/config/ignore.paths
$ echo "build/" >> sec-ctrl/config/ignore.paths
$ echo "dist/" >> sec-ctrl/config/ignore.paths

# 4. Verify reduced scope
$ sca scope | wc -l
1392  # Much better!

# 5. Run audit (faster)
$ sca audit
```

### Problem: Agent Immutability Error

```bash
$ sca audit
[ERROR] Agent directory is writable (must be read-only)
Exit code: 4

# Fix: Make agent read-only
$ ls -ld /opt/sca
drwxr-xr-x 10 user user 4096 Jan 15 12:00 /opt/sca  # Writable!

$ sudo chown -R root:root /opt/sca
$ sudo chmod -R a-w /opt/sca
$ ls -ld /opt/sca
dr-xr-xr-x 10 root root 4096 Jan 15 12:00 /opt/sca  # Read-only ✓

$ sca audit
# Works now
```

### Problem: Finding Should Be Excluded But Appears

```bash
# 1. Check override syntax
$ cat sec-ctrl/OVERRIDE.md
...
# Override: Test API key
# File: tests/fixtures/key.json  # Wrong path!
tests/fixture/key.json  # Typo: fixture vs fixtures

# 2. Verify exact path from report
$ grep "key.json" sec-ctrl/reports/security-audit.latest.md
**Evidence**: `tests/fixtures/key.json:5`

# 3. Fix override (correct path)
$ vim sec-ctrl/OVERRIDE.md
tests/fixtures/key.json  # Fixed

# 4. Re-audit
$ sca audit
Exit code: 0  # Finding suppressed
```

---

## Real-World Scenarios

### Scenario 1: Pre-Production Security Gate

```bash
#!/bin/bash
# deploy-gate.sh - Block deployment if security issues exist

set -e

# 1. Checkout release candidate
git checkout release/v2.0.0

# 2. Run comprehensive audit
sca audit --enable-deps --verbose

# 3. Check exit code
if [ $? -eq 2 ]; then
    echo "❌ Deployment blocked: Security findings exist"
    echo "Review sec-ctrl/SUGGESTIONS.md and fix before deploying"
    exit 1
elif [ $? -eq 0 ]; then
    echo "✅ Security audit passed"
    echo "Proceeding with deployment..."
    ./deploy.sh
else
    echo "⚠️  Audit completed with warnings"
    echo "Manual review recommended"
    # Optional: Require manual approval
    read -p "Continue with deployment? (yes/no) " answer
    if [ "$answer" != "yes" ]; then
        exit 1
    fi
fi
```

### Scenario 2: Quarterly Security Review

```bash
#!/bin/bash
# quarterly-review.sh - Review security posture and overrides

echo "=== Quarterly Security Review $(date) ==="

# 1. Run fresh audit
sca audit --enable-deps

# 2. Check override expiry
echo ""
echo "=== Expiring Overrides (review required) ==="
grep "Review:" sec-ctrl/OVERRIDE.md | while read line; do
    review_date=$(echo "$line" | grep -oP '\d{4}-\d{2}-\d{2}')
    if [[ "$review_date" < "$(date +%Y-%m-%d)" ]]; then
        echo "EXPIRED: $line"
    elif [[ "$review_date" < "$(date -d '+30 days' +%Y-%m-%d)" ]]; then
        echo "EXPIRING SOON: $line"
    fi
done

# 3. Generate metrics
echo ""
echo "=== Security Metrics ==="
critical=$(grep -c "### Critical" sec-ctrl/reports/security-audit.latest.md || echo 0)
high=$(grep -c "### High" sec-ctrl/reports/security-audit.latest.md || echo 0)
medium=$(grep -c "### Medium" sec-ctrl/reports/security-audit.latest.md || echo 0)
low=$(grep -c "### Low" sec-ctrl/reports/security-audit.latest.md || echo 0)

echo "Critical: $critical"
echo "High: $high"
echo "Medium: $medium"
echo "Low: $low"
echo "Total: $((critical + high + medium + low))"

# 4. Track trend
echo ""
echo "=== Security Trend (last 4 audits) ==="
ls -t sec-ctrl/reports/security-audit.*.md | head -4 | while read report; do
    date=$(basename "$report" | grep -oP '\d{8}_\d{6}')
    count=$(grep -c "^\*\*Evidence\*\*" "$report" || echo 0)
    echo "$date: $count findings"
done
```

### Scenario 3: Pull Request Security Review

```bash
#!/bin/bash
# pr-security-check.sh - Compare PR branch with main

# 1. Save current branch
current_branch=$(git branch --show-current)

# 2. Audit main branch
git checkout main
sca audit
cp sec-ctrl/reports/security-audit.latest.md /tmp/main-report.md

# 3. Audit PR branch
git checkout "$current_branch"
sca audit

# 4. Compare
sca diff > /tmp/security-diff.txt
cat /tmp/security-diff.txt

# 5. Fail if security degraded
if grep -q "Δ +" /tmp/security-diff.txt; then
    echo "❌ PR introduces new security issues"
    echo "Fix before merging to main"
    exit 1
else
    echo "✅ No new security issues introduced"
    exit 0
fi
```

### Scenario 4: Compliance Report Generation

```bash
#!/bin/bash
# compliance-report.sh - Generate compliance-ready security documentation

REPORT_DIR="compliance-reports/$(date +%Y%m%d)"
mkdir -p "$REPORT_DIR"

# 1. Run comprehensive audit
sca audit --enable-deps --verbose

# 2. Copy reports
cp sec-ctrl/reports/security-audit.latest.md "$REPORT_DIR/security-audit.md"
cp sec-ctrl/reports/security-audit.latest.json "$REPORT_DIR/security-audit.json"
cp sec-ctrl/OVERRIDE.md "$REPORT_DIR/accepted-risks.md"
cp sec-ctrl/SUGGESTIONS.md "$REPORT_DIR/remediation-plan.md"

# 3. Generate executive summary
cat > "$REPORT_DIR/executive-summary.md" <<EOF
# Security Audit Report - $(date +%Y-%m-%d)

## Overview
This report summarizes the security audit performed on the ACME application
codebase as of commit $(git rev-parse HEAD).

## Findings Summary
$(cat sec-ctrl/reports/security-audit.latest.md | grep -A 10 "## Executive Summary")

## Accepted Risks
The following security findings have been reviewed and accepted by the security team:
$(grep -c "^# Override:" sec-ctrl/OVERRIDE.md || echo 0) risks documented in accepted-risks.md

## Remediation Plan
Open security issues with remediation steps are documented in remediation-plan.md

## Compliance Status
- PCI-DSS: $(grep -q "### Critical\|### High" sec-ctrl/reports/security-audit.latest.md && echo "Non-Compliant (findings exist)" || echo "Compliant")
- HIPAA: $(grep -q "### Critical\|### High" sec-ctrl/reports/security-audit.latest.md && echo "Non-Compliant (findings exist)" || echo "Compliant")
- SOC 2: Under review

## Next Steps
1. Review and remediate all Critical and High severity findings
2. Schedule quarterly review of accepted risks
3. Update security controls documentation

EOF

echo "Compliance report generated in $REPORT_DIR/"
ls -lh "$REPORT_DIR"/
```

---

## Tips & Best Practices

### Tip 1: Reduce False Positives

```bash
# Be specific in OVERRIDE.md - match exact file path + reason
# ✅ Good
tests/fixtures/api_key.json:5 - mock Stripe key

# ❌ Bad (too broad)
api_key
```

### Tip 2: Automate Recurring Audits

```bash
# Cron job: Weekly audit on main branch
0 9 * * 1 cd /srv/myapp && git pull && /opt/sca/bin/sca audit --incremental && mail -s "Weekly Security Audit" security@example.com < sec-ctrl/SUGGESTIONS.md
```

### Tip 3: Use Incremental Mode in Development

```bash
# .git/hooks/pre-commit
#!/bin/bash
sca audit --incremental
if [ $? -eq 2 ]; then
    echo "Security findings detected - commit blocked"
    echo "Run 'sca audit' and fix issues, or add to OVERRIDE.md"
    exit 1
fi
```

### Tip 4: Version Control Your Overrides

```bash
# Track security decisions in git
git add sec-ctrl/OVERRIDE.md sec-ctrl/config/ignore.paths
git commit -m "chore: Update security override rules"
```

### Tip 5: Regular Override Reviews

```bash
# Quarterly reminder
echo "0 9 1 */3 * cd /srv/myapp && grep 'Review:' sec-ctrl/OVERRIDE.md | mail -s 'Quarterly Override Review Due' security@example.com" | crontab -
```

---

## Additional Resources

- **Documentation**: `/opt/sca/docs/`
- **Man Pages**: `man sca`, `man sca-audit`, etc.
- **GitHub**: https://github.com/your-org/sca
- **Support**: security@example.com

---

**Last Updated**: 2026-01-02
