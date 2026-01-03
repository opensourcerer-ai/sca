# SCA Ticket Creation Guide

## Overview

Automatically create GitHub issues or Jira tickets from security audit findings. This feature integrates your security audits directly into your existing workflow management system.

---

## 🚀 Quick Start

### GitHub Issues

```bash
# Prerequisites: Install and authenticate with GitHub CLI
gh auth login

# Create issues for Critical/High findings
sca create-tickets --platform github

# Dry run to preview
sca create-tickets --platform github --dry-run
```

### Jira Tickets

```bash
# Create .env file with Jira credentials
cp .env.example .env
# Edit .env with your Jira details

# Create tickets for Critical/High findings
sca create-tickets --platform jira

# Dry run to preview
sca create-tickets --platform jira --dry-run
```

---

## 📋 Configuration

### GitHub Setup

**Option 1: Using GitHub CLI (Recommended)**

```bash
# Install GitHub CLI
# macOS: brew install gh
# Linux: https://github.com/cli/cli#installation

# Authenticate
gh auth login

# That's it! No .env needed
```

**Option 2: Using Personal Access Token**

```bash
# Create token at: https://github.com/settings/tokens
# Required scopes: repo (or public_repo for public repos)

# Add to .env:
GITHUB_TOKEN=ghp_xxxxxxxxxxxxx
GITHUB_REPO=mycompany/myapp
```

### Jira Setup

1. **Generate API Token**
   - Go to: https://id.atlassian.com/manage-profile/security/api-tokens
   - Create token
   - Copy token value

2. **Configure .env**

```bash
cp .env.example .env
```

Edit `.env`:

```bash
JIRA_URL=https://yourcompany.atlassian.net
JIRA_USER=security-team@company.com
JIRA_API_TOKEN=ATATTxxx...
JIRA_PROJECT=SEC
JIRA_ISSUE_TYPE=Bug
```

3. **Test Configuration**

```bash
# Dry run to test credentials
sca create-tickets --platform jira --dry-run
```

---

## 🎯 Usage Examples

### Create Tickets for All Critical/High Findings

```bash
# GitHub
sca create-tickets --platform github

# Jira
sca create-tickets --platform jira
```

### Create Tickets for All Severities

```bash
sca create-tickets --platform github --severity-min LOW
```

### Preview Without Creating

```bash
sca create-tickets --platform github --dry-run
```

### Force Create Even if Tickets Exist

```bash
# By default, skips findings that already have tickets
# Use --create-all to override
sca create-tickets --platform github --create-all
```

### Use Specific Report

```bash
sca create-tickets \
  --platform github \
  --report sec-ctrl/reports/security-audit.20260103T043000Z.json
```

### Custom Environment File

```bash
# Use different credentials
sca create-tickets \
  --platform jira \
  --env-file ~/.sca-production.env
```

---

## 📝 Ticket Format

### GitHub Issue Example

```markdown
## Security Finding: CRIT-001

**File**: `src/auth/session_token.c:292-294`
**CWE**: CWE-347
**Remediation Priority**: IMMEDIATE

### Impact
Complete authentication bypass - attackers can forge JWT tokens

### Location
```
src/auth/session_token.c:292-294
```

### Remediation Steps
1. Implement base64url decoding function
2. Decode the signature component from the JWT
3. Compare decoded signature with expected HMAC using constant-time function

**Code to Add**:
```c
// Add base64url decode helper function
static size_t base64url_decode(const char *src, size_t src_len,
                               uint8_t *dst, size_t dst_len) {
    // Implementation needed
}

// In session_token_validate() after line 290:
uint8_t decoded_sig[EVP_MAX_MD_SIZE];
size_t decoded_len = base64url_decode(sig_encoded, strlen(sig_encoded),
                                      decoded_sig, sizeof(decoded_sig));

if (decoded_len != expected_len ||
    CRYPTO_memcmp(decoded_sig, expected_sig, expected_len) != 0) {
    log_warning("JWT signature validation failed");
    return ERR_AUTH_FAILED;
}
```

### References
- [Security Audit Report](sec-ctrl/reports/security-audit.latest.md)
- [Full Remediation Guide](sec-ctrl/SUGGESTIONS.md)

---
*This issue was automatically created by SCA (Security Control Agent)*
*Finding ID: CRIT-001*
```

**Labels Applied**:
- `security`
- `sca-finding`
- `severity:critical`
- `priority:p0`

---

## 🔧 Tracking & Deduplication

### Ticket Tracker

Created tickets are tracked in `sec-ctrl/state/created-tickets.json`:

```json
{
  "tickets": [
    {
      "finding_id": "CRIT-001",
      "ticket_key": "#123",
      "ticket_url": "https://github.com/mycompany/myapp/issues/123",
      "created_at": "2026-01-03T12:00:00Z"
    },
    {
      "finding_id": "HIGH-001",
      "ticket_key": "SEC-456",
      "ticket_url": "https://company.atlassian.net/browse/SEC-456",
      "created_at": "2026-01-03T12:01:00Z"
    }
  ]
}
```

### Deduplication Behavior

By default, the script:
- ✅ **Skips findings that already have tickets**
- ✅ **Shows existing ticket URL in log**
- ❌ **Does not create duplicates**

To override and create duplicates:

```bash
sca create-tickets --create-all
```

### Manual Tracking Edits

To reset tracking (create fresh tickets):

```bash
# Backup first
cp sec-ctrl/state/created-tickets.json sec-ctrl/state/created-tickets.json.bak

# Clear tracker
echo '{"tickets": []}' > sec-ctrl/state/created-tickets.json

# Re-run ticket creation
sca create-tickets --platform github
```

---

## 🔄 CI/CD Integration

### GitHub Actions

```yaml
name: Security Audit and Tickets

on:
  schedule:
    - cron: '0 9 * * 1'  # Weekly on Monday
  workflow_dispatch:

jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install SCA
        run: |
          # Install SCA tool
          curl -L https://github.com/your-org/sca/releases/latest/download/sca.tar.gz | tar xz
          sudo mv sca /opt/sca
          sudo ln -s /opt/sca/bin/sca /usr/local/bin/sca

      - name: Run Security Audit
        run: sca audit --verbose

      - name: Create GitHub Issues
        if: always()
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          sca create-tickets --platform github --severity-min HIGH

      - name: Commit Ticket Tracker
        if: always()
        run: |
          git config user.name "Security Bot"
          git config user.email "security-bot@company.com"
          git add sec-ctrl/state/created-tickets.json
          git commit -m "chore: Update ticket tracker [skip ci]" || true
          git push
```

### GitLab CI

```yaml
security-audit-tickets:
  stage: security
  script:
    - sca audit
    - sca create-tickets --platform jira --severity-min HIGH
  variables:
    JIRA_URL: $JIRA_URL
    JIRA_USER: $JIRA_USER
    JIRA_API_TOKEN: $JIRA_API_TOKEN
    JIRA_PROJECT: SEC
  artifacts:
    paths:
      - sec-ctrl/state/created-tickets.json
  only:
    - schedules
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any

    environment {
        JIRA_URL = credentials('jira-url')
        JIRA_USER = credentials('jira-user')
        JIRA_API_TOKEN = credentials('jira-api-token')
        JIRA_PROJECT = 'SEC'
    }

    stages {
        stage('Security Audit') {
            steps {
                sh 'sca audit'
            }
        }

        stage('Create Jira Tickets') {
            steps {
                sh '''
                    sca create-tickets \
                      --platform jira \
                      --severity-min HIGH
                '''
            }
        }

        stage('Archive Tracker') {
            steps {
                archiveArtifacts artifacts: 'sec-ctrl/state/created-tickets.json'
            }
        }
    }
}
```

---

## 🛠️ Advanced Usage

### Filter by Severity

```bash
# Only Critical
sca create-tickets --platform github --severity-min CRITICAL

# Critical and High (default)
sca create-tickets --platform github --severity-min HIGH

# All severities
sca create-tickets --platform github --severity-min LOW
```

### Combined Workflow

```bash
# 1. Run audit with filtering
sca audit --exclude-standards OWASP --severity-min HIGH

# 2. Create tickets for remaining findings
sca create-tickets --platform github --severity-min HIGH

# 3. Commit tracker
git add sec-ctrl/state/created-tickets.json
git commit -m "chore: Update ticket tracker"
```

### Multiple Platforms

```bash
# Create both GitHub issues AND Jira tickets
sca create-tickets --platform github --severity-min CRITICAL
sca create-tickets --platform jira --severity-min HIGH
```

---

## 📊 Reporting

### View Created Tickets

```bash
# List all created tickets
jq -r '.tickets[] | "\(.finding_id): \(.ticket_url)"' \
  sec-ctrl/state/created-tickets.json

# Count tickets by platform
jq -r '.tickets[] | .ticket_url | select(contains("github")) | "GitHub"' \
  sec-ctrl/state/created-tickets.json | wc -l
```

### Export to CSV

```bash
# Export ticket tracker to CSV
jq -r '.tickets[] | [.finding_id, .ticket_key, .ticket_url, .created_at] | @csv' \
  sec-ctrl/state/created-tickets.json > tickets.csv
```

---

## 🔐 Security Best Practices

### 1. Protect Credentials

```bash
# Set restrictive permissions
chmod 600 .env

# Never commit .env
echo ".env" >> .gitignore

# Use secrets manager in production
# AWS: aws secretsmanager get-secret-value
# GCP: gcloud secrets versions access
```

### 2. Use Dedicated Service Accounts

- **GitHub**: Create machine user or use GitHub App
- **Jira**: Create dedicated "Security Automation" user

### 3. Rotate Tokens Regularly

```bash
# Quarterly token rotation
# Update .env with new tokens
# Test with --dry-run first
sca create-tickets --dry-run --platform jira
```

### 4. Audit Token Usage

```bash
# GitHub: Check token usage
gh api /user -i

# Jira: Monitor API usage in admin console
```

---

## 🐛 Troubleshooting

### GitHub Issues Not Created

**Error**: `gh: command not found`

```bash
# Install GitHub CLI
# macOS:
brew install gh

# Linux:
# See: https://github.com/cli/cli#installation

# Authenticate:
gh auth login
```

**Error**: `Not authenticated with GitHub`

```bash
# Re-authenticate
gh auth login

# Or set token in .env:
GITHUB_TOKEN=ghp_xxxxx
```

**Error**: `Resource not accessible by integration`

```bash
# Check token has 'repo' scope
# Regenerate token if needed
```

### Jira Tickets Not Created

**Error**: `HTTP 401 Unauthorized`

```bash
# Verify credentials in .env
echo $JIRA_USER
echo $JIRA_URL

# Test with curl:
curl -u "$JIRA_USER:$JIRA_API_TOKEN" \
  "$JIRA_URL/rest/api/2/myself" | jq
```

**Error**: `HTTP 400 Bad Request` - "project is required"

```bash
# Verify project key exists:
curl -u "$JIRA_USER:$JIRA_API_TOKEN" \
  "$JIRA_URL/rest/api/2/project/$JIRA_PROJECT" | jq

# List all projects:
curl -u "$JIRA_USER:$JIRA_API_TOKEN" \
  "$JIRA_URL/rest/api/2/project" | jq -r '.[].key'
```

### Duplicate Tickets Created

```bash
# Check ticket tracker:
cat sec-ctrl/state/created-tickets.json

# If corrupted, reset:
echo '{"tickets": []}' > sec-ctrl/state/created-tickets.json
```

### Dry Run Shows Nothing

```bash
# Verify findings exist in report:
jq '.findings.critical, .findings.high' \
  sec-ctrl/reports/security-audit.latest.json

# Check severity threshold:
sca create-tickets --dry-run --severity-min LOW
```

---

## 📚 See Also

- [FILTERING_GUIDE.md](FILTERING_GUIDE.md) - Filter findings before creating tickets
- [USAGE.md](USAGE.md) - General SCA usage guide
- [GitHub CLI Documentation](https://cli.github.com/manual/)
- [Jira REST API](https://developer.atlassian.com/cloud/jira/platform/rest/v2/)

---

## 💡 Pro Tips

### 1. Combine with Filtering

```bash
# Only create tickets for NIST Critical findings
sca audit --include-standards NIST --severity-min CRITICAL
sca create-tickets --platform github --severity-min CRITICAL
```

### 2. Scheduled Ticket Creation

```bash
# Cron job: Weekly ticket creation
0 9 * * 1 cd /path/to/repo && sca audit && sca create-tickets --platform jira
```

### 3. Custom Labels/Tags

For GitHub, edit `bin/sca-create-tickets.sh` labels variable:

```bash
# Add custom labels
local labels="security,sca-finding,team-backend"
```

For Jira, add custom fields in the payload.

### 4. Notification Integration

```bash
# Send Slack notification after ticket creation
sca create-tickets --platform github && \
  curl -X POST -H 'Content-type: application/json' \
    --data '{"text":"Security tickets created"}' \
    $SLACK_WEBHOOK_URL
```

---

**Need help?** Run `sca create-tickets --help`
