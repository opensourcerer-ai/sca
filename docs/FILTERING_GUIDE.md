# SCA Filtering and Suppression Guide

## Overview

The SCA tool supports filtering findings by standards/categories and interactive suppression with predefined justifications.

---

## Command-Line Filtering

### Filter by Standard/Category

Exclude specific standards from the audit report:

```bash
# Exclude OWASP findings
sca audit --exclude-standards OWASP

# Exclude multiple standards
sca audit --exclude-standards OWASP,NIST,PCI-DSS

# Include only specific standards
sca audit --include-standards CWE,SCA
```

**Supported Standards**:
- `SCA` - SCA-specific IDs (e.g., SCA-301, SCA-870)
- `OWASP` - OWASP Top 10 / API Security Top 10
- `NIST` - NIST SP 800-53 controls
- `PCI-DSS` - PCI-DSS requirements
- `CWE` - Common Weakness Enumeration
- `CVSS` - CVE/CVSS findings

### Filter by Severity

```bash
# Only show Critical and High findings
sca audit --severity-min HIGH

# Only show Critical
sca audit --severity-min CRITICAL

# Show all except Low
sca audit --exclude-severity LOW
```

**Severity Levels**: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`

### Combine Filters

```bash
# Only NIST Critical/High findings
sca audit --include-standards NIST --severity-min HIGH

# Exclude OWASP Low/Medium findings
sca audit --exclude-standards OWASP --exclude-severity LOW,MEDIUM
```

---

## Interactive Suppression Mode

After an audit, interactively review and suppress findings:

```bash
# Run audit in interactive mode
sca audit --interactive

# Or suppress findings from existing report
sca suppress
```

### Workflow

1. Audit completes and displays findings summary
2. Tool prompts: "Review findings interactively? [y/N]"
3. For each finding:
   - Display finding details
   - Show options:
     - `[s]` Suppress with justification
     - `[k]` Keep (report this finding)
     - `[v]` View full details
     - `[q]` Quit interactive mode
4. If suppress selected, choose justification category
5. Automatically updates OVERRIDE.md with metadata

### Justification Categories

When suppressing a finding, select from predefined justifications:

1. **False Positive** - Finding is incorrect or doesn't apply to the code
2. **Accepted Risk** - Risk acknowledged and accepted by security team
3. **Compensating Controls** - Mitigated by other security measures
4. **Not Applicable** - Does not apply to this environment/deployment
5. **Planned for Future** - Acknowledged, will fix in upcoming release
6. **Third-Party Code** - Vendor-maintained code, cannot modify
7. **Test/Development Only** - Only exists in non-production code
8. **Performance Trade-off** - Security vs performance decision documented
9. **Legacy Compatibility** - Required for backward compatibility
10. **Custom Justification** - Provide free-text explanation

---

## OVERRIDE.md Format

Enhanced format with metadata:

```markdown
# Security Audit Overrides

# Override: JWT secret in test fixture (False Positive)
# Category: False Positive
# Finding: CRIT-001 - Hardcoded credentials
# Reason: Test fixture only, not production secret
# Approved-By: Security Team
# Date: 2026-01-03
# Review-Date: 2027-01-03
tests/fixtures/mock_jwt_secret.txt

# Override: HTTP localhost in dev config (Not Applicable)
# Category: Not Applicable
# Finding: HIGH-004 - Insecure HTTP connection
# Reason: Development configuration only, never deployed
# Approved-By: Jane Doe
# Date: 2026-01-03
# Review-Date: 2026-07-03
config/dev.yaml:15
```

### Required Fields

- `Category` - One of the justification categories
- `Finding` - Finding ID or description
- `Reason` - Human-readable explanation
- `Approved-By` - Who approved the override
- `Date` - When override was created
- `Review-Date` - When to review this override

---

## Advanced Usage

### Audit with Pre-Filtering

Generate a report excluding known overrides and specific categories:

```bash
# Exclude OWASP, only show Critical/High
sca audit --exclude-standards OWASP --severity-min HIGH

# Focus on specific CWE categories
sca audit --include-standards CWE --cwe-categories 119,120,121
```

### Batch Suppression from File

Suppress multiple findings at once:

```bash
# Create suppression file
cat > suppressions.txt <<EOF
CRIT-001|False Positive|Test data only
HIGH-002|Accepted Risk|Performance critical path
MED-003|Planned for Future|Scheduled for v2.0
EOF

# Apply suppressions
sca suppress --batch suppressions.txt
```

### Export Findings for Review

Export findings to CSV for team review:

```bash
sca audit --format csv --output findings.csv

# Review and annotate in spreadsheet
# Import decisions back
sca suppress --import findings.csv
```

---

## CI/CD Integration

### Fail Build on Unaccepted Findings

```yaml
# .github/workflows/security.yml
- name: Security Audit
  run: |
    sca audit --exclude-standards OWASP --severity-min HIGH
    # Exit code 2 means Critical/High findings exist
    # Exit code 0 means clean (or all findings suppressed)
```

### Weekly Full Audit

```bash
# Cron job: full audit weekly, email results
0 9 * * 1 sca audit --include-all --format html --email security@example.com
```

---

## Best Practices

1. **Review Overrides Quarterly** - Ensure suppressions are still valid
2. **Require Approval** - Don't suppress Critical/High without security team review
3. **Set Review Dates** - Auto-flag overrides older than 6-12 months
4. **Document Thoroughly** - Explain *why* the finding is suppressed
5. **Track in Version Control** - Commit OVERRIDE.md changes with justification

---

## Examples

### Example 1: Suppress test fixtures

```bash
$ sca audit --interactive

Finding: CRIT-001 - Hardcoded API key in source
File: tests/fixtures/api_test_key.txt
Severity: CRITICAL

Suppress this finding? [s/k/v/q]: s

Select justification:
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

Choice [1-10]: 7

Approved by: security-team
Review in (months) [6]: 12

✓ Added to OVERRIDE.md
```

### Example 2: Filter production audit

```bash
# Production audit: NIST compliance only, Critical/High only
sca audit \
  --include-standards NIST \
  --severity-min HIGH \
  --exclude-severity LOW \
  --output prod-audit.md
```

---

## Configuration

Store default filters in `.sca-config.yaml`:

```yaml
filters:
  exclude_standards:
    - OWASP  # Exclude OWASP by default
  severity_min: MEDIUM  # Only show MEDIUM and above

suppression:
  require_approval: true
  default_review_months: 6
  approval_required_for:
    - CRITICAL
    - HIGH
```

---

## Troubleshooting

**Q: Why are my overrides not working?**
A: Check OVERRIDE.md syntax - file paths must match exactly, including line numbers.

**Q: How do I un-suppress a finding?**
A: Edit OVERRIDE.md and remove the corresponding entry, or use `sca suppress --remove CRIT-001`.

**Q: Can I suppress by regex pattern?**
A: Yes, use `--pattern` in OVERRIDE.md:
```markdown
# Override pattern for all test files
# Pattern: tests/**/*.txt
# Category: Test/Development Only
```

---

## See Also

- `OVERRIDE_GUIDE.md` - Detailed override management
- `USAGE.md` - General SCA usage guide
- `docs/API.md` - Programmatic filtering API
