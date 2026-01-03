# SCA Filtering & Suppression - Quick Start

## Overview

The SCA tool supports command-line filtering by standards/severity and interactive suppression with predefined justification categories.

---

## 🎯 Quick Examples

### Filter by Standard (Exclude OWASP)
```bash
sca audit --exclude-standards OWASP
```

### Filter by Severity (Only Critical/High)
```bash
sca audit --severity-min HIGH
```

### Interactive Suppression
```bash
# Run audit in interactive mode - prompts to suppress findings
sca audit --interactive

# Or suppress findings from existing report
sca suppress
```

### Combine Filters
```bash
# NIST Critical/High findings only
sca audit --include-standards NIST --severity-min HIGH
```

---

## 📋 Command-Line Filtering

### Supported Standards
- `SCA` - SCA-specific IDs (SCA-301, SCA-870, etc.)
- `OWASP` - OWASP Top 10 / API Security Top 10
- `NIST` - NIST SP 800-53 controls
- `PCI-DSS` - PCI-DSS requirements
- `CWE` - Common Weakness Enumeration

### Severity Levels
- `CRITICAL` - Immediate remediation required
- `HIGH` - Fix before production
- `MEDIUM` - Fix within sprint
- `LOW` - Address as time permits

### Filter Examples

```bash
# Exclude multiple standards
sca audit --exclude-standards OWASP,PCI-DSS

# Include only specific standards
sca audit --include-standards CWE,SCA

# Exclude low severity findings
sca audit --exclude-severity LOW,MEDIUM

# Complex filtering
sca audit \
  --include-standards NIST \
  --severity-min HIGH \
  --exclude-severity LOW
```

---

## 🔧 Interactive Suppression Workflow

### Step 1: Run Audit with Interactive Mode
```bash
sca audit --interactive
```

### Step 2: Review Each Finding
For each finding, you'll see:
```
Finding #1
─────────────────────────────────────────
ID:       CRIT-001
Title:    Incomplete JWT Signature Validation
File:     src/auth/session_token.c
Lines:    292-294
Severity: CRITICAL

Action: [s]uppress [k]eep [v]iew details [q]uit:
```

### Step 3: Suppress with Justification
If you choose `s`, select a category:
```
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
Additional reason/notes: Mock JWT for integration tests only
Approved by (name/team): Security Team

✓ Suppressed
```

### Step 4: Auto-Regenerate Report
The audit automatically re-runs with suppressions applied, excluding suppressed findings from the report.

---

## 📝 OVERRIDE.md Format

Suppressions are saved to `sec-ctrl/OVERRIDE.md` with full metadata:

```markdown
# Override: Mock JWT in test fixture (Test/Development Only)
# Category: Test/Development Only
# Finding: CRIT-001 - Incomplete JWT Signature Validation
# Reason: Mock JWT for integration tests only, never used in production
# Approved-By: Security Team
# Date: 2026-01-03
# Review-Date: 2027-01-03
src/auth/session_token.c:292-294
```

**Required Fields**:
- `Category` - One of the 10 predefined categories
- `Finding` - Finding ID and title
- `Reason` - Detailed justification
- `Approved-By` - Approver name/team
- `Date` - When created (YYYY-MM-DD)
- `Review-Date` - When to re-evaluate
- File path (last line, no # prefix)

---

## 🚀 Advanced Usage

### Batch Suppression from File

Create a suppression file:
```bash
cat > suppressions.txt <<EOF
CRIT-001|7|Test fixture only, not production code
HIGH-002|1|False positive - this is a safe strcpy usage
MED-003|2|Accepted risk - performance critical path
EOF
```

Apply batch suppressions:
```bash
sca suppress --batch suppressions.txt --auto-commit
```

**Format**: `FINDING_ID|CATEGORY_ID|REASON`

### Manual Suppression (Command-Line)

```bash
# Interactive mode
sca suppress --ctrl-dir ./sec-ctrl

# Non-interactive batch mode
sca suppress --batch suppressions.txt --non-interactive
```

### Use Existing Report

```bash
# Suppress from specific report
sca suppress --report sec-ctrl/reports/security-audit.20260103T043000Z.json
```

---

## 🔍 CI/CD Integration

### Block on Unfiltered Critical/High

```yaml
# .github/workflows/security.yml
- name: Security Audit (Critical/High Only)
  run: |
    sca audit --severity-min HIGH
    # Exit code 2 = Critical/High findings exist
```

### Weekly Full Audit with Filtering

```yaml
- name: Weekly Security Audit
  run: |
    # NIST compliance check only
    sca audit --include-standards NIST --severity-min MEDIUM
```

### Interactive Suppression in PR

```yaml
- name: Security Review
  run: |
    # Run audit, prompt for suppressions if findings exist
    sca audit --interactive || true

- name: Commit Suppressions
  if: always()
  run: |
    git add sec-ctrl/OVERRIDE.md
    git commit -m "chore: Security finding suppressions" || true
```

---

## 📊 Viewing Current Overrides

```bash
# View all overrides
cat sec-ctrl/OVERRIDE.md

# Count overrides by category
grep "^# Category:" sec-ctrl/OVERRIDE.md | sort | uniq -c

# Find expiring overrides (within 30 days)
grep "Review-Date:" sec-ctrl/OVERRIDE.md | \
  awk -F": " '{print $2}' | \
  while read date; do
    if [[ $(date -d "$date" +%s) -lt $(date -d "+30 days" +%s) ]]; then
      echo "Expiring: $date"
    fi
  done
```

---

## 🛡️ Best Practices

### 1. Review Overrides Regularly
- **Critical/High**: Review every 3-6 months
- **Medium**: Review every 6-12 months
- **Low**: Review annually

### 2. Require Approval for Critical/High
Don't suppress Critical/High findings without security team review.

### 3. Document Thoroughly
Provide detailed reasoning - future reviewers need to understand *why*.

### 4. Track in Git
```bash
git add sec-ctrl/OVERRIDE.md
git commit -m "chore: Suppress test fixture findings (approved by Security Team)"
```

### 5. Set Review Dates
Use appropriate review periods based on category:
- False Positive: 12 months
- Accepted Risk: 6 months
- Planned for Future: 3 months

### 6. Use Specific Categories
Choose the most accurate category - avoid "Custom Justification" unless necessary.

---

## 🔧 Troubleshooting

### Suppressions Not Working
**Q**: My overrides aren't suppressing findings.
**A**: Check that file paths match exactly, including line numbers.

```bash
# In OVERRIDE.md
src/auth/session_token.c:292-294

# Must match finding exactly (check audit report)
```

### Re-run Audit After Suppression
```bash
# Suppressions are applied on next audit
sca audit
```

### Remove a Suppression
Edit `sec-ctrl/OVERRIDE.md` and delete the override block:
```bash
vim sec-ctrl/OVERRIDE.md
# Delete the override section
sca audit  # Finding will reappear
```

### View Suppression History
```bash
# Git history of OVERRIDE.md
git log -p sec-ctrl/OVERRIDE.md
```

---

## 📚 See Also

- [FILTERING_GUIDE.md](FILTERING_GUIDE.md) - Comprehensive filtering documentation
- [OVERRIDE_GUIDE.md](OVERRIDE_GUIDE.md) - Detailed override management
- [USAGE.md](USAGE.md) - General SCA usage guide

---

## 💡 Quick Tips

```bash
# Most common use case: exclude OWASP, Critical/High only
sca audit --exclude-standards OWASP --severity-min HIGH

# Review findings interactively
sca audit --interactive

# Suppress from existing report
sca suppress

# Batch suppress multiple findings
sca suppress --batch suppressions.txt --auto-commit
```

---

**Need help?** Run `sca audit --help` or `sca suppress --help`
