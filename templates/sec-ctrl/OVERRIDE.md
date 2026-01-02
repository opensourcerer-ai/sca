# Security Audit Override Rules

This file contains findings that have been reviewed and **explicitly accepted** by the security team. Findings listed here will be **suppressed** in future audit reports.

## Purpose
Use this file to:
- Document **accepted risks** (with business justification)
- Suppress **false positives** (with technical explanation)
- Exclude **development/test artifacts** (clearly marked as non-production)

## Format
Each entry should include:
1. **File path or pattern** to identify the finding
2. **Reason** for override (security justification required)
3. **Approver** and date
4. **Review date** (when this override should be re-evaluated)

---

## Example Overrides

### Example 1: Test Fixtures with Hardcoded Keys
```
# Override: API key in test fixture (not used in production)
# File: tests/fixtures/mock_api_key.json
# Reason: Test-only mock credential, not a real API key
# Approved: Security Team, 2024-01-15
# Review: 2025-01-15
tests/fixtures/mock_api_key.json
```

### Example 2: Development Configuration
```
# Override: HTTP localhost connection in development config
# File: config/development.yml
# Reason: Local development only, not deployed to production
# Approved: DevOps Team, 2024-01-20
# Review: 2024-07-20
config/development.yml - http://localhost
```

### Example 3: Accepted Business Risk
```
# Override: User emails logged for audit trail
# File: src/auth/audit_logger.py:45
# Reason: Required for compliance audit trail (SOC2 requirement)
#         Logs are encrypted at rest and access-controlled
# Approved: CISO, 2024-02-01
# Review: 2024-08-01
# Mitigation: Logs encrypted, 90-day retention, RBAC enforced
src/auth/audit_logger.py:45
```

---

## Active Overrides

<!-- Add your overrides below this line -->

<!-- Each override MUST include:
     - File path or unique identifier
     - Business/technical justification
     - Approver name and date
     - Next review date
-->

---

## Override Guidelines

### ✅ Valid Reasons to Override
- **Test/development artifacts** clearly separated from production
- **False positives** with technical explanation why it's safe
- **Mitigated risks** where controls are in place (document the controls)
- **Business requirements** that override security best practices (requires CISO approval)

### ❌ Invalid Reasons to Override
- "Too hard to fix right now" (use backlog instead)
- "Low priority" (Critical/High findings should not be overridden without strong justification)
- "Legacy code" (plan migration instead)
- No justification provided

### 🔄 Review Process
- **Critical/High overrides**: Review every 3 months
- **Medium overrides**: Review every 6 months
- **Low overrides**: Review annually
- Expired overrides will be **removed** and findings **restored** in next audit

---

## Audit Trail

| Date | Approver | Action | Finding |
|------|----------|--------|---------|
| | | | |

<!-- Update this table when overrides are added/removed/modified -->
