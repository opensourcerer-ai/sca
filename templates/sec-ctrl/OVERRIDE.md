# Security Audit Override Rules

This file contains findings that have been reviewed and **explicitly accepted** by the security team. Findings listed here will be **suppressed** in future audit reports.

## Purpose
Use this file to:
- Document **accepted risks** (with business justification)
- Suppress **false positives** (with technical explanation)
- Exclude **development/test artifacts** (clearly marked as non-production)

## Format (Enhanced Metadata)
Each override entry MUST include these fields:
1. **Override**: One-line summary with category in parentheses
2. **Category**: Justification category (see categories below)
3. **Finding**: Finding ID and title from audit report
4. **Reason**: Detailed explanation (business/technical justification)
5. **Approved-By**: Name of person/team who approved the override
6. **Date**: Date when override was created (YYYY-MM-DD)
7. **Review-Date**: When this override should be re-evaluated (YYYY-MM-DD)
8. **File path** or pattern (last line, no comment prefix)

### Valid Justification Categories:
1. **False Positive** - Finding is incorrect or doesn't apply
2. **Accepted Risk** - Risk acknowledged and accepted by security team
3. **Compensating Controls** - Mitigated by other security measures
4. **Not Applicable** - Doesn't apply to this environment/deployment
5. **Planned for Future** - Scheduled for fix in upcoming release
6. **Third-Party Code** - Vendor-maintained code, cannot modify
7. **Test/Development Only** - Only exists in non-production code
8. **Performance Trade-off** - Security vs performance decision documented
9. **Legacy Compatibility** - Required for backward compatibility
10. **Custom Justification** - Other (provide detailed explanation)

---

## Example Overrides

### Example 1: Test Fixtures with Hardcoded Keys
```
# Override: API key in test fixture (Test/Development Only)
# Category: Test/Development Only
# Finding: CRIT-001 - Hardcoded API key in source
# Reason: Test-only mock credential, not a real API key. Never deployed.
# Approved-By: Security Team
# Date: 2024-01-15
# Review-Date: 2025-01-15
tests/fixtures/mock_api_key.json
```

### Example 2: Development Configuration
```
# Override: HTTP localhost connection (Not Applicable)
# Category: Not Applicable
# Finding: HIGH-004 - Insecure HTTP connection
# Reason: Development configuration only, not used in production deployments
# Approved-By: DevOps Team
# Date: 2024-01-20
# Review-Date: 2025-01-20
config/development.yml:15
```

### Example 3: Accepted Business Risk
```
# Override: User emails logged for audit trail (Accepted Risk)
# Category: Accepted Risk
# Finding: MED-002 - PII in application logs
# Reason: Required for SOC2 compliance audit trail. Logs encrypted at rest, 90-day retention, RBAC enforced.
# Approved-By: CISO
# Date: 2024-02-01
# Review-Date: 2024-08-01
src/auth/audit_logger.py:45
```

### Example 4: False Positive
```
# Override: Base64 string mistaken for secret (False Positive)
# Category: False Positive
# Finding: HIGH-001 - Hardcoded credential detected
# Reason: This is a base64-encoded public configuration value, not a secret. Source: public documentation.
# Approved-By: Security Team
# Date: 2024-03-10
# Review-Date: 2025-03-10
src/config/defaults.py:88
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
