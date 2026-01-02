# Override Guide — Managing False Positives and Accepted Risks

## Overview
SCA supports suppressing security findings through the **OVERRIDE.md** file in your control directory. This allows you to:
- Document **accepted risks** with business justification
- Suppress **false positives** with technical explanations
- Exclude **test/development artifacts** that don't apply to production

---

## How It Works

1. **OVERRIDE.md** - You maintain this file manually
   - Located in `sec-ctrl/OVERRIDE.md` (or your custom `--ctrl-dir`)
   - Contains patterns/paths of findings to suppress
   - MUST include justification for each override

2. **Audit Processing** - SCA reads OVERRIDE.md during each audit
   - Findings matching override patterns are excluded from reports
   - Audit agent is instructed to skip these findings

3. **SUGGESTIONS.md** - Auto-generated remediation guidance
   - Created after each audit
   - Contains only findings NOT in OVERRIDE.md
   - Includes concrete fix suggestions from the report

---

## OVERRIDE.md Format

### Required Elements
Each override entry MUST include:
- **File path or pattern**: Uniquely identifies the finding
- **Reason**: Why this is acceptable (business/technical justification)
- **Approver**: Who authorized this override (name + date)
- **Review date**: When to re-evaluate this decision

### Example Entry
```markdown
# Override: Hardcoded test API key in fixture
# File: tests/fixtures/mock_stripe_key.json
# Reason: Mock credential for integration tests, not a real Stripe key
#         Value is "sk_test_MOCK12345", clearly marked as test-only
# Approved: Security Team (Alice), 2024-01-15
# Review: 2025-01-15
tests/fixtures/mock_stripe_key.json
```

### Pattern Matching
The override system matches **substrings** in findings. Examples:

**Exact file path**:
```
src/config/development.py:12
```
Suppresses finding at exactly line 12 in that file.

**File pattern**:
```
tests/fixtures/
```
Suppresses all findings in the `tests/fixtures/` directory.

**Description keyword**:
```
localhost HTTP connection
```
Suppresses findings with "localhost HTTP connection" in description.

---

## Use Cases

### 1. Test Fixtures with Mock Credentials
```markdown
# Override: Mock API keys in test suite
# Files: tests/fixtures/*.json
# Reason: Test fixtures containing deliberately fake credentials
#         - All keys prefixed with "test_" or "mock_"
#         - Not used in production code paths
#         - Required for integration test coverage
# Approved: QA Lead (Bob), 2024-02-10
# Review: 2024-08-10
tests/fixtures/
```

### 2. Development-Only Configuration
```markdown
# Override: HTTP localhost in development config
# File: config/development.yml:8
# Reason: Local development server on http://localhost:3000
#         - Only used when NODE_ENV=development
#         - Production config uses HTTPS
#         - Separated by environment-specific config files
# Approved: DevOps (Carol), 2024-01-20
# Review: 2024-07-20
config/development.yml:8 - http://localhost
```

### 3. Accepted Business Risk (High Severity)
```markdown
# Override: User emails logged in audit trail
# File: src/auth/audit.py:45
# Reason: Regulatory requirement for SOC2 compliance audit trail
#         - Logs include user email + action + timestamp
#         - Logs encrypted at rest (AES-256)
#         - Access restricted to security team (RBAC)
#         - 90-day retention with auto-deletion
#         - Annual compliance audit reviews log access
# Approved: CISO (David), 2024-03-01
# Review: 2024-09-01 (quarterly review for High severity)
# Mitigation: Encrypted storage, RBAC, retention policy
src/auth/audit.py:45 - email logging
```

### 4. Mitigated Vulnerability
```markdown
# Override: SQL injection risk mitigated by WAF
# File: api/legacy/search.php:102
# Reason: Legacy endpoint with string concatenation in SQL
#         - Cannot refactor without breaking API compatibility
#         - Protected by AWS WAF with SQL injection rule set
#         - Rate limited to 10 req/min per IP
#         - Monitoring alerts on suspicious patterns
#         - Scheduled for deprecation in Q3 2024
# Approved: Engineering Manager (Eve), 2024-01-10
# Review: 2024-04-10 (monthly until deprecated)
# Mitigation: WAF protection, rate limiting, monitoring, deprecation plan
api/legacy/search.php:102
```

### 5. False Positive (Technical Explanation)
```markdown
# Override: False positive - "password" variable is not a credential
# File: src/utils/validation.py:78
# Reason: Variable named "password_policy" contains password complexity rules,
#         not actual passwords. Contains strings like "min_length: 12".
#         Static analyzer flagged variable name, but content is safe.
# Approved: Security Engineer (Frank), 2024-02-15
# Review: 2024-08-15
src/utils/validation.py:78 - password_policy
```

---

## Override Governance

### Approval Requirements

| Severity | Approver Required | Review Frequency |
|----------|-------------------|------------------|
| **Critical** | CISO or Security VP | Monthly |
| **High** | Security Team Lead | Quarterly |
| **Medium** | Senior Engineer + Security Review | Semi-annually |
| **Low** | Engineering Manager | Annually |

### Review Process
1. **Initial approval**: Add to OVERRIDE.md with justification
2. **Periodic review**: Check if override is still valid
3. **Update or remove**: Either extend review date or delete override
4. **Audit trail**: Track changes in git history

### Auto-Expiration
Consider adding review dates to trigger alerts:
```bash
# Check for expired overrides
grep "Review:" sec-ctrl/OVERRIDE.md | while read line; do
  review_date=$(echo "$line" | grep -oP '\d{4}-\d{2}-\d{2}')
  if [[ "$review_date" < "$(date +%Y-%m-%d)" ]]; then
    echo "EXPIRED OVERRIDE: $line"
  fi
done
```

---

## Anti-Patterns (What NOT to Do)

### ❌ BAD: No Justification
```markdown
# Override: SQL injection
src/api/search.py:45
```
**Problem**: No reason given, no approver, no review date

### ❌ BAD: Vague Justification
```markdown
# Override: Legacy code, will fix later
# File: src/legacy/
# Reason: Old code
src/legacy/
```
**Problem**: "Will fix later" is not an accepted risk, no timeline, too broad

### ❌ BAD: Suppressing Critical Without Mitigation
```markdown
# Override: Hardcoded production API key
# File: src/config/prod.py:10
# Reason: Easier than using environment variables
# Approved: Developer (Greg), 2024-01-01
src/config/prod.py:10
```
**Problem**: Critical security issue with invalid justification, no mitigation plan

### ❌ BAD: Overly Broad Pattern
```markdown
# Override: All password-related findings
password
```
**Problem**: Suppresses ALL findings containing "password", not specific enough

---

## SUGGESTIONS.md — Auto-Generated Remediations

After each audit, SCA generates **SUGGESTIONS.md** containing:
- All confirmed findings (Critical → Low)
- Findings requiring review (Suspicious)
- **Excludes** findings in OVERRIDE.md
- Concrete remediation steps from the report

### Using SUGGESTIONS.md

**Workflow**:
1. Run `sca audit`
2. Review `sec-ctrl/SUGGESTIONS.md`
3. Assign fixes to team members
4. Fix issues or add to OVERRIDE.md if accepted risk
5. Re-run `sca audit` to verify fixes
6. Repeat

**Example SUGGESTIONS.md**:
```markdown
# Security Audit Remediation Suggestions

## Confirmed Findings (Prioritized)

### Critical

**Evidence**: `src/auth/login.py:45`
```python
logger.info(f"User {username} logged in with password {password}")
```

**Remediation**:
```python
# Remove password from logs entirely
logger.info(f"User {username} logged in successfully")
```

### High

**Evidence**: `src/api/db.py:12`
```python
conn = psycopg2.connect("host=db.prod.com dbname=app user=admin password=secret")
```

**Remediation**:
```python
# Add SSL/TLS and use environment variables
conn = psycopg2.connect(
    host=os.environ['DB_HOST'],
    dbname=os.environ['DB_NAME'],
    user=os.environ['DB_USER'],
    password=os.environ['DB_PASSWORD'],
    sslmode='verify-full',
    sslrootcert='/path/to/ca.pem'
)
```
```

### Tracking Progress
- **Option 1**: Edit SUGGESTIONS.md, mark completed items
  ```markdown
  ### ✅ Fixed: Password in logs
  ~~`src/auth/login.py:45`~~
  Fixed in commit abc1234
  ```

- **Option 2**: Delete fixed items from SUGGESTIONS.md
  (File is regenerated each audit)

- **Option 3**: Use issue tracker
  - Create tickets from SUGGESTIONS.md
  - Link ticket IDs in OVERRIDE.md if accepted

---

## Best Practices

### 1. Be Specific
✅ Good: `tests/fixtures/api_key.json:5 - mock Stripe key`
❌ Bad: `api_key`

### 2. Always Justify
Every override MUST answer: "Why is this safe?"

### 3. Set Review Dates
Critical/High: 3-6 months
Medium/Low: 6-12 months

### 4. Use Git for Audit Trail
- Commit OVERRIDE.md changes with meaningful messages
- Tag approvers in commit messages or PR descriptions
- Review OVERRIDE.md changes in code review

### 5. Limit Scope
Override specific instances, not broad categories

### 6. Document Mitigations
If accepting risk, document compensating controls

### 7. Periodic Cleanup
Quarterly: Review all overrides, remove obsolete entries

---

## Integration with CI/CD

### GitHub Actions Example
```yaml
- name: Security Audit
  run: sca audit

- name: Check for High/Critical Findings
  run: |
    # Exit 2 means Critical/High findings exist
    if [ $? -eq 2 ]; then
      echo "::warning::Critical or High findings detected"
      echo "Review sec-ctrl/SUGGESTIONS.md for remediation guidance"
      exit 1
    fi

- name: Upload Suggestions
  if: failure()
  uses: actions/upload-artifact@v3
  with:
    name: security-suggestions
    path: sec-ctrl/SUGGESTIONS.md
```

### Pre-commit Hook
```bash
#!/bin/bash
# .git/hooks/pre-commit

# Ensure OVERRIDE.md changes are reviewed
if git diff --cached --name-only | grep -q "sec-ctrl/OVERRIDE.md"; then
  echo "⚠️  OVERRIDE.md modified - ensure security team approval"
  echo "Modified overrides:"
  git diff --cached sec-ctrl/OVERRIDE.md | grep "^+# Override"
  read -p "Approved by security team? (y/n) " -n 1 -r
  echo
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "❌ Aborting commit - get security approval first"
    exit 1
  fi
fi
```

---

## FAQ

**Q: Can I override Critical severity findings?**
A: Yes, but requires CISO approval and must include compensating controls. Review monthly.

**Q: What if I disagree with a finding?**
A: Add to OVERRIDE.md with technical explanation why it's a false positive. Include approver.

**Q: How do I know if an override is still valid?**
A: Check the review date. Run periodic audits of OVERRIDE.md using the auto-expiration script.

**Q: Can I use wildcards in overrides?**
A: Partial string matching is supported, but be specific. Avoid overly broad patterns.

**Q: What happens if I delete OVERRIDE.md?**
A: All previously suppressed findings will reappear in the next audit report.

**Q: How do I track fixed items from SUGGESTIONS.md?**
A: Either edit SUGGESTIONS.md to mark completed (it's regenerated each run) or use an issue tracker.

---

## Support

For questions about override policies:
- **Security Team**: security@example.com
- **SCA Issues**: https://github.com/your-org/sca/issues
- **Documentation**: See `sec-ctrl/README.md` in your repository
