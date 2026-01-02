# Security Standards Mapping Invariant (v1)

## Overview

Every security finding MUST be tagged with a reference to established security standards (CWE, CVE, OWASP, etc.) or assigned a unique SCA identifier.

**Purpose**: Enable compliance mapping, risk scoring, cross-referencing, and remediation tracking.

---

## CRITICAL: All Findings Must Reference Standards

### Required Standard References

Each finding MUST include at least one of the following:

**Industry Standards**:
- **CWE** (Common Weakness Enumeration) - e.g., CWE-89 (SQL Injection)
- **CVE** (Common Vulnerabilities and Exposures) - e.g., CVE-2017-14124
- **OWASP** (Open Web Application Security Project) - e.g., OWASP-A01:2021
- **CAPEC** (Common Attack Pattern Enumeration) - e.g., CAPEC-66
- **NIST** (National Institute of Standards) - e.g., NIST SP 800-53 AC-3
- **PCI-DSS** (Payment Card Industry) - e.g., PCI-DSS 6.5.1
- **MITRE ATT&CK** - e.g., T1190 (Exploit Public-Facing Application)

**SCA Identifiers** (when no standard exists):
- **Format**: `SCA-XXX` where XXX is a unique 3-digit number
- **Range**: SCA-001 through SCA-999
- **Assignment**: Sequentially assigned, never reused

---

## SCA Identifier Registry

### Active Identifiers

| ID | Title | Severity | Category | Status |
|----|-------|----------|----------|--------|
| SCA-001 | Unencrypted sensitive data in logs | High | Data Protection | Active |
| SCA-002 | Missing documentation for security-critical functions | Medium | Documentation | Active |
| SCA-003 | LLM prompt injection via DAN attack | Critical | LLM Security | Active |
| SCA-004 | Format-Preserving Encryption using deprecated FF3 | Critical | Cryptography | Active |
| SCA-005 | Jailbreak attempt via token smuggling | High | LLM Security | Active |
| SCA-006 | Missing man page for CLI command | Low | Documentation | Active |
| SCA-007 | Configuration file without schema documentation | Medium | Documentation | Active |
| SCA-008 | Environment variable without .env.example | Medium | Documentation | Active |
| SCA-009 | Agent directory writable (immutability violation) | Critical | System Integrity | Active |
| SCA-010 | Control directory included in analysis scope | Critical | System Integrity | Active |

### Reserved Blocks

- **SCA-001 to SCA-099**: Core security issues
- **SCA-100 to SCA-199**: Cryptography and key management
- **SCA-200 to SCA-299**: Data protection and privacy
- **SCA-300 to SCA-399**: Authentication and authorization
- **SCA-400 to SCA-499**: LLM and AI security
- **SCA-500 to SCA-599**: Documentation and configuration
- **SCA-600 to SCA-699**: Language-specific issues
- **SCA-700 to SCA-799**: Compliance and governance
- **SCA-800 to SCA-899**: Infrastructure and deployment
- **SCA-900 to SCA-999**: Reserved for future use

---

## Finding Report Format

### Required Fields

Every finding MUST include:

```markdown
### [Severity]: [Title]

**Standard**: [CWE-XXX | CVE-XXXX-XXXXX | OWASP-XXX | SCA-XXX]
**Category**: [Category from taxonomy]
**Severity**: [Critical | High | Medium | Low]

**Evidence**: `file_path:line_number`
```code
[Code snippet showing the issue]
```

**Impact**:
- [Specific security risk]
- [Potential exploitation scenario]

**Remediation**:
```code
[Fixed code example]
```

**References**:
- [Standard specification URL]
- [Related vulnerabilities or attacks]

**Compliance**:
- [Relevant compliance requirements: PCI-DSS, HIPAA, GDPR, etc.]
```

### Examples

#### Example 1: Finding with CWE Reference

```markdown
### Critical: SQL Injection in User Query

**Standard**: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)
**Category**: Injection Vulnerabilities
**Severity**: Critical

**Evidence**: `src/api/users.py:45`
```python
query = f"SELECT * FROM users WHERE username = '{username}'"
cursor.execute(query)
```

**Impact**:
- Attacker can execute arbitrary SQL commands
- Complete database compromise possible
- Data exfiltration, modification, or deletion

**Remediation**:
```python
query = "SELECT * FROM users WHERE username = ?"
cursor.execute(query, (username,))
```

**References**:
- CWE-89: https://cwe.mitre.org/data/definitions/89.html
- OWASP A03:2021 - Injection
- CAPEC-66: SQL Injection

**Compliance**:
- PCI-DSS 6.5.1: Injection flaws
- OWASP Top 10 2021 A03
```

#### Example 2: Finding with OWASP LLM Reference

```markdown
### Critical: LLM Prompt Injection via User Input

**Standard**: OWASP-LLM-01 (Prompt Injection)
**Category**: LLM Security
**Severity**: Critical

**Evidence**: `src/chatbot/handler.py:23`
```python
prompt = f"You are a helpful assistant. User asks: {user_input}"
response = llm.complete(prompt)
```

**Impact**:
- Attacker can override system instructions
- Bypass safety guardrails
- Extract system prompts or training data
- Unauthorized tool/function access

**Remediation**:
```python
messages = [
    {"role": "system", "content": "You are a helpful assistant."},
    {"role": "user", "content": sanitize_input(user_input)}
]
response = llm.chat(messages)
```

**References**:
- OWASP LLM Top 10: https://owasp.org/www-project-top-10-for-large-language-model-applications/
- MITRE ATLAS: AML.T0051 (LLM Prompt Injection)

**Compliance**:
- NIST AI RMF: Govern 1.1, Map 1.1
- ISO/IEC 42001: AI risk management
```

#### Example 3: Finding with CVE Reference

```markdown
### Critical: Use of Vulnerable FF3 Format-Preserving Encryption

**Standard**: CVE-2017-14124, SCA-004
**Category**: Cryptography
**Severity**: Critical

**Evidence**: `src/crypto/tokenization.py:67`
```python
from pyffx import FF3
cipher = FF3(key, tweak)
token = cipher.encrypt(credit_card_number)
```

**Impact**:
- FF3 has known cryptanalysis attacks (Durak & Vaudenay, 2017)
- Practical plaintext recovery with ~2^32 chosen plaintexts
- Complete loss of tokenization confidentiality

**Remediation**:
```python
from pyffx import FF1
cipher = FF1(key, radix=10)
tweak = f"merchant:{merchant_id}:card".encode()
token = cipher.encrypt(credit_card_number, tweak)
```

**References**:
- CVE-2017-14124: https://nvd.nist.gov/vuln/detail/CVE-2017-14124
- CWE-327: Use of Broken or Risky Cryptographic Algorithm
- NIST SP 800-38G: Recommendation for FF1 (approved)

**Compliance**:
- PCI-DSS 3.5.1: Protect stored cardholder data with strong cryptography
- NIST FIPS 140-2: Approved cryptographic algorithms only
```

#### Example 4: Finding with SCA Identifier (No Standard Exists)

```markdown
### Medium: Missing CLI Command Documentation

**Standard**: SCA-006
**Category**: Documentation Completeness
**Severity**: Medium

**Evidence**: `bin/custom-tool.sh`
```bash
#!/bin/bash
# No --help flag, no man page, no examples

do_something() {
    # ... implementation ...
}

do_something
```

**Impact**:
- Users unable to discover command usage
- Increased likelihood of misuse
- Higher support burden
- Prevents effective security review

**Remediation**:
Add --help flag and create man page:
```bash
#!/bin/bash

usage() {
    cat <<EOF
Usage: custom-tool.sh [OPTIONS]

Options:
    -h, --help     Show this help message
    -v, --verbose  Enable verbose output

Examples:
    custom-tool.sh --verbose
EOF
}

[[ "$1" = "-h" ]] || [[ "$1" = "--help" ]] && usage && exit 0

do_something() {
    # ... implementation ...
}

do_something
```

Also create: docs/man/custom-tool.1

**References**:
- SCA Documentation Completeness Invariant
- POSIX.1-2017: Utility Conventions

**Compliance**:
- SOC 2 CC6.1: Logical and physical access controls (documentation requirement)
- ISO 27001 A.12.1.1: Documented operating procedures
```

---

## Mapping to Existing Standards

### CWE (Common Weakness Enumeration)

**Most Common CWEs in SCA Audits**:

| CWE | Title | SCA Invariant |
|-----|-------|---------------|
| CWE-78 | OS Command Injection | global.md, languages/*.md |
| CWE-79 | Cross-site Scripting (XSS) | global.md |
| CWE-89 | SQL Injection | global.md, languages/*.md |
| CWE-94 | Improper Control of Generation of Code | languages/python.md (eval, exec) |
| CWE-119 | Improper Restriction of Operations within Memory Buffer | languages/c-cpp.md |
| CWE-190 | Integer Overflow or Wraparound | languages/c-cpp.md |
| CWE-200 | Exposure of Sensitive Information | data-protection/*.md |
| CWE-259 | Use of Hard-coded Password | crypto/secrets.md |
| CWE-287 | Improper Authentication | global.md |
| CWE-295 | Improper Certificate Validation | global.md |
| CWE-311 | Missing Encryption of Sensitive Data | data-protection/database.md |
| CWE-312 | Cleartext Storage of Sensitive Information | data-protection/*.md |
| CWE-326 | Inadequate Encryption Strength | crypto/WEAK_ALGORITHMS.md |
| CWE-327 | Use of Broken Cryptographic Algorithm | crypto/WEAK_ALGORITHMS.md |
| CWE-330 | Use of Insufficiently Random Values | crypto/secrets.md, languages/*.md |
| CWE-416 | Use After Free | languages/c-cpp.md |
| CWE-476 | NULL Pointer Dereference | languages/c-cpp.md, languages/java.md |
| CWE-502 | Deserialization of Untrusted Data | languages/java.md, languages/python.md |
| CWE-521 | Weak Password Requirements | global.md |
| CWE-798 | Use of Hard-coded Credentials | crypto/secrets.md |
| CWE-917 | Improper Neutralization of Special Elements (Expression Language Injection) | global.md |
| CWE-1004 | Sensitive Cookie Without HttpOnly Flag | global.md |

### OWASP Top 10 (2021)

| OWASP ID | Title | SCA Invariants |
|----------|-------|----------------|
| A01:2021 | Broken Access Control | global.md (authorization) |
| A02:2021 | Cryptographic Failures | crypto/*.md |
| A03:2021 | Injection | global.md, languages/*.md |
| A04:2021 | Insecure Design | global.md |
| A05:2021 | Security Misconfiguration | global.md (SSL/TLS, CORS, CSP) |
| A06:2021 | Vulnerable and Outdated Components | (deps-scan.sh) |
| A07:2021 | Identification and Authentication Failures | global.md |
| A08:2021 | Software and Data Integrity Failures | global.md (deserialization) |
| A09:2021 | Security Logging and Monitoring Failures | data-protection/logging.md |
| A10:2021 | Server-Side Request Forgery (SSRF) | global.md, languages/python.md |

### OWASP LLM Top 10 (2023)

| OWASP LLM ID | Title | SCA Invariants |
|--------------|-------|----------------|
| LLM01 | Prompt Injection | llm/global.md (jailbreaking) |
| LLM02 | Insecure Output Handling | llm/global.md |
| LLM03 | Training Data Poisoning | llm/global.md |
| LLM04 | Model Denial of Service | llm/global.md |
| LLM05 | Supply Chain Vulnerabilities | llm/global.md (pickle, untrusted models) |
| LLM06 | Sensitive Information Disclosure | llm/global.md |
| LLM07 | Insecure Plugin Design | llm/global.md (tool security) |
| LLM08 | Excessive Agency | llm/global.md (autonomous agents) |
| LLM09 | Over-reliance | llm/global.md |
| LLM10 | Model Theft | llm/global.md |

### PCI-DSS v4.0

| Requirement | Title | SCA Invariants |
|-------------|-------|----------------|
| 3.3.1 | Encrypt cardholder data | data-protection/database.md |
| 3.5.1 | Use strong cryptography | crypto/WEAK_ALGORITHMS.md, crypto/FPE.md |
| 6.2.4 | Secure coding practices | global.md, all invariants |
| 6.4.1 | Detect and prevent web attacks | global.md (injection, XSS) |
| 6.4.2 | Automated security testing | (SCA audit workflow) |
| 8.3.6 | Authentication mechanisms | global.md |
| 11.3.1 | External penetration testing | (SCA as automated testing) |

---

## Audit Report Requirements

### Mandatory Standard References

The audit report MUST include a standards mapping section:

```markdown
## Standards Mapping

This audit detected violations of the following security standards:

### CWE (Common Weakness Enumeration)
- CWE-89 (SQL Injection): 3 instances
- CWE-327 (Broken Cryptography): 2 instances
- CWE-798 (Hard-coded Credentials): 1 instance

### OWASP Top 10 (2021)
- A03:2021 (Injection): 3 instances
- A02:2021 (Cryptographic Failures): 2 instances

### OWASP LLM Top 10 (2023)
- LLM01 (Prompt Injection): 1 instance

### SCA Custom Identifiers
- SCA-006 (Missing CLI Documentation): 2 instances

### Compliance Impact
- **PCI-DSS**: Non-compliant (5 findings affect requirements 3.5.1, 6.4.1)
- **HIPAA**: Non-compliant (2 findings affect § 164.312(a)(2)(iv))
- **GDPR**: At risk (1 finding affects Art. 32 security requirements)
- **SOC 2**: Review required (2 findings affect CC6.1)
```

### Standard Reference Format

Each finding in the report MUST use this format:

```markdown
### [Severity]: [Title] ([Standard Reference])
```

Examples:
```markdown
### Critical: SQL Injection in User Query (CWE-89)

### High: Use of MD5 for Password Hashing (CWE-327, PCI-DSS 3.5.1)

### Critical: LLM Prompt Injection (OWASP-LLM-01, SCA-003)

### Medium: Missing API Documentation (SCA-007)
```

---

## Assigning New SCA Identifiers

### Process

1. **Check for existing standard**:
   - Search CWE database: https://cwe.mitre.org/
   - Check OWASP projects: https://owasp.org/
   - Review CVE list for specific vulnerabilities
   - Check CAPEC for attack patterns

2. **If no standard exists**:
   - Reserve next available SCA-XXX identifier
   - Document in this registry
   - Include in audit report

3. **Update registry**:
   - Add entry to table above
   - Assign to appropriate block (001-099, 100-199, etc.)
   - Mark status as "Active"
   - Include category and severity

4. **Cross-reference**:
   - Link to relevant invariant file
   - Note similar/related standards if any
   - Document typical remediation approach

### Example: Adding New SCA Identifier

```markdown
# Discovered new issue: Missing security headers in HTTP responses
# (not directly covered by existing CWE/OWASP)

# Step 1: Check standards
# - CWE-16 (Configuration) is too broad
# - OWASP A05:2021 (Security Misconfiguration) is too general
# - No specific CWE for missing security headers

# Step 2: Assign SCA identifier
# Next available in 001-099 block: SCA-011

# Step 3: Update registry
| SCA-011 | Missing HTTP security headers | High | Web Security | Active |

# Step 4: Document
**SCA-011**: Missing HTTP Security Headers

**Description**: HTTP responses lack security headers (X-Frame-Options,
X-Content-Type-Options, Content-Security-Policy, etc.)

**Severity**: High

**Related Standards**:
- OWASP A05:2021 (Security Misconfiguration) - partial coverage
- CWE-16 (Configuration) - too general

**Remediation**: Add security headers to all HTTP responses

**Invariant**: global.md (to be added)
```

---

## Validation

### Pre-Commit Hook

Validate all findings have standard references:

```bash
#!/bin/bash
# .git/hooks/pre-commit

# Check invariant files for standard references
for file in invariants/**/*.md; do
    # Extract finding titles
    findings=$(grep "^### " "$file" | grep -v "^### Good" | grep -v "^### Example")

    while IFS= read -r finding; do
        # Check if finding has standard reference
        if ! echo "$finding" | grep -qE '\((CWE-[0-9]+|CVE-[0-9]{4}-[0-9]+|OWASP-[A-Z0-9]+|SCA-[0-9]{3}|PCI-DSS|CAPEC-[0-9]+)\)'; then
            echo "ERROR: Finding lacks standard reference in $file:"
            echo "  $finding"
            echo ""
            echo "Add one of: CWE-XXX, CVE-XXXX-XXXXX, OWASP-XXX, SCA-XXX"
            exit 1
        fi
    done <<< "$findings"
done
```

### Audit Report Validation

Ensure all findings in report have standards:

```bash
# In sec-audit.sh, after report generation
validate_standards() {
    local report="$1"

    # Extract all finding titles
    findings=$(grep "^### " "$report" | grep -E "Critical|High|Medium|Low")

    while IFS= read -r finding; do
        if ! echo "$finding" | grep -qE '\((CWE-[0-9]+|CVE-[0-9]{4}-[0-9]+|OWASP-[A-Z0-9]+|SCA-[0-9]{3})\)'; then
            log_warn "Finding lacks standard reference: $finding"
            log_warn "Report may be incomplete"
        fi
    done <<< "$findings"
}
```

---

## Benefits

### Compliance Mapping
- Direct mapping to PCI-DSS, HIPAA, GDPR requirements
- Easier auditor review (recognized standards)
- Evidence for compliance certifications

### Risk Scoring
- CWE has CVSS base scores
- Enables automated risk calculation
- Prioritization based on industry severity

### Cross-Referencing
- Link to vendor advisories using CVE
- Reference detailed CWE descriptions
- Connect to MITRE ATT&CK tactics

### Remediation Tracking
- Track fixes by standard (e.g., "fixed all CWE-89 instances")
- Measure progress on OWASP Top 10 coverage
- Report on compliance gap closure

### Industry Communication
- Use industry-standard terminology
- Easier communication with security teams
- Better integration with vulnerability management tools

---

## Tools Integration

### SARIF Output

When generating SARIF reports, include standard references:

```json
{
  "results": [
    {
      "ruleId": "SCA-001",
      "message": {
        "text": "Unencrypted sensitive data in logs"
      },
      "properties": {
        "cwe": ["CWE-312"],
        "owasp": ["A09:2021"],
        "pci-dss": ["12.3.1"],
        "sca-id": "SCA-001"
      }
    }
  ]
}
```

### SIEM Integration

Export findings with standard tags:

```json
{
  "timestamp": "2024-01-15T12:00:00Z",
  "severity": "Critical",
  "standard": "CWE-89",
  "category": "Injection",
  "file": "src/api/users.py",
  "line": 45,
  "sca_id": null
}
```

---

## Summary

**Every finding MUST include**:
1. Standard reference (CWE, CVE, OWASP, PCI-DSS, CAPEC, NIST) when applicable
2. SCA-XXX identifier when no standard exists
3. Category classification
4. Compliance impact statement

**Benefits**:
- Compliance mapping (PCI-DSS, HIPAA, GDPR, SOC 2)
- Risk scoring and prioritization
- Industry-standard communication
- Integration with security tools (SIEM, vulnerability management)
- Remediation tracking and metrics

**SCA Identifier Format**: `SCA-XXX` (001-999)
**Registry**: Maintained in this file (invariants/meta/standards-mapping.md)
**Validation**: Pre-commit hooks and audit report checks
