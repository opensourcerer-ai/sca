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
- **SCA-900 to SCA-999**: Supply chain and dependencies
- **SCA-1000 to SCA-2000**: AI Agents and MCP (Model Context Protocol) Security

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

### NIST SP 800-53 Rev 5 (Security and Privacy Controls)

**Control Families Mapped to SCA Invariants**:

| Family | Title | Key Controls | SCA Invariants |
|--------|-------|--------------|----------------|
| **AC** | Access Control | AC-2 (Account Management), AC-3 (Access Enforcement), AC-6 (Least Privilege), AC-7 (Login Attempts), AC-11 (Session Lock) | **authentication.md** (NEW), global.md |
| **AU** | Audit and Accountability | AU-2 (Event Logging), AU-3 (Content of Audit Records), AU-6 (Audit Review), AU-9 (Protection of Audit Info) | data-protection/logging.md, **audit-logging.md** (NEW) |
| **AT** | Awareness and Training | AT-2 (Training), AT-3 (Role-based Training) | documentation/completeness.md |
| **CA** | Assessment, Authorization | CA-2 (Security Assessments), CA-7 (Continuous Monitoring) | (SCA audit workflow) |
| **CM** | Configuration Management | CM-2 (Baseline Config), CM-3 (Change Control), CM-6 (Configuration Settings), CM-7 (Least Functionality) | **configuration-management.md** (NEW) |
| **CP** | Contingency Planning | CP-9 (Backup), CP-10 (System Recovery) | (operational controls) |
| **IA** | Identification and Authentication | IA-2 (User Identification), IA-5 (Authenticator Management), IA-8 (Identification Assertion) | **authentication.md** (NEW), crypto/secrets.md |
| **IR** | Incident Response | IR-4 (Incident Handling), IR-5 (Monitoring), IR-6 (Reporting) | **incident-response.md** (NEW) |
| **MA** | Maintenance | MA-2 (Controlled Maintenance), MA-4 (Remote Maintenance) | (operational controls) |
| **MP** | Media Protection | MP-6 (Media Sanitization) | **media-protection.md** (NEW) |
| **PS** | Personnel Security | PS-7 (Third-Party Personnel) | (organizational controls) |
| **PE** | Physical Protection | PE-2 (Physical Access), PE-3 (Access Control) | (physical controls, limited code audit) |
| **PL** | Planning | PL-2 (System Security Plan), PL-8 (Security Architecture) | documentation/completeness.md |
| **PM** | Program Management | PM-11 (Mission/Business Focus) | (organizational controls) |
| **RA** | Risk Assessment | RA-3 (Risk Assessment), RA-5 (Vulnerability Monitoring) | (SCA audit workflow), **risk-assessment.md** (NEW) |
| **SA** | System and Services Acquisition | SA-8 (Security Engineering), SA-11 (Developer Testing), SA-12 (Supply Chain Protection), SA-15 (Development Process) | **supply-chain.md** (NEW), documentation/completeness.md |
| **SC** | System and Communications Protection | SC-7 (Boundary Protection), SC-8 (Transmission Confidentiality), SC-12 (Cryptographic Key Establishment), SC-13 (Cryptographic Protection), SC-28 (Protection of Info at Rest) | global.md (TLS/SSL), crypto/*.md, data-protection/database.md |
| **SI** | System and Information Integrity | SI-3 (Malicious Code Protection), SI-4 (System Monitoring), SI-7 (Software Integrity), SI-10 (Information Input Validation), SI-16 (Memory Protection) | global.md (injection, validation), languages/c-cpp.md, **supply-chain.md** (NEW) |
| **SR** | Supply Chain Risk Management | SR-3 (Supply Chain Controls), SR-4 (Provenance), SR-5 (Acquisition Strategies), SR-6 (Supplier Assessments), SR-11 (Component Authenticity) | **supply-chain.md** (NEW) |
| **PT** | Privacy Controls | PT-2 (Authority to Process PII), PT-3 (PII Processing Purposes), PT-5 (Privacy Notice), PT-6 (System of Records Notice), PT-7 (Redress) | **privacy.md** (NEW), data-protection/*.md |

**Critical Controls Requiring New Invariants**:
- **AC-3**: Access enforcement - Need access-control.md
- **IA-5**: Authenticator management - Need authentication.md
- **AU-2/AU-9**: Comprehensive audit logging - Need audit-logging.md
- **SA-12/SR-3**: Supply chain protection - Need supply-chain.md
- **PT-2/PT-3**: PII processing - Need privacy.md
- **CM-6/CM-7**: Configuration hardening - Need configuration-management.md

### NIST Cybersecurity Framework (CSF) 2.0

**Six Core Functions Mapped to SCA**:

| Function | Categories | SCA Coverage |
|----------|-----------|--------------|
| **GOVERN (GV)** | Organizational cybersecurity strategy, expectations, policy | documentation/completeness.md, **governance.md** (NEW) |
| **IDENTIFY (ID)** | Asset Management (ID.AM), Risk Assessment (ID.RA), Supply Chain (ID.SC) | **asset-inventory.md** (NEW), **supply-chain.md** (NEW) |
| **PROTECT (PR)** | Access Control (PR.AC), Data Security (PR.DS), Platform Security (PR.PS) | **authentication.md** (NEW), crypto/*.md, data-protection/*.md, global.md |
| **DETECT (DE)** | Continuous Monitoring (DE.CM), Adverse Event Analysis (DE.AE) | data-protection/logging.md, **detection.md** (NEW) |
| **RESPOND (RS)** | Incident Management (RS.MA), Incident Analysis (RS.AN), Response Reporting (RS.CO) | **incident-response.md** (NEW) |
| **RECOVER (RC)** | Incident Recovery (RC.RP), Recovery Communications (RC.CO) | (operational controls) |

**Detailed Mappings**:

**PROTECT Function** (Most relevant for code audit):
- **PR.AC-1**: Identities and credentials managed → **authentication.md** (NEW), crypto/secrets.md
- **PR.AC-3**: Remote access managed → global.md (TLS/SSL)
- **PR.AC-4**: Access permissions managed → **access-control.md** (NEW)
- **PR.DS-1**: Data at rest protected → data-protection/database.md, crypto/*.md
- **PR.DS-2**: Data in transit protected → global.md (TLS/SSL)
- **PR.DS-5**: Protections against data leaks → data-protection/logging.md
- **PR.DS-6**: Integrity checking mechanisms → **supply-chain.md** (NEW)
- **PR.PS-1**: Configuration management → **configuration-management.md** (NEW)

**DETECT Function**:
- **DE.CM-1**: Networks and network services monitored → **detection.md** (NEW)
- **DE.CM-3**: Personnel activity monitored → data-protection/logging.md
- **DE.CM-4**: Malicious code detected → **supply-chain.md** (NEW)

### NIST SP 800-171 Rev 2 (Protecting CUI)

**Requirements for Controlled Unclassified Information**:

| Req | Title | SCA Invariants |
|-----|-------|----------------|
| **3.1.x** | Access Control | **access-control.md** (NEW), **authentication.md** (NEW) |
| **3.3.x** | Audit and Accountability | data-protection/logging.md, **audit-logging.md** (NEW) |
| **3.4.x** | Configuration Management | **configuration-management.md** (NEW) |
| **3.5.x** | Identification and Authentication | **authentication.md** (NEW), crypto/secrets.md |
| **3.10.x** | Physical Protection | (physical controls) |
| **3.11.x** | Risk Assessment | **risk-assessment.md** (NEW) |
| **3.12.x** | Security Assessment | (SCA audit workflow) |
| **3.13.x** | System and Communications Protection | global.md (TLS/SSL), crypto/*.md, **cui-protection.md** (NEW) |
| **3.14.x** | System and Information Integrity | global.md (validation), languages/*.md, **system-integrity.md** (NEW) |

**CUI-Specific Requirements**:
- **3.13.11**: Cryptographic mechanisms to protect CUI → crypto/WEAK_ALGORITHMS.md, data-protection/database.md
- **3.13.16**: Protect CUI at rest → data-protection/database.md, **cui-protection.md** (NEW)
- **3.14.1**: Identify and manage flaws → **supply-chain.md** (NEW)
- **3.14.2**: Identify malicious content → **supply-chain.md** (NEW)
- **3.14.3**: Monitor system security alerts → **detection.md** (NEW)

### NIST AI Risk Management Framework (AI RMF)

**Four Core Functions for AI Systems** (Critical for LLM invariants):

| Function | Activities | SCA Invariants |
|----------|-----------|----------------|
| **GOVERN** | Policies, processes, and procedures for AI governance and oversight | llm/global.md, **ai-governance.md** (NEW) |
| **MAP** | Context establishment, categorization, risk identification | llm/global.md, **ai-risk-mapping.md** (NEW) |
| **MEASURE** | AI system testing, evaluation, validation, and verification (TEVV) | llm/global.md (testing), **ai-metrics.md** (NEW) |
| **MANAGE** | Risk response, monitoring, and continuous improvement | llm/global.md, **ai-monitoring.md** (NEW) |

**Key AI Risks Mapped**:
- **GOVERN-1.1**: Legal/regulatory requirements identified → llm/global.md (compliance)
- **GOVERN-1.2**: AI risk management responsibilities assigned → **ai-governance.md** (NEW)
- **MAP-1.1**: AI system context documented → **ai-risk-mapping.md** (NEW)
- **MAP-2.1**: System categorization → llm/global.md
- **MAP-3.1**: AI capabilities documented → documentation/completeness.md
- **MEASURE-1.1**: Evaluation metrics defined → **ai-metrics.md** (NEW)
- **MEASURE-2.1**: AI system tested for trustworthiness → llm/global.md (jailbreaking tests)
- **MANAGE-1.1**: Risks prioritized and responded to → llm/global.md

**Current LLM Coverage** (llm/global.md):
- ✅ Prompt injection (MAP-2.3, MEASURE-2.1)
- ✅ Jailbreaking detection (MEASURE-2.1)
- ✅ Output validation (MANAGE-2.1)
- ⚠️ Missing: Model governance documentation (GOVERN-1.2)
- ⚠️ Missing: Continuous monitoring hooks (MANAGE-4.1)

### NIST Secure Software Development Framework (SSDF)

**Practices Mapped to SCA**:

| Practice | Description | SCA Invariants |
|----------|-------------|----------------|
| **PO.1** | Prepare: Define security requirements | documentation/completeness.md, **requirements.md** (NEW) |
| **PO.3** | Prepare: Implement supporting toolchains | (SCA audit tooling) |
| **PO.5** | Prepare: Maintain secure environments | **configuration-management.md** (NEW) |
| **PS.1** | Protect Software: Protect code from unauthorized access | **access-control.md** (NEW) |
| **PS.2** | Protect Software: Provide verification for acquired software | **supply-chain.md** (NEW) |
| **PS.3** | Protect Software: Archive and protect software | **media-protection.md** (NEW) |
| **PW.1** | Produce: Design software securely | documentation/completeness.md (architecture) |
| **PW.2** | Produce: Review human-readable code | documentation/completeness.md (code review) |
| **PW.4** | Produce: Reuse existing software | **supply-chain.md** (NEW - dependency analysis) |
| **PW.5** | Produce: Create source code by trained developers | (organizational control) |
| **PW.6** | Produce: Configure software securely | **configuration-management.md** (NEW) |
| **PW.7** | Produce: Review code before release | documentation/completeness.md |
| **PW.8** | Produce: Test software | documentation/completeness.md (test documentation) |
| **PW.9** | Produce: Configure tool pipelines securely | **supply-chain.md** (NEW - build integrity) |
| **RV.1** | Respond: Identify and confirm vulnerabilities | (SCA audit workflow) |
| **RV.2** | Respond: Assess, prioritize, remediate | (SUGGESTIONS.md, OVERRIDE.md workflow) |
| **RV.3** | Respond: Analyze root causes | (audit reports) |

### FIPS Standards

**Federal Information Processing Standards**:

| FIPS | Title | SCA Invariants |
|------|-------|----------------|
| **FIPS 140-2/140-3** | Cryptographic Module Validation | crypto/WEAK_ALGORITHMS.md, crypto/secrets.md |
| **FIPS 180-4** | Secure Hash Standard (SHA-256, SHA-512) | crypto/WEAK_ALGORITHMS.md (flags MD5, SHA-1) |
| **FIPS 186-5** | Digital Signature Standard (DSA, ECDSA, EdDSA) | crypto/WEAK_ALGORITHMS.md (weak key sizes) |
| **FIPS 197** | Advanced Encryption Standard (AES) | crypto/WEAK_ALGORITHMS.md (flags DES, 3DES) |
| **FIPS 199** | Security Categorization | **risk-assessment.md** (NEW) |
| **FIPS 200** | Minimum Security Requirements | (all invariants collectively) |
| **FIPS 201-3** | PIV for Federal Employees | **authentication.md** (NEW - credential management) |

**FIPS 140-2/140-3 Approved Algorithms**:
- ✅ **Approved**: AES, SHA-256/384/512, RSA (2048+), ECDSA (P-256+), HMAC, PBKDF2
- ❌ **Disapproved**: DES, 3DES, MD5, SHA-1, RSA < 2048

Detected by: `crypto/WEAK_ALGORITHMS.md`

### NIST SP 800-63-3 (Digital Identity Guidelines)

**Authentication Assurance Levels (AAL)**:

| AAL | Requirements | SCA Checks |
|-----|-------------|------------|
| **AAL1** | Single-factor authentication | **authentication.md** (NEW - password requirements) |
| **AAL2** | Multi-factor authentication | **authentication.md** (NEW - MFA detection) |
| **AAL3** | Hardware-based authenticator | **authentication.md** (NEW - hardware token usage) |

**Authenticator Types**:
- **Memorized Secret** (passwords) → Check strength, storage (crypto/secrets.md, **authentication.md**)
- **Look-up Secret** (OTP) → Check secure generation (crypto/secrets.md)
- **Out-of-Band** (SMS, push) → Check channel security (global.md TLS)
- **Single-Factor OTP** → Check TOTP/HOTP implementation (**authentication.md**)
- **Multi-Factor** → Check MFA enforcement (**authentication.md**)

**Identity Assurance Levels (IAL)**:
- **IAL1**: Self-asserted identity
- **IAL2**: Remote identity proofing
- **IAL3**: In-person identity proofing

**Federation Assurance Levels (FAL)**:
- **FAL1**: Bearer assertion
- **FAL2**: Proof of possession

Mapped to: **authentication.md** (NEW)

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
