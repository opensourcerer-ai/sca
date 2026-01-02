# Format-Preserving Encryption (FPE) Security Invariants (v1)

## Overview

Format-Preserving Encryption (FPE) encrypts data while preserving its format (e.g., 16-digit credit card number → 16-digit ciphertext). Used for tokenization, PCI-DSS compliance, and legacy system integration.

**CRITICAL**: FPE has known vulnerabilities. FF3 is DEPRECATED. This document covers secure vs insecure FPE usage.

---

## Algorithm Status Summary

| Algorithm | NIST Status | Security Status | Recommendation |
|-----------|-------------|-----------------|----------------|
| **FF1** | ✅ Approved (SP 800-38G) | ✅ SECURE (if properly implemented) | **USE THIS** |
| **FF3** | ❌ WITHDRAWN | ❌ BROKEN (cryptanalysis attacks) | **NEVER USE** |
| **FF3-1** | ⚠️ Revised | ⚠️ WEAK (improved but still vulnerable) | **AVOID** |

---

## FF3 Vulnerabilities (CRITICAL)

### CVE-2017-14124: Cryptanalysis Attack (Durak & Vaudenay)

**Vulnerability**: FF3 is vulnerable to **plaintext recovery attacks** with practical complexity.

**Attack details**:
- Exploits the 8-round Feistel structure
- Requires ~2^32 chosen plaintexts (feasible)
- Can recover plaintext from ciphertext without key
- Affects all FF3 implementations

**Reference**: "Breaking the FF3 Format-Preserving Encryption Standard" (Durak & Vaudenay, CRYPTO 2017)

**Flag as**: **CRITICAL**

### FF3 vs FF3-1 Differences

| Issue | FF3 | FF3-1 |
|-------|-----|-------|
| Tweak size | 64 bits | 56 bits (7 bytes) |
| Tweak handling | Vulnerable to manipulation | Improved but not perfect |
| NIST status | Withdrawn | Revised (2019) |
| Security | Broken | Weak (better than FF3, worse than FF1) |

**FF3-1 improvements**:
- Reduced tweak size to mitigate some attacks
- Changed tweak encoding

**FF3-1 remaining issues**:
- Still uses 8-round Feistel (same as FF3)
- Academic research suggests potential vulnerabilities
- NIST prefers FF1 for new deployments

---

## FF1 (Recommended)

### NIST SP 800-38G Approved

**Status**: ✅ Approved for government use
**Security**: No known practical attacks when properly implemented
**Recommendation**: Use FF1 for all new FPE deployments

### Requirements for Secure FF1 Usage

1. **Minimum radix**: radix ≥ 2 (alphabet size)
2. **Minimum message length**: At least 2 characters in the alphabet
3. **Key size**: AES-128, AES-192, or AES-256
4. **Tweak**: 0-128 bytes (use for domain separation)

### Common FF1 Mistakes (Flag as HIGH)

**No tweak usage**:
```python
# HIGH: No tweak - same plaintext always produces same ciphertext
cipher = FF1(key, radix=10)
ciphertext = cipher.encrypt(plaintext)  # Deterministic without tweak
```

**Fix**:
```python
# GOOD: Use tweak for domain separation
cipher = FF1(key, radix=10)
tweak = b"customer_id:12345"  # Unique per context
ciphertext = cipher.encrypt(plaintext, tweak)
```

**Radix too small**:
```python
# MEDIUM: Binary FPE (radix=2) has limited security
cipher = FF1(key, radix=2)  # Weak for short messages
```

**Weak key management**:
```python
# CRITICAL: Hardcoded FPE key
fpe_key = b"0123456789abcdef0123456789abcdef"  # 32 bytes = AES-256
cipher = FF1(fpe_key, radix=10)
```

---

## Detection Patterns by Language

### Python

**FF3 Usage (CRITICAL)**:
```python
# CRITICAL: Deprecated FF3
from pyffx import FF3
cipher = FF3(key, tweak)

# CRITICAL: Library with FF3 support
import ff3  # Any import of ff3 module
from Crypto.Cipher import FF3  # If such module exists
```

**FF3-1 Usage (HIGH)**:
```python
# HIGH: FF3-1 is weak, use FF1 instead
from pyffx import FF3_1
cipher = FF3_1(key, tweak)
```

**FF1 Misuse (HIGH)**:
```python
# HIGH: No tweak (deterministic)
from pyffx import FF1
cipher = FF1(key, radix=10)
ciphertext = cipher.encrypt(plaintext)  # Missing tweak parameter

# HIGH: Hardcoded key
cipher = FF1(b"hardcoded_key_32_bytes_long!", radix=10)
```

**Secure FF1 Usage (GOOD)**:
```python
# GOOD: FF1 with tweak and proper key management
from pyffx import FF1
import os

key = os.environ['FPE_KEY']  # From secure key management
cipher = FF1(key, radix=10)
tweak = f"domain:{context_id}".encode()
ciphertext = cipher.encrypt(plaintext, tweak)
```

### Go

**FF3 Usage (CRITICAL)**:
```go
// CRITICAL: FF3 library usage
import "github.com/capitalone/fpe/ff3"

cipher, _ := ff3.NewCipher(key, tweak, radix)
```

**FF1 Usage (check for mistakes)**:
```go
// HIGH: No tweak
import "github.com/capitalone/fpe/ff1"

cipher, _ := ff1.NewCipher(key, radix)
ciphertext, _ := cipher.Encrypt(plaintext, nil)  // No tweak

// GOOD: With tweak
tweak := []byte("customer:12345")
ciphertext, _ := cipher.Encrypt(plaintext, tweak)
```

### Java

**FF3 Usage (CRITICAL)**:
```java
// CRITICAL: FF3 cipher
import com.privacylogistics.FF3Cipher;

FF3Cipher cipher = new FF3Cipher(key, tweak);
String ciphertext = cipher.encrypt(plaintext);
```

**FF1 Misuse (HIGH)**:
```java
// HIGH: Hardcoded key
import com.privacylogistics.FF1Cipher;

String key = "0123456789abcdef0123456789abcdef";  // Hardcoded
FF1Cipher cipher = new FF1Cipher(key.getBytes(), radix);
```

### JavaScript/TypeScript

**FF3 Usage (CRITICAL)**:
```javascript
// CRITICAL: node-fpe with FF3
const FPE = require('node-fpe');
const cipher = FPE.FF3({ key, tweak });
```

**FF1 Usage**:
```javascript
// GOOD: FF1 with proper setup
const FPE = require('node-fpe');
const key = process.env.FPE_KEY;  // From environment
const tweak = Buffer.from(`context:${userId}`);
const cipher = FPE.FF1({
  key: Buffer.from(key, 'hex'),
  radix: 10
});
const ciphertext = cipher.encrypt(plaintext, tweak);
```

### C/C++ (OpenSSL-based)

**FF3 Implementation (CRITICAL)**:
```c
// CRITICAL: Custom FF3 implementation (flag any FF3 reference)
#include "ff3.h"  // Any FF3 header

FF3_encrypt(key, tweak, plaintext, ciphertext);
```

**FF1 Implementation**:
```c
// Check for proper key management
// HIGH: Hardcoded key
unsigned char key[32] = {0x01, 0x02, ...};  // Hardcoded key array
FF1_encrypt(key, tweak, radix, plaintext, ciphertext);
```

---

## Automated Detection Patterns

### Grep Patterns

**FF3 Detection (CRITICAL)**:
```bash
# Search for FF3 imports/usage
git grep -i "ff3\\|FF3"

# Python specific
git grep "from.*ff3\\|import.*ff3\\|FF3("

# Java
git grep "import.*FF3\\|FF3Cipher"

# Go
git grep "fpe/ff3\\|ff3\\.New"
```

**FF3-1 Detection (HIGH)**:
```bash
git grep -i "ff3-1\\|ff3_1\\|FF3_1"
```

**FF1 Misuse Detection**:
```bash
# Find FF1 encrypt calls without tweak
git grep -A 2 "FF1.*encrypt" | grep -v "tweak"

# Hardcoded FPE keys
git grep -i "fpe.*key.*=.*['\"]\\|FF1.*key.*=.*['\"]"
```

---

## Known Vulnerabilities Summary

### FF3 (CVE-2017-14124)

**Attack**: Plaintext recovery via differential cryptanalysis
**Complexity**: ~2^32 chosen plaintexts (practical)
**Impact**: Complete loss of confidentiality
**Mitigation**: **NEVER USE FF3**

**Evidence patterns to flag**:
- Any import of ff3 libraries
- Function calls to `FF3.encrypt()` or `ff3.Encrypt()`
- Configuration files specifying `algorithm: ff3`

### FF3-1 (Improved but Weak)

**Status**: NIST revised in 2019 to address FF3 issues
**Issues**:
- Still 8-round Feistel (vs FF1's 10 rounds)
- Reduced tweak space (56 bits) limits flexibility
- Academic concerns about security margins

**Recommendation**: Migrate to FF1

**Evidence patterns to flag (HIGH)**:
- `FF3_1`, `ff3-1`, `FF3-1` usage
- Suggest migration to FF1 in remediation

### FF1 Implementation Bugs

**Common mistakes** (flag as HIGH):
1. **Missing tweak**: Deterministic encryption
2. **Hardcoded keys**: Key exposure
3. **Insufficient radix**: radix < 10 for numeric data
4. **No key rotation**: Same key used indefinitely
5. **Tweak reuse**: Same tweak for different contexts

---

## Compliance Requirements

### PCI-DSS Tokenization

**Requirement**: PCI-DSS allows FPE for credit card tokenization if properly implemented.

**Requirements**:
- Must use approved algorithm (**FF1 only**)
- Keys must be stored in HSM or equivalent
- Key rotation policy required
- Tweak must provide domain separation
- Audit logging of all tokenization operations

**Flag as CRITICAL if**:
- Using FF3/FF3-1 for PCI data
- FPE keys stored in application code
- No audit logging

**Example compliant usage**:
```python
# GOOD: PCI-compliant FPE tokenization
from pyffx import FF1
import hsm_client  # Hardware Security Module

key = hsm_client.get_key('fpe-key-id')  # Key from HSM
cipher = FF1(key, radix=10)

# Tweak includes merchant ID for domain separation
tweak = f"merchant:{merchant_id}:card".encode()
token = cipher.encrypt(credit_card_number, tweak)

# Audit log
audit_log.info(f"Tokenized card for merchant {merchant_id}",
               extra={"merchant_id": merchant_id, "token": token})
```

### GDPR / Data Minimization

**Use case**: FPE for pseudonymization (GDPR Article 4)

**Requirements**:
- FF1 only
- Keys must be separated from encrypted data
- Encryption must be reversible only by authorized parties
- Document lawful basis for processing

---

## Remediation Examples

### Migrate FF3 → FF1

**BEFORE (CRITICAL)**:
```python
from pyffx import FF3

key = b"0123456789abcdef0123456789abcdef"
tweak = b"12345678"  # 64-bit tweak
cipher = FF3(key, tweak)
ciphertext = cipher.encrypt(plaintext)
```

**AFTER (FIXED)**:
```python
from pyffx import FF1
import os

# Use environment variable for key
key = os.environ['FPE_KEY']  # 32 bytes for AES-256

# FF1 supports larger tweaks (0-128 bytes)
tweak = f"context:{entity_id}".encode()

cipher = FF1(key, radix=10)
ciphertext = cipher.encrypt(plaintext, tweak)
```

### Add Tweak to FF1

**BEFORE (HIGH)**:
```python
from pyffx import FF1

cipher = FF1(key, radix=10)
ciphertext = cipher.encrypt(ssn)  # No tweak - deterministic
```

**AFTER (FIXED)**:
```python
from pyffx import FF1

cipher = FF1(key, radix=10)

# Use tweak for domain separation (prevents identical ciphertexts)
tweak = f"ssn:user:{user_id}".encode()
ciphertext = cipher.encrypt(ssn, tweak)
```

### Key Management

**BEFORE (CRITICAL)**:
```java
// Hardcoded key
String key = "0123456789abcdef0123456789abcdef";
FF1Cipher cipher = new FF1Cipher(key.getBytes(), radix);
```

**AFTER (FIXED)**:
```java
// Retrieve from secure key management
import com.amazonaws.services.kms.AWSKMS;

AWSKMS kms = AWSKMSClientBuilder.defaultClient();
ByteBuffer keyPlaintext = kms.decrypt(
    new DecryptRequest()
        .withCiphertextBlob(encryptedKey)
).getPlaintext();

FF1Cipher cipher = new FF1Cipher(keyPlaintext.array(), radix);
```

---

## Testing for FPE Vulnerabilities

### Static Analysis Checks

```bash
#!/bin/bash
# Check for insecure FPE usage

echo "=== Checking for FF3 usage (CRITICAL) ==="
git grep -n -i "ff3" | grep -v "ff3-1" | grep -v "ff3_1" | grep -v ".md:"

echo ""
echo "=== Checking for FF3-1 usage (HIGH) ==="
git grep -n -i "ff3-1\|ff3_1"

echo ""
echo "=== Checking for hardcoded FPE keys (CRITICAL) ==="
git grep -n "FF1.*key.*=.*['\"]"

echo ""
echo "=== Checking for FF1 without tweak (HIGH) ==="
git grep -n -A 3 "\.encrypt(" | grep -B 3 "FF1" | grep -v "tweak"
```

### Runtime Validation

```python
# Test: Ensure FF1 with tweak is used
def test_fpe_security():
    """Verify FPE implementation uses FF1 with tweaks"""

    # Check no FF3 modules loaded
    import sys
    forbidden = ['ff3', 'FF3']
    for module in sys.modules:
        for forbidden_name in forbidden:
            assert forbidden_name.lower() not in module.lower(), \
                f"CRITICAL: Forbidden module {module} loaded (contains {forbidden_name})"

    # Check FF1 usage includes tweaks
    from myapp.crypto import fpe_encrypt

    # Mock inputs
    plaintext = "1234567890123456"
    context = "test-context"

    # Encrypt twice with same plaintext
    ct1 = fpe_encrypt(plaintext, context="ctx1")
    ct2 = fpe_encrypt(plaintext, context="ctx2")

    # Different contexts should produce different ciphertexts (tweak is used)
    assert ct1 != ct2, "CRITICAL: FPE appears deterministic (no tweak?)"
```

---

## References

### NIST Publications

- **NIST SP 800-38G** (March 2016): "Recommendation for Block Cipher Modes of Operation: Methods for Format-Preserving Encryption"
  - Specifies FF1 (approved)

- **NIST SP 800-38G Revision 1** (February 2019): Addendum for FF3-1
  - Revises FF3 due to vulnerabilities
  - Still recommends FF1 over FF3-1

### Security Research

- **Durak & Vaudenay (CRYPTO 2017)**: "Breaking the FF3 Format-Preserving Encryption Standard"
  - Practical attack on FF3 with 2^32 complexity

- **Hoang, Tessaro, Trieu (CRYPTO 2018)**: "The Multi-user Security of GCM, Revisited: Tight Bounds for Nonce Randomization"
  - Discusses FPE security in multi-user settings

### Compliance Standards

- **PCI-DSS v4.0**: Section 3.4 - Tokenization requirements
- **GDPR Article 4(5)**: Pseudonymization definition
- **NIST Cybersecurity Framework**: Cryptographic standards

---

## Detection Priority Summary

| Pattern | Severity | Action |
|---------|----------|--------|
| FF3 usage (any language) | **CRITICAL** | Immediate remediation required |
| FF3-1 usage | **HIGH** | Plan migration to FF1 |
| FF1 without tweak | **HIGH** | Add domain-specific tweaks |
| Hardcoded FPE keys | **CRITICAL** | Move to secure key management |
| FPE for PCI data with FF3 | **CRITICAL** | Compliance violation, immediate fix |
| No key rotation policy | **MEDIUM** | Implement key lifecycle management |
| Radix < 10 for numeric data | **MEDIUM** | Increase radix or use AES-GCM |

---

## Summary

**CRITICAL Rules**:
1. ❌ **NEVER use FF3** - cryptographically broken
2. ⚠️ **Avoid FF3-1** - use FF1 instead
3. ✅ **Use FF1 (NIST SP 800-38G)** for all FPE
4. 🔑 **Always use tweaks** with FF1 for domain separation
5. 🔐 **Never hardcode FPE keys** - use HSM/KMS
6. 📋 **For PCI-DSS**: FF1 only, keys in HSM, audit logging

**Common Mistakes to Flag**:
- Any usage of FF3 libraries/functions
- FF1 encryption without tweak parameter
- Hardcoded FPE encryption keys in source code
- Using FPE for PCI data without proper key management
- No audit logging for tokenization operations
