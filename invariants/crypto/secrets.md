# Cryptography & Key Material Security Invariants (v1)

## Critical: Key Material Exposure & Out-of-Enclave Violations

### Key Material MUST remain in secure enclaves
- **Never log, print, or serialize** private keys, symmetric keys, HSM handles, seed phrases, mnemonics
- **Never transmit unencrypted keys** over network (even localhost without TLS)
- **Never write keys to disk** except in hardware-backed keystores (HSM, TPM, Secure Enclave, KMS)
- **Never store keys in environment variables** accessible to untrusted processes
- **Never embed keys in source code** (checked-in credentials, hardcoded secrets)
- **Never store keys in plaintext config files** (YAML, JSON, .env without encryption)
- **Never pass keys as command-line arguments** (visible in process lists)

### Key Material Detection Patterns (flag as Critical)
Search for variables/fields containing:
- `private_key`, `privateKey`, `priv_key`, `secret_key`, `secretKey`
- `api_key`, `apiKey`, `API_KEY`
- `master_key`, `masterKey`, `root_key`
- `encryption_key`, `decryption_key`
- `hmac_secret`, `signing_key`, `jwt_secret`
- `seed`, `mnemonic`, `recovery_phrase`
- `password`, `passwd`, `pwd` (when used for crypto, not user auth)
- `token`, `access_token`, `refresh_token` (when long-lived)
- `certificate_key`, `tls_key`, `ssl_key`
- PEM blocks: `-----BEGIN PRIVATE KEY-----`, `-----BEGIN RSA PRIVATE KEY-----`
- Base64-encoded keys (heuristic: long base64 strings near crypto imports)

### Evidence Required for Confirmed Finding
- File path + line number where key is exposed
- Context: is it logged, serialized, transmitted, written to file?
- Is the key hardcoded or read from insecure source?

---

## Cryptography Algorithms: Approved vs Forbidden

### FORBIDDEN (flag as Critical)
- **Block ciphers in ECB mode**: AES-ECB, DES-ECB, 3DES-ECB (no randomness → patterns leak)
- **DES, 3DES**: Obsolete, insufficient key length
- **RC4, RC2**: Stream ciphers with known biases
- **MD5, SHA-1** for cryptographic purposes (integrity, signatures, HMAC)
  - Exception: SHA-1 for Git commit hashing is acceptable (non-security)
- **Homebrew crypto**: Custom encryption schemes, XOR-based "encryption"
- **RSA < 2048 bits**: Insufficient for current threat model
- **DSA, Diffie-Hellman < 2048 bits**

### APPROVED (baseline)
- **Block ciphers**: AES-GCM, AES-CCM, ChaCha20-Poly1305
- **Hashing**: SHA-256, SHA-384, SHA-512, SHA-3, BLAKE2, BLAKE3
- **HMAC**: HMAC-SHA256 or stronger
- **Key derivation**: PBKDF2, Argon2, scrypt, HKDF
- **Asymmetric**: RSA ≥ 2048 bits, ECDSA (P-256 or stronger), Ed25519
- **Key exchange**: ECDH (P-256+), X25519

### POST-QUANTUM CRYPTOGRAPHY (PQC) MIGRATION
- **Warning (Medium)**: Flag use of non-PQC algorithms (RSA, ECDSA, DH) in NEW code
  - Message: "Consider PQC-safe alternatives (ML-KEM, ML-DSA, SLH-DSA) for long-term security"
- **Critical**: Flag new deployments without PQC roadmap in high-security contexts
- **Approved PQC algorithms** (NIST standards):
  - ML-KEM (formerly CRYSTALS-Kyber) - key encapsulation
  - ML-DSA (formerly CRYSTALS-Dilithium) - digital signatures
  - SLH-DSA (formerly SPHINCS+) - stateless hash-based signatures

---

## Key Management Invariants

### Key Lifecycle
- **Generation**: Use cryptographically secure RNG (e.g., `/dev/urandom`, `secrets` module in Python, `crypto/rand` in Go)
  - Never use `math.random()`, `rand()`, `Random()` for key generation
- **Storage**: Keys MUST be stored in:
  - Hardware Security Modules (HSM)
  - Key Management Services (AWS KMS, GCP KMS, Azure Key Vault, HashiCorp Vault)
  - OS-level keystores (macOS Keychain, Windows DPAPI, Linux Secret Service API)
  - Encrypted at rest with separate master key
- **Rotation**: Keys MUST have rotation policies
  - Flag keys older than 90 days without rotation mechanism (High)
  - Flag symmetric keys used for > 1 year (Critical)
- **Destruction**: Keys MUST be securely wiped (zeroed memory, not just dereferenced)
  - Check for `memset_s()`, `SecureZeroMemory()`, `explicit_bzero()`, or equivalent

### Encryption at Rest
- **Database encryption**: Verify TDE (Transparent Data Encryption) or application-level encryption for sensitive fields
- **File encryption**: Sensitive files MUST be encrypted (credentials, PII, financial data)
- **Backup encryption**: Backups MUST be encrypted with keys separate from production

### Encryption in Transit
- **TLS version**: Require TLS 1.2+ (flag TLS 1.0, 1.1 as Critical)
- **Certificate validation**: MUST validate server certificates (no `verify=False`, `InsecureSkipVerify`)
- **Cipher suites**: Prefer forward secrecy (ECDHE), disable NULL, EXPORT, DES, RC4
- **HSTS**: HTTPS-only services MUST use HSTS headers

---

## Specific Vulnerability Patterns

### Weak Randomness
- **Seeded PRNGs with predictable seeds** (timestamps, process IDs)
- **Reusing IVs/nonces** for encryption (especially with CTR, GCM modes)
- **Low-entropy keys** (dictionary words, sequential numbers)

### Padding Oracle Attacks
- **CBC mode without authenticated encryption** (use GCM, CCM, or Encrypt-then-MAC)
- **Padding validation without constant-time comparison**

### Timing Attacks
- **Non-constant-time comparison** of secrets (passwords, tokens, HMACs)
  - Use `hmac.compare_digest()` (Python), `subtle.ConstantTimeCompare()` (Go), `MessageDigest.isEqual()` (Java)

### Key Derivation Failures
- **Using hash functions directly for passwords** (instead of PBKDF2/Argon2/scrypt)
- **Insufficient iteration counts** for PBKDF2 (< 100,000 iterations)
- **No salt or short salts** (< 16 bytes)

### Certificate & PKI Issues
- **Self-signed certificates in production** (flag as High)
- **Expired certificates**
- **Missing certificate pinning** for high-security mobile/desktop apps
- **Wildcard certificates for different trust domains**

---

## Language-Specific Patterns

### Python
```python
# CRITICAL: Hardcoded key
SECRET_KEY = "sk-1234567890abcdef"

# CRITICAL: Weak randomness
import random
key = random.randint(0, 1000000)

# CRITICAL: ECB mode
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_ECB)  # No IV, patterns leak

# APPROVED: AES-GCM
cipher = AES.new(key, AES.MODE_GCM)
```

### Go
```go
// CRITICAL: Non-crypto RNG
import "math/rand"
key := make([]byte, 32)
rand.Read(key)  // NOT crypto-secure

// APPROVED: Crypto RNG
import "crypto/rand"
rand.Read(key)

// CRITICAL: Skipping cert verification
tr := &http.Transport{
    TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
}
```

### JavaScript/TypeScript
```javascript
// CRITICAL: Hardcoded API key
const API_KEY = "sk-1234567890abcdef";

// CRITICAL: Weak randomness
const key = Math.random().toString(36);

// APPROVED: Web Crypto API
const key = await crypto.subtle.generateKey(
  { name: "AES-GCM", length: 256 },
  true,
  ["encrypt", "decrypt"]
);
```

### Java
```java
// CRITICAL: DES usage
Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");

// CRITICAL: Weak RNG
Random rand = new Random();

// APPROVED: SecureRandom
SecureRandom rand = new SecureRandom();

// APPROVED: AES-GCM
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
```

### C/C++
```c
// CRITICAL: Weak RNG
int key = rand();

// APPROVED: OS RNG
#ifdef _WIN32
#include <bcrypt.h>
BCryptGenRandom(NULL, buffer, size, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
#else
#include <sys/random.h>
getrandom(buffer, size, 0);
#endif
```

### Rust
```rust
// CRITICAL: Hardcoded key in source
const SECRET: &[u8] = b"my-secret-key";

// APPROVED: Key from secure storage
use ring::rand::{SecureRandom, SystemRandom};
let rng = SystemRandom::new();
let mut key = [0u8; 32];
rng.fill(&mut key).unwrap();
```

---

## Reporting Template for Crypto Findings

For each finding, include:
1. **Severity**: Critical | High | Medium
2. **Category**: Key exposure | Weak crypto | Insecure RNG | Protocol flaw
3. **Evidence**: File path, line number, code snippet
4. **Impact**: Data confidentiality loss, authentication bypass, compliance violation
5. **Remediation**: Specific fix with approved alternative
6. **Compliance**: Mention if violates PCI-DSS, HIPAA, GDPR, FIPS 140-2

### Example Finding
```
### Critical: Hardcoded API Key Exposure

**Evidence**: `src/config/settings.py:15`
```python
API_KEY = "sk-live-abcd1234567890"
```

**Impact**: Secret key committed to repository, accessible to anyone with read access. Enables unauthorized API access.

**Remediation**:
1. Revoke exposed key immediately
2. Store key in environment variable or KMS
3. Use secret scanning in CI/CD to prevent recurrence
```python
import os
API_KEY = os.environ.get("API_KEY")
if not API_KEY:
    raise ValueError("API_KEY environment variable required")
```

**Compliance**: Violates PCI-DSS 3.5.3 (protection of cryptographic keys)
```

---

## Special Cases

### Development vs Production
- **Acceptable in dev**: Hardcoded test keys IF clearly marked as test-only and different from production
- **Never acceptable**: Using dev keys in production config

### Encrypted Secrets Management
- **Approved tools**: HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager, SOPS, sealed-secrets
- **Not approved**: Committing encrypted secrets without key separation, using symmetric encryption with key in same repo

### Quantum-Safe Migration Timeline
- **2024-2026**: Hybrid mode (classical + PQC)
- **2026+**: PQC-only for new systems
- Flag systems without PQC roadmap in regulated industries (Critical)
