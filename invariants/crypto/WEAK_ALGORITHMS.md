# Weak Cryptographic Algorithms Reference (v1)

## Quick Reference for Static Analysis

This file provides patterns to detect weak/dangerous cryptographic algorithms across all languages.

---

## CRITICAL: Forbidden Algorithms (Always Flag)

### Symmetric Encryption

| Algorithm | Status | Reason | Flag As |
|-----------|--------|--------|---------|
| **DES** | ❌ FORBIDDEN | 56-bit key, broken since 1998 | Critical |
| **3DES (Triple-DES)** | ❌ FORBIDDEN | Obsolete, 64-bit block size (SWEET32) | Critical |
| **RC2** | ❌ FORBIDDEN | Weak key schedule | Critical |
| **RC4** | ❌ FORBIDDEN | Biased keystream, practical attacks | Critical |
| **Blowfish** | ⚠️ DEPRECATED | 64-bit block size, use AES instead | High |
| **AES-ECB** | ❌ FORBIDDEN | No IV, deterministic (patterns leak) | Critical |
| **AES-CBC without MAC** | ⚠️ RISKY | Padding oracle attacks | High |

**Approved Alternatives**: AES-GCM, AES-CCM, ChaCha20-Poly1305

### Hash Functions

| Algorithm | Status | Reason | Flag As |
|-----------|--------|--------|---------|
| **MD5** | ❌ FORBIDDEN | Collision attacks (practical since 2004) | Critical |
| **SHA-1** | ❌ FORBIDDEN | Collision attacks (SHAttered 2017) | Critical |
| **SHA-224** | ⚠️ WEAK | Truncated SHA-256, use full SHA-256 instead | Medium |
| **RIPEMD-160** | ⚠️ DEPRECATED | Not actively maintained | Medium |

**Exception**: SHA-1 for Git commit hashing is acceptable (non-security use)

**Approved Alternatives**: SHA-256, SHA-384, SHA-512, SHA-3, BLAKE2, BLAKE3

### Asymmetric Encryption & Signatures

| Algorithm | Key Size | Status | Flag As |
|-----------|----------|--------|---------|
| **RSA** | < 2048 bits | ❌ FORBIDDEN | Critical |
| **RSA** | 2048 bits | ⚠️ MINIMUM | Medium (migrate to 4096+) |
| **RSA** | 4096+ bits | ✅ ACCEPTABLE | - |
| **DSA** | < 2048 bits | ❌ FORBIDDEN | Critical |
| **DH** | < 2048 bits | ❌ FORBIDDEN | Critical |
| **ECDSA** | P-192 | ❌ FORBIDDEN | Critical |
| **ECDSA** | P-256 | ✅ ACCEPTABLE | - |

**Post-Quantum Readiness**: Flag all classical algorithms (RSA, ECDSA, DH) with **Warning** if no PQC migration plan

**Approved Alternatives**: 
- Classical: RSA-4096+, ECDSA-P256+, Ed25519
- Post-Quantum: ML-KEM, ML-DSA, SLH-DSA

---

## Detection Patterns by Language

### Python

**Weak Ciphers**:
```python
# CRITICAL
from Crypto.Cipher import DES, DES3, ARC2, ARC4, Blowfish
cipher = DES.new(key, DES.MODE_ECB)
cipher = DES3.new(key, DES3.MODE_ECB)
cipher = ARC4.new(key)  # RC4

# CRITICAL: ECB mode
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_ECB)
```

**Weak Hashes**:
```python
# CRITICAL
import hashlib
hashlib.md5(data)
hashlib.sha1(data)
hashlib.new('md5', data)
hashlib.new('sha1', data)

# MEDIUM: SHA-224
hashlib.sha224(data)
```

**Weak RSA**:
```python
# CRITICAL: Key too small
from Crypto.PublicKey import RSA
key = RSA.generate(1024)  # < 2048 bits

# MEDIUM: Minimum acceptable
key = RSA.generate(2048)  # Recommend 4096+
```

### Go

**Weak Ciphers**:
```go
// CRITICAL
import "crypto/des"
import "crypto/rc4"

cipher, _ := des.NewCipher(key)
cipher, _ := des.NewTripleDESCipher(key)  // 3DES
cipher, _ := rc4.NewCipher(key)
```

**Weak Hashes**:
```go
// CRITICAL
import "crypto/md5"
import "crypto/sha1"

md5.Sum(data)
md5.New()
sha1.Sum(data)
sha1.New()
```

**Weak RSA**:
```go
// CRITICAL
import "crypto/rsa"
privateKey, _ := rsa.GenerateKey(rand.Reader, 1024)  // < 2048

// MEDIUM
privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)  // Recommend 4096
```

### JavaScript/TypeScript (Node.js)

**Weak Ciphers**:
```javascript
// CRITICAL
const crypto = require('crypto');
crypto.createCipheriv('des-ecb', key, null);
crypto.createCipheriv('des3', key, iv);
crypto.createCipheriv('rc4', key, null);
crypto.createCipheriv('aes-128-ecb', key, null);  // ECB mode
```

**Weak Hashes**:
```javascript
// CRITICAL
crypto.createHash('md5');
crypto.createHash('sha1');
crypto.createHash('md4');  // Even worse than MD5
```

### Java

**Weak Ciphers**:
```java
// CRITICAL
import javax.crypto.Cipher;

Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");  // 3DES
Cipher cipher = Cipher.getInstance("RC4");
Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
Cipher cipher = Cipher.getInstance("Blowfish");
```

**Weak Hashes**:
```java
// CRITICAL
import java.security.MessageDigest;

MessageDigest.getInstance("MD5");
MessageDigest.getInstance("SHA-1");
MessageDigest.getInstance("SHA1");  // Alternate name
```

**Weak RSA**:
```java
// CRITICAL
import java.security.KeyPairGenerator;

KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
keyGen.initialize(1024);  // < 2048 bits
```

### C/C++ (OpenSSL)

**Weak Ciphers**:
```c
// CRITICAL
#include <openssl/des.h>
#include <openssl/rc4.h>

DES_cbc_encrypt(...);
DES_ede3_cbc_encrypt(...);  // 3DES
RC4(...);
EVP_des_ecb();
EVP_des_ede3();
EVP_aes_128_ecb();  // ECB mode
```

**Weak Hashes**:
```c
// CRITICAL
#include <openssl/md5.h>
#include <openssl/sha.h>

MD5(...);
MD5_Init(...);
SHA1(...);
SHA1_Init(...);
EVP_md5();
EVP_sha1();
```

### C# (.NET)

**Weak Ciphers**:
```csharp
// CRITICAL
using System.Security.Cryptography;

DES.Create();
TripleDES.Create();
RC2.Create();
var aes = Aes.Create();
aes.Mode = CipherMode.ECB;  // ECB mode
```

**Weak Hashes**:
```csharp
// CRITICAL
MD5.Create();
SHA1.Create();
new MD5CryptoServiceProvider();
new SHA1Managed();
```

### Rust

**Weak Ciphers**:
```rust
// CRITICAL (if these crates are used)
// Crate names to flag: des, des-ede3, rc4, md5, sha1

use des::Des;
use rc4::Rc4;
```

---

## Automated Detection Queries

### Grep Patterns

**DES/3DES**:
```bash
git grep -i "des\|triple.*des\|des3\|desede"
```

**RC4**:
```bash
git grep -i "rc4\|arc4\|arcfour"
```

**MD5**:
```bash
git grep -i "md5\|hashlib.md5\|MessageDigest.*MD5"
```

**SHA-1**:
```bash
git grep -i "sha1\|sha-1\|hashlib.sha1"
```

**ECB Mode**:
```bash
git grep -i "ecb\|MODE_ECB"
```

**Weak RSA**:
```bash
git grep -i "generate.*1024\|KeySize.*1024\|RSA.*1024"
```

---

## Remediation Examples

### Replace DES with AES-GCM
```python
# BEFORE (CRITICAL)
from Crypto.Cipher import DES
cipher = DES.new(key, DES.MODE_CBC, iv)
ciphertext = cipher.encrypt(plaintext)

# AFTER (FIXED)
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_GCM)
ciphertext, tag = cipher.encrypt_and_digest(plaintext)
```

### Replace MD5 with SHA-256
```python
# BEFORE (CRITICAL)
import hashlib
hash = hashlib.md5(data).hexdigest()

# AFTER (FIXED)
import hashlib
hash = hashlib.sha256(data).hexdigest()
```

### Increase RSA Key Size
```python
# BEFORE (CRITICAL)
from Crypto.PublicKey import RSA
key = RSA.generate(1024)

# AFTER (FIXED)
from Crypto.PublicKey import RSA
key = RSA.generate(4096)  # Or use ECDSA/Ed25519
```

### Replace AES-ECB with AES-GCM
```java
// BEFORE (CRITICAL)
Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

// AFTER (FIXED)
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
```

---

## Compliance References

- **NIST SP 800-131A**: Disallows SHA-1, 3DES, 1024-bit RSA
- **PCI-DSS**: Requires TLS 1.2+ (disallows weak ciphers)
- **FIPS 140-2**: Approved algorithms list (excludes DES, MD5, SHA-1 for new systems)
- **BSI TR-02102-1** (Germany): Similar restrictions
- **ANSSI** (France): Recommends against SHA-1, RSA < 2048

---

## Testing for Weak Crypto

### Static Analysis
```bash
# Find all crypto imports/usage
sca audit --verbose

# Custom grep
./scripts/find-weak-crypto.sh
```

### Runtime Testing
```python
# Test: Ensure strong ciphers only
def test_no_weak_ciphers():
    weak_modules = ['DES', 'DES3', 'RC4', 'md5', 'sha1']
    for module in sys.modules:
        assert not any(weak in module for weak in weak_modules)
```

### Dependency Audit
```bash
# Check if dependencies use weak crypto
pip list | grep -i "pycrypto\|pycryptodome"  # Pycrypto is deprecated
npm audit
```
