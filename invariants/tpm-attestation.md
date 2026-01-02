# TPM and Attestation Security Invariants (v1)

## Overview

This file defines security invariants for Trusted Platform Module (TPM), remote attestation, and hardware-based trust anchors aligned with:
- **NIST SP 800-155**: BIOS Integrity Measurement Guidelines
- **NIST SP 800-147**: BIOS Protection Guidelines
- **NIST SP 800-193**: Platform Firmware Resiliency Guidelines
- **TCG (Trusted Computing Group)**: TPM 2.0 Library Specification
- **ISO/IEC 11889**: Trusted Platform Module specifications
- **Confidential Computing Consortium**: Attestation standards

**SCA Identifier Range**: SCA-800 to SCA-899 (Infrastructure and deployment)

---

## CRITICAL: Missing TPM for Cryptographic Operations (SCA-801, NIST SP 800-147)

**Standard**: SCA-801, NIST SP 800-147, NIST SP 800-53 SC-12, SC-13

**Finding**: Cryptographic keys stored in software without TPM protection

**Detection Patterns**:

### Python
```python
# CRITICAL: Software-only key storage
from cryptography.hazmat.primitives import serialization

# Generate RSA key in software
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# CRITICAL: Store to disk unprotected
with open('/etc/app/private_key.pem', 'wb') as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()  # No protection!
    ))
```

### Go
```go
// CRITICAL: Software-only key generation
import "crypto/rsa"

privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

// CRITICAL: Save to disk without TPM
pemData := x509.MarshalPKCS1PrivateKey(privateKey)
ioutil.WriteFile("/etc/app/key.pem", pemData, 0600)
```

### C (OpenSSL)
```c
// CRITICAL: Software key generation
RSA *rsa = RSA_new();
BIGNUM *bne = BN_new();
BN_set_word(bne, RSA_F4);
RSA_generate_key_ex(rsa, 2048, bne, NULL);

// CRITICAL: Save to file without TPM
FILE *fp = fopen("/etc/app/private.pem", "w");
PEM_write_RSAPrivateKey(fp, rsa, NULL, NULL, 0, NULL, NULL);
```

**TPM Benefits**:
- **Hardware-backed key storage**: Keys never leave TPM
- **Sealed storage**: Keys bound to PCR values (system state)
- **Attestation**: Prove key was generated in TPM
- **Anti-tampering**: Physical protection

**Remediation**:

### Python with TPM 2.0
```python
# GOOD: TPM-backed key storage
from tpm2_pytss import ESAPI, TPM2B_PUBLIC, TPM2B_SENSITIVE_CREATE

def create_tpm_key():
    """Create RSA key in TPM"""
    esapi = ESAPI()

    # Create primary key in TPM
    in_sensitive = TPM2B_SENSITIVE_CREATE()
    in_public = TPM2B_PUBLIC(
        publicArea={
            'type': 'RSA',
            'nameAlg': 'SHA256',
            'objectAttributes': (
                'fixedTPM',      # Key cannot be duplicated
                'fixedParent',
                'sensitiveDataOrigin',
                'userWithAuth',
                'sign'           # Key can sign
            ),
            'authPolicy': b'',
            'parameters': {
                'rsaDetail': {
                    'symmetric': 'NULL',
                    'scheme': 'RSASSA',
                    'keyBits': 2048,
                    'exponent': 0
                }
            }
        }
    )

    # Create key in TPM (never leaves TPM)
    key_handle, out_public, _, _, _ = esapi.CreatePrimary(
        primaryHandle='OWNER',
        inSensitive=in_sensitive,
        inPublic=in_public
    )

    # Make key persistent
    persistent_handle = esapi.EvictControl(
        auth='OWNER',
        objectHandle=key_handle,
        persistentHandle=0x81010001
    )

    return persistent_handle, out_public

def tpm_sign(data: bytes, key_handle):
    """Sign data using TPM key"""
    esapi = ESAPI()

    # Create digest
    digest = hashlib.sha256(data).digest()

    # Sign using TPM
    signature = esapi.Sign(
        keyHandle=key_handle,
        digest=digest,
        inScheme={'scheme': 'RSASSA', 'details': {'hashAlg': 'SHA256'}}
    )

    return signature
```

### Go with go-tpm
```go
// GOOD: TPM-backed key storage
import (
    "github.com/google/go-tpm/tpm2"
    "github.com/google/go-tpm/tpmutil"
)

func createTPMKey() (tpmutil.Handle, error) {
    // Open TPM
    rwc, err := tpm2.OpenTPM("/dev/tpm0")
    if err != nil {
        return 0, err
    }
    defer rwc.Close()

    // Create primary key in TPM
    parentHandle := tpmutil.Handle(0x81000001)

    publicTemplate := tpm2.Public{
        Type:       tpm2.AlgRSA,
        NameAlg:    tpm2.AlgSHA256,
        Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth | tpm2.FlagSign,
        RSAParameters: &tpm2.RSAParams{
            Sign: &tpm2.SigScheme{
                Alg:  tpm2.AlgRSASSA,
                Hash: tpm2.AlgSHA256,
            },
            KeyBits: 2048,
        },
    }

    // Create key in TPM
    keyHandle, _, err := tpm2.CreatePrimary(
        rwc,
        tpm2.HandleOwner,
        tpm2.PCRSelection{},
        "",
        "",
        publicTemplate,
    )

    if err != nil {
        return 0, err
    }

    // Make persistent
    err = tpm2.EvictControl(rwc, "", tpm2.HandleOwner, keyHandle, parentHandle)

    return parentHandle, err
}
```

**NIST Controls**: SC-12 - Cryptographic Key Establishment, SC-13 - Cryptographic Protection

---

## CRITICAL: Missing Secure Boot Verification (SCA-802, NIST SP 800-147)

**Standard**: SCA-802, NIST SP 800-147 (BIOS Protection), NIST SP 800-155 (BIOS Integrity)

**Finding**: Boot process not verified with cryptographic signatures

**Detection Patterns**:

### Boot Configuration (GRUB)
```bash
# CRITICAL: No signature verification
# /boot/grub/grub.cfg

set root='hd0,gpt2'
linux /vmlinuz root=/dev/sda2 ro  # No signature check
initrd /initrd.img
```

### Kernel Module Loading
```python
# CRITICAL: Load unsigned kernel module
import subprocess

# No signature verification
subprocess.run(['insmod', '/lib/modules/custom_driver.ko'])
```

**UEFI Secure Boot Requirements**:
- **Platform Key (PK)**: Root of trust
- **Key Exchange Keys (KEK)**: Intermediate keys
- **Signature Database (db)**: Allowed signatures
- **Forbidden Signature Database (dbx)**: Revoked signatures

**Remediation**:

### Enable UEFI Secure Boot
```bash
# GOOD: Verify Secure Boot is enabled
#!/bin/bash

# Check if Secure Boot is enabled
if ! mokutil --sb-state | grep -q "SecureBoot enabled"; then
    echo "ERROR: Secure Boot is NOT enabled"
    exit 1
fi

# Verify boot components are signed
sbverify --list /boot/efi/EFI/ubuntu/shimx64.efi
sbverify --list /boot/efi/EFI/ubuntu/grubx64.efi
sbverify --list /boot/vmlinuz-$(uname -r)

# Check if running kernel is signed
if ! mokutil --test-key /var/lib/shim-signed/mok/MOK.der; then
    echo "WARNING: Kernel not signed with trusted key"
fi
```

### Sign Kernel Modules
```bash
# GOOD: Sign custom kernel modules
#!/bin/bash

MODULE_PATH="/lib/modules/custom_driver.ko"
SIGNING_KEY="/var/lib/shim-signed/mok/MOK.priv"
SIGNING_CERT="/var/lib/shim-signed/mok/MOK.der"

# Sign the module
/usr/src/linux-headers-$(uname -r)/scripts/sign-file \
    sha256 \
    "$SIGNING_KEY" \
    "$SIGNING_CERT" \
    "$MODULE_PATH"

# Verify signature
modinfo "$MODULE_PATH" | grep "sig_id"

# Only load if signature valid
modprobe custom_driver
```

### Measured Boot with TPM
```python
# GOOD: Extend TPM PCRs during boot
from tpm2_pytss import ESAPI

def extend_boot_measurement(pcr_index: int, measurement: bytes):
    """Extend TPM PCR with boot measurement"""
    esapi = ESAPI()

    # Hash the measurement
    digest = hashlib.sha256(measurement).digest()

    # Extend PCR (cannot be reset without reboot)
    esapi.PCR_Extend(
        pcrHandle=pcr_index,
        digests={
            'sha256': digest
        }
    )

    # Audit log
    audit_log('PCR_EXTENDED', pcr=pcr_index, measurement=measurement.hex()[:32])

# Measure bootloader
bootloader_hash = hashlib.sha256(open('/boot/efi/EFI/ubuntu/grubx64.efi', 'rb').read()).digest()
extend_boot_measurement(pcr_index=4, measurement=bootloader_hash)

# Measure kernel
kernel_hash = hashlib.sha256(open('/boot/vmlinuz', 'rb').read()).digest()
extend_boot_measurement(pcr_index=5, measurement=kernel_hash)

# Measure initramfs
initrd_hash = hashlib.sha256(open('/boot/initrd.img', 'rb').read()).digest()
extend_boot_measurement(pcr_index=6, measurement=initrd_hash)
```

**NIST Controls**: SI-7 - Software Integrity, SI-7(6) - Integrity Verification, CM-3 - Configuration Change Control

---

## CRITICAL: Missing Remote Attestation (SCA-803, TCG Attestation)

**Standard**: SCA-803, TCG Remote Attestation, NIST SP 800-155, Confidential Computing Consortium

**Finding**: No remote attestation to verify system integrity

**Detection**: Look for absence of attestation service, quote generation, or PCR validation

**Remote Attestation Flow**:
1. **Challenger** sends nonce to **Attester**
2. **Attester** generates TPM Quote (signed PCR values + nonce)
3. **Challenger** verifies Quote signature with Attestation Key (AK)
4. **Challenger** validates PCR values against golden measurements
5. **Challenger** makes trust decision

**Remediation**:

### Attester (Generate Quote)
```python
# GOOD: Generate TPM attestation quote
from tpm2_pytss import ESAPI, TPM2B_ATTEST
import secrets

class TPMAttester:
    """Generate TPM attestation quotes"""

    def __init__(self):
        self.esapi = ESAPI()
        self.ak_handle = self.load_attestation_key()

    def load_attestation_key(self):
        """Load Attestation Key (AK) from TPM"""
        # AK is a restricted signing key
        # Cannot sign arbitrary data, only TPM-generated attestation structures
        return 0x81010002  # Persistent AK handle

    def generate_quote(self, nonce: bytes, pcr_selection: list[int]) -> dict:
        """Generate TPM Quote for remote attestation"""
        # Create PCR selection
        pcr_sel = {
            'sha256': pcr_selection  # e.g., [0, 1, 2, 3, 4, 5, 6, 7]
        }

        # Read current PCR values
        _, pcr_values = self.esapi.PCR_Read(pcrSelectionIn=pcr_sel)

        # Generate Quote (signed attestation)
        quoted, signature = self.esapi.Quote(
            signHandle=self.ak_handle,
            qualifyingData=nonce,  # Freshness nonce from verifier
            pcrSelect=pcr_sel
        )

        # Get AK public key for verifier
        ak_public = self.esapi.ReadPublic(self.ak_handle)

        return {
            'quote': quoted,
            'signature': signature,
            'pcr_values': pcr_values,
            'ak_public': ak_public,
            'nonce': nonce
        }

# Usage
attester = TPMAttester()
nonce = secrets.token_bytes(32)  # From verifier
quote = attester.generate_quote(
    nonce=nonce,
    pcr_selection=[0, 1, 2, 3, 4, 5, 6, 7]  # Boot PCRs
)
```

### Verifier (Verify Quote)
```python
# GOOD: Verify TPM attestation quote
from tpm2_pytss import ESAPI, TPM2_ALG
import json

class AttestationVerifier:
    """Verify TPM attestation quotes"""

    def __init__(self, golden_measurements_path: str):
        """Load expected PCR values (golden measurements)"""
        with open(golden_measurements_path) as f:
            self.golden_measurements = json.load(f)

    def verify_quote(self, quote_data: dict, expected_nonce: bytes) -> bool:
        """Verify TPM quote and PCR values"""

        # 1. Verify nonce (freshness)
        if quote_data['nonce'] != expected_nonce:
            raise ValueError("Nonce mismatch - replay attack detected")

        # 2. Verify quote signature using AK public key
        esapi = ESAPI()

        ak_public = quote_data['ak_public']
        signature = quote_data['signature']
        quoted = quote_data['quote']

        # Load AK public key
        ak_handle = esapi.LoadExternal(
            inPublic=ak_public,
            hierarchy='NULL'
        )

        # Verify signature
        try:
            esapi.VerifySignature(
                keyHandle=ak_handle,
                digest=quoted.attestationData,
                signature=signature
            )
        except Exception as e:
            raise ValueError(f"Quote signature verification failed: {e}")

        # 3. Verify PCR values against golden measurements
        pcr_values = quote_data['pcr_values']

        for pcr_index, expected_value in self.golden_measurements.items():
            actual_value = pcr_values['sha256'][int(pcr_index)]

            if actual_value.hex() != expected_value:
                raise ValueError(
                    f"PCR {pcr_index} mismatch!\n"
                    f"Expected: {expected_value}\n"
                    f"Got: {actual_value.hex()}"
                )

        # 4. All checks passed
        audit_log('ATTESTATION_VERIFIED', pcr_count=len(pcr_values['sha256']))
        return True

# Golden measurements file (reference_pcrs.json)
{
  "0": "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969",
  "1": "b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236",
  "2": "b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236",
  "3": "b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236",
  "4": "f1d2d2f924e986ac86fdf7b36c94bcdf32beec15",
  "5": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "6": "b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236",
  "7": "518bd167271fbb64589c61e43d8c0165861431d8"
}

# Usage
verifier = AttestationVerifier('reference_pcrs.json')
nonce = secrets.token_bytes(32)

# Send nonce to attester, receive quote
quote = receive_quote_from_attester(nonce)

# Verify
if verifier.verify_quote(quote, nonce):
    print("Attestation successful - system trusted")
else:
    print("Attestation failed - system compromised")
```

### Remote Attestation with Intel TXT
```python
# GOOD: Intel TXT attestation
import subprocess
import hashlib

def get_tpm_pcr_values() -> dict:
    """Read TPM PCR values for TXT-measured launch"""
    result = subprocess.run(
        ['tpm2_pcrread', 'sha256:17,18'],  # PCR 17-18 for TXT
        capture_output=True,
        text=True
    )

    # Parse PCR values
    pcrs = {}
    for line in result.stdout.split('\n'):
        if 'sha256' in line and ':' in line:
            pcr_num, value = line.split(':')
            pcr_num = int(pcr_num.strip().split()[-1])
            pcrs[pcr_num] = value.strip()

    return pcrs

def verify_txt_launch():
    """Verify system was launched with Intel TXT"""
    pcrs = get_tpm_pcr_values()

    # PCR 17 = DRTM (Dynamic Root of Trust Measurement)
    # PCR 18 = TXT policy

    # Zero value means TXT not active
    if pcrs.get(17) == '0' * 64:
        raise ValueError("Intel TXT not active - untrusted launch")

    # Verify against known-good measurements
    # (would compare against reference values in production)
    return True
```

**NIST Controls**: SI-7 - Software Integrity, SC-8 - Transmission Confidentiality

---

## HIGH: Insecure PCR Usage (SCA-804, TCG PCR Specification)

**Standard**: SCA-804, TCG TPM 2.0 Library Specification Part 1, NIST SP 800-155

**Finding**: Using resettable PCRs or incorrect PCR banks for security-critical sealing

**PCR Allocation** (TCG Standard):
- **PCR 0-7**: BIOS/UEFI firmware and boot measurements (cannot reset without reboot)
- **PCR 8-15**: OS and application measurements
- **PCR 16**: Debug (resettable)
- **PCR 17-22**: Dynamic measurements (TXT, etc.)
- **PCR 23**: Application support

**Detection Patterns**:

```python
# HIGH: Using resettable PCR for security
def seal_secret_to_tpm(secret: bytes):
    # CRITICAL: PCR 16 is resettable!
    pcr_selection = {'sha256': [16]}  # Wrong PCR

    sealed_data = esapi.Seal(
        parentHandle=storage_key,
        inSensitive=secret,
        pcrSelect=pcr_selection
    )

    return sealed_data

# HIGH: No PCR policy (any system state can unseal)
def seal_without_pcr(secret: bytes):
    # No PCR binding - secret can be unsealed on any system
    sealed_data = esapi.Seal(
        parentHandle=storage_key,
        inSensitive=secret
        # Missing: pcrSelect
    )
```

**Remediation**:

```python
# GOOD: Seal to correct PCRs
from tpm2_pytss import ESAPI, TPM2B_DIGEST

def seal_secret_securely(secret: bytes) -> bytes:
    """Seal secret to boot PCRs (0-7)"""
    esapi = ESAPI()

    # Use boot-time PCRs (cannot reset without reboot)
    pcr_selection = {
        'sha256': [0, 1, 2, 3, 4, 5, 6, 7]  # BIOS, bootloader, kernel
    }

    # Read current PCR values
    _, pcr_values = esapi.PCR_Read(pcrSelectionIn=pcr_selection)

    # Create PCR policy
    policy_session = esapi.StartAuthSession(
        sessionType='POLICY',
        authHash='SHA256'
    )

    # Bind to PCR values
    esapi.PolicyPCR(
        policySession=policy_session,
        pcrDigest=calculate_pcr_digest(pcr_values),
        pcrs=pcr_selection
    )

    # Get policy digest
    policy_digest = esapi.PolicyGetDigest(policy_session)

    # Seal data with PCR policy
    sealed_data = esapi.Create(
        parentHandle=storage_key,
        inSensitive={'data': secret},
        inPublic={
            'type': 'KEYEDHASH',
            'nameAlg': 'SHA256',
            'objectAttributes': 'fixedTPM|fixedParent',
            'authPolicy': policy_digest  # PCR policy required to unseal
        }
    )

    return sealed_data

def unseal_secret_securely(sealed_data: bytes) -> bytes:
    """Unseal only if PCR values match sealing time"""
    esapi = ESAPI()

    # Load sealed object
    handle = esapi.Load(
        parentHandle=storage_key,
        inPrivate=sealed_data['private'],
        inPublic=sealed_data['public']
    )

    # Start policy session
    policy_session = esapi.StartAuthSession(
        sessionType='POLICY',
        authHash='SHA256'
    )

    # Satisfy PCR policy
    esapi.PolicyPCR(
        policySession=policy_session,
        pcrs={'sha256': [0, 1, 2, 3, 4, 5, 6, 7]}
    )

    # Unseal (will fail if PCRs changed)
    try:
        unsealed = esapi.Unseal(
            itemHandle=handle,
            auth=policy_session
        )
        return unsealed
    except Exception as e:
        # PCR values changed - system state different
        raise ValueError(f"Unseal failed - system state changed: {e}")
```

**NIST Controls**: SC-28 - Protection of Information at Rest, SC-28(1) - Cryptographic Protection

---

## HIGH: Missing Attestation Key Provisioning (SCA-805, TCG EK/AK)

**Standard**: SCA-805, TCG TPM 2.0 Keys for Device Identity and Attestation

**Finding**: No Endorsement Key (EK) or Attestation Key (AK) provisioned

**TPM Key Hierarchy**:
- **Endorsement Key (EK)**: TPM identity, never signs user data, used for credential activation
- **Attestation Key (AK)**: Restricted signing key, only signs TPM-generated structures (quotes)
- **Storage Root Key (SRK)**: Parent for storage keys

**Remediation**:

```python
# GOOD: Provision EK and AK
from tpm2_pytss import ESAPI

def provision_tpm_keys():
    """Provision EK and AK for attestation"""
    esapi = ESAPI()

    # 1. Create Endorsement Key (EK) - RSA 2048
    ek_template = {
        'type': 'RSA',
        'nameAlg': 'SHA256',
        'objectAttributes': (
            'fixedTPM',
            'fixedParent',
            'sensitiveDataOrigin',
            'adminWithPolicy',
            'restricted',
            'decrypt'
        ),
        'authPolicy': b'\x83\x71\x97\x67...',  # Well-known EK policy
        'parameters': {
            'rsaDetail': {
                'symmetric': 'AES128CFB',
                'scheme': 'NULL',
                'keyBits': 2048,
                'exponent': 0
            }
        }
    }

    ek_handle, ek_public, _, _, _ = esapi.CreatePrimary(
        primaryHandle='ENDORSEMENT',
        inPublic=ek_template
    )

    # Make EK persistent
    ek_persistent = esapi.EvictControl(
        auth='ENDORSEMENT',
        objectHandle=ek_handle,
        persistentHandle=0x81010001
    )

    # 2. Create Attestation Key (AK) under EK
    ak_template = {
        'type': 'RSA',
        'nameAlg': 'SHA256',
        'objectAttributes': (
            'fixedTPM',
            'fixedParent',
            'sensitiveDataOrigin',
            'userWithAuth',
            'restricted',  # Can only sign TPM-generated data
            'sign'
        ),
        'parameters': {
            'rsaDetail': {
                'symmetric': 'NULL',
                'scheme': 'RSASSA',
                'keyBits': 2048,
                'exponent': 0
            }
        }
    }

    ak_private, ak_public, _, _, _ = esapi.Create(
        parentHandle=ek_persistent,
        inPublic=ak_template
    )

    # Load AK
    ak_handle = esapi.Load(
        parentHandle=ek_persistent,
        inPrivate=ak_private,
        inPublic=ak_public
    )

    # Make AK persistent
    ak_persistent = esapi.EvictControl(
        auth='ENDORSEMENT',
        objectHandle=ak_handle,
        persistentHandle=0x81010002
    )

    return ek_persistent, ak_persistent

# EK Certificate Validation
def validate_ek_certificate(ek_cert_der: bytes):
    """Validate TPM Endorsement Key certificate"""
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend

    cert = x509.load_der_x509_certificate(ek_cert_der, default_backend())

    # Verify issuer is trusted TPM manufacturer
    trusted_issuers = [
        'CN=Intel(R) TPM EK Intermediate CA',
        'CN=AMD Endorsement Key Certificate',
        'CN=Infineon OPTIGA(TM) ECC Root CA'
    ]

    issuer = cert.issuer.rfc4514_string()
    if not any(trusted in issuer for trusted in trusted_issuers):
        raise ValueError(f"Untrusted EK issuer: {issuer}")

    # Verify certificate is valid
    # (would check against CRL/OCSP in production)

    return True
```

**NIST Controls**: IA-2 - Identification and Authentication, IA-5 - Authenticator Management

---

## MEDIUM: TPM 1.2 Usage (SCA-806, TCG Deprecation)

**Standard**: SCA-806, TCG TPM 2.0 Library Specification (TPM 1.2 deprecated)

**Finding**: Using deprecated TPM 1.2 instead of TPM 2.0

**TPM 1.2 Limitations**:
- Limited crypto algorithms (RSA only, no ECC)
- SHA-1 only (deprecated)
- Complex authorization (OIAP/OSAP)
- No policy-based authorization
- Limited PCR banks

**Detection Patterns**:

```bash
# MEDIUM: Check TPM version
$ cat /sys/class/tpm/tpm0/tpm_version_major
1  # TPM 1.2 (deprecated)
```

**Remediation**:

```bash
# GOOD: Verify TPM 2.0
#!/bin/bash

TPM_VERSION=$(cat /sys/class/tpm/tpm0/tpm_version_major 2>/dev/null)

if [ "$TPM_VERSION" != "2" ]; then
    echo "ERROR: TPM 2.0 required, found TPM $TPM_VERSION"
    echo "RECOMMENDATION: Upgrade to hardware with TPM 2.0"
    exit 1
fi

# Verify TPM 2.0 capabilities
tpm2_getcap properties-fixed | grep -q "TPM2_PT_FAMILY_INDICATOR"

echo "TPM 2.0 verified"
```

**NIST Controls**: SA-22 - Unsupported System Components

---

## MEDIUM: Missing Confidential Computing Attestation (SCA-807, CCC)

**Standard**: SCA-807, Confidential Computing Consortium Attestation

**Finding**: Running in TEE (SGX, SEV, TDX) without attestation

**Confidential Computing Technologies**:
- **Intel SGX**: Software Guard Extensions (enclaves)
- **AMD SEV**: Secure Encrypted Virtualization
- **Intel TDX**: Trust Domain Extensions
- **ARM TrustZone**: Trusted Execution Environment

**Remediation**:

### Intel SGX Attestation
```c
// GOOD: SGX remote attestation
#include <sgx_urts.h>
#include <sgx_quote.h>

sgx_status_t generate_sgx_quote(sgx_enclave_id_t eid) {
    sgx_status_t ret;
    sgx_report_t report;
    sgx_target_info_t qe_target_info;
    sgx_quote_t *quote = NULL;
    uint32_t quote_size = 0;

    // 1. Get Quoting Enclave target info
    ret = sgx_init_quote(&qe_target_info, &gid);
    if (ret != SGX_SUCCESS) {
        return ret;
    }

    // 2. Generate enclave report
    ret = enclave_create_report(eid, &qe_target_info, &report);
    if (ret != SGX_SUCCESS) {
        return ret;
    }

    // 3. Get quote size
    ret = sgx_calc_quote_size(NULL, 0, &quote_size);
    quote = (sgx_quote_t*)malloc(quote_size);

    // 4. Get quote from QE
    ret = sgx_get_quote(&report,
                        SGX_UNLINKABLE_SIGNATURE,
                        &spid,
                        NULL,
                        NULL, 0,
                        NULL,
                        quote,
                        quote_size);

    // 5. Send quote to attestation service for verification
    verify_quote_with_ias(quote, quote_size);

    return ret;
}
```

### AMD SEV Attestation
```python
# GOOD: AMD SEV attestation
import struct
import hashlib

def verify_sev_attestation(measurement: bytes, expected_measurement: bytes):
    """Verify AMD SEV launch measurement"""

    if measurement != expected_measurement:
        raise ValueError(
            f"SEV measurement mismatch!\n"
            f"Expected: {expected_measurement.hex()}\n"
            f"Got: {measurement.hex()}"
        )

    # Verify attestation report signature
    # (would verify with AMD KDS in production)

    return True

def get_sev_measurement(vm_guid: str) -> bytes:
    """Get SEV launch measurement from hypervisor"""
    # In production, query hypervisor API
    # For QEMU/KVM:
    # $ virsh qemu-monitor-command <vm> --hmp "info sev"

    # Returns SHA-256 of: firmware + kernel + initrd + cmdline
    return hashlib.sha256(b'...').digest()
```

**NIST Controls**: SC-39 - Process Isolation, SC-7 - Boundary Protection

---

## Summary Table

| Finding | Severity | Standard | NIST Control | Remediation Priority |
|---------|----------|----------|--------------|---------------------|
| Missing TPM for crypto | Critical | SCA-801, NIST SP 800-147 | SC-12, SC-13 | Immediate |
| Missing Secure Boot | Critical | SCA-802, NIST SP 800-147 | SI-7, SI-7(6) | Immediate |
| Missing remote attestation | Critical | SCA-803, TCG | SI-7, SC-8 | Immediate |
| Insecure PCR usage | High | SCA-804, TCG | SC-28, SC-28(1) | High |
| Missing EK/AK provisioning | High | SCA-805, TCG | IA-2, IA-5 | High |
| TPM 1.2 usage | Medium | SCA-806, TCG | SA-22 | Medium |
| Missing TEE attestation | Medium | SCA-807, CCC | SC-39, SC-7 | Medium |

---

## Compliance Mapping

### NIST SP 800-53 Rev 5
- **SC-12**: Cryptographic Key Establishment
- **SC-13**: Cryptographic Protection
- **SC-28**: Protection of Information at Rest
- **SC-28(1)**: Cryptographic Protection
- **SI-7**: Software, Firmware, and Information Integrity
- **SI-7(6)**: Integrity Verification
- **IA-2**: Identification and Authentication
- **SC-39**: Process Isolation

### NIST Platform Firmware Guidelines
- **NIST SP 800-147**: BIOS Protection Guidelines
- **NIST SP 800-155**: BIOS Integrity Measurement Guidelines
- **NIST SP 800-193**: Platform Firmware Resiliency Guidelines

### TCG (Trusted Computing Group)
- **TPM 2.0 Library Specification**
- **PC Client Platform TPM Profile**
- **TPM Keys for Device Identity and Attestation**

### Confidential Computing Consortium
- **Attestation Specification**
- **Confidential Computing Threat Model**

---

## Testing

### Automated Checks
```bash
# Check TPM presence
ls /dev/tpm* || echo "No TPM device found"

# Check TPM version
cat /sys/class/tpm/tpm0/tpm_version_major

# Check Secure Boot status
mokutil --sb-state

# Read PCR values
tpm2_pcrread sha256:0,1,2,3,4,5,6,7

# List persistent TPM objects
tpm2_getcap handles-persistent

# Check for attestation keys
tpm2_readpublic -c 0x81010002  # AK handle
```

### Manual Review
1. Verify TPM 2.0 is available and enabled
2. Check UEFI Secure Boot is enabled
3. Verify boot components are signed
4. Review PCR values for anomalies
5. Test attestation quote generation
6. Verify EK certificate chain
7. For TEE: verify attestation service integration

### Security Testing
```python
# Test PCR sealing
def test_pcr_sealing():
    """Verify secrets cannot be unsealed if PCRs change"""
    secret = b"sensitive_data"

    # Seal to current PCRs
    sealed = seal_secret_securely(secret)

    # Should unseal successfully
    assert unseal_secret_securely(sealed) == secret

    # Extend PCR (simulate boot change)
    extend_boot_measurement(pcr_index=7, measurement=b"new_component")

    # Should fail to unseal
    try:
        unseal_secret_securely(sealed)
        assert False, "Should not unseal after PCR change"
    except ValueError:
        pass  # Expected
```

---

## Implementation Guide

### 1. Enable TPM and Secure Boot
```bash
# Check BIOS/UEFI settings:
# - Enable TPM 2.0
# - Enable Secure Boot
# - Enable Intel TXT or AMD Platform Security Processor (if available)

# Verify from OS
mokutil --sb-state  # Should show "SecureBoot enabled"
ls /dev/tpm0        # TPM device should exist
```

### 2. Provision TPM Keys
```bash
# Create EK (if not factory-provisioned)
tpm2_createek -c ek.ctx -G rsa -u ek.pub

# Make EK persistent
tpm2_evictcontrol -c ek.ctx 0x81010001

# Create AK
tpm2_createak -C ek.ctx -c ak.ctx -G rsa -g sha256 -s rsassa -u ak.pub -n ak.name

# Make AK persistent
tpm2_evictcontrol -c ak.ctx 0x81010002
```

### 3. Implement Attestation Service
- Deploy attestation verifier service
- Collect golden PCR measurements from trusted systems
- Implement quote verification endpoint
- Integrate with access control decisions

### 4. Seal Sensitive Data
- Identify secrets/keys to protect (encryption keys, credentials)
- Seal to appropriate PCRs (boot PCRs for boot secrets, OS PCRs for runtime)
- Test unsealing under normal and tampered conditions

### 5. Monitor and Alert
- Log all attestation attempts
- Alert on attestation failures
- Monitor PCR values for unexpected changes
- Track TPM usage and errors
