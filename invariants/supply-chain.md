# Supply Chain Security Invariants (v1)

## Overview

This file defines security invariants for supply chain risk management, software composition, and dependency security aligned with:
- **NIST SP 800-53 Rev 5**: SR (Supply Chain Risk Management), SA (System and Services Acquisition), SI-7 (Software Integrity)
- **NIST SSDF**: Secure Software Development Framework (PW.4, PS.2, PW.9)
- **NIST SP 800-161**: Supply Chain Risk Management Practices
- **NIST SP 800-171**: Requirements 3.13.1, 3.14.1, 3.14.2
- **OWASP**: A06:2021 (Vulnerable and Outdated Components)
- **CWE-1357**: Reliance on Insufficiently Trustworthy Component

---

## CRITICAL: Dependency with Known Vulnerabilities (CWE-1035, NIST SA-12)

**Standard**: CWE-1035, OWASP A06:2021, NIST SP 800-53 SA-12, SR-3, NIST SSDF PW.4

**Finding**: Using dependencies with published CVEs or security advisories

**Detection Patterns**:

### Python (requirements.txt)
```txt
# CRITICAL: Old Django with CVE-2023-24580
Django==3.0.0

# CRITICAL: Old requests with CVE-2023-32681
requests==2.25.0

# CRITICAL: Pillow with image processing CVE
Pillow==8.0.0
```

### JavaScript (package.json)
```json
{
  "dependencies": {
    // CRITICAL: express with CVE-2024-29041
    "express": "4.17.1",
    
    // CRITICAL: lodash prototype pollution
    "lodash": "4.17.15",
    
    // CRITICAL: axios SSRF CVE-2023-45857
    "axios": "0.21.0"
  }
}
```

### Java (pom.xml)
```xml
<!-- CRITICAL: Log4j with CVE-2021-44228 (Log4Shell) -->
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.14.0</version>
</dependency>

<!-- CRITICAL: Spring Boot with CVE-2022-22965 (Spring4Shell) -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
    <version>2.5.0</version>
</dependency>
```

### Go (go.mod)
```go
// CRITICAL: grpc with HTTP/2 vulnerabilities
require (
    google.golang.org/grpc v1.40.0  // CVE-2023-44487
)
```

**Automated Detection**:
```bash
# Python
pip-audit --desc on

# JavaScript/Node.js
npm audit
npm audit fix

# Java
mvn org.owasp:dependency-check-maven:check

# Go
govulncheck ./...

# Ruby
bundle audit

# Rust
cargo audit
```

**Remediation**:
```bash
# Update to patched versions
pip install --upgrade Django>=4.2.5
npm install express@latest
mvn versions:use-latest-releases
go get -u google.golang.org/grpc
```

**NIST Controls**: SA-12 - Supply Chain Protection, SR-3 - Supply Chain Controls and Processes, SSDF PW.4 - Reuse Existing Software

---

## CRITICAL: Malicious Package (Typosquatting, Dependency Confusion) (CWE-494, NIST SR-11)

**Standard**: CWE-494, SCA-019, NIST SP 800-53 SR-11, NIST SSDF PS.2

**Finding**: Potential malicious packages through typosquatting or dependency confusion

**Detection Patterns**:

### Python
```python
# CRITICAL: Typosquatting (should be 'requests')
import requets

# CRITICAL: Suspicious package name
from python3-dateutil import parser  # Real package is 'python-dateutil'

# Package.txt shows:
# requets==1.0.0  # Malicious typosquat
# python3-dateutil==2.0.0  # Malicious
```

### JavaScript
```json
{
  "dependencies": {
    // CRITICAL: Typosquatting (should be 'lodash')
    "loddash": "^1.0.0",
    
    // CRITICAL: Internal package name exposed (dependency confusion)
    "@mycompany/internal-lib": "^1.0.0"  // If not from private registry, could be malicious
  }
}
```

### Common Typosquatting Patterns
- `requets` instead of `requests`
- `loddash` instead of `lodash`
- `python3-dateutil` instead of `python-dateutil`
- `cross-env.js` instead of `cross-env`
- `babelcli` instead of `babel-cli`

**Detection Methods**:

```bash
# Check package author and downloads
pip show requests  # Verify author and version
npm info lodash  # Check weekly downloads

# Verify package hash/checksum
pip install --require-hashes -r requirements.txt

# Use private package registry for internal packages
npm config set registry https://registry.npmjs.org/
npm config set @mycompany:registry https://npm.internal.mycompany.com/
```

**Remediation**:
1. Remove malicious package: `pip uninstall requets && pip install requests`
2. Pin dependencies with hashes
3. Use package name linting tools
4. Configure private registries for internal packages
5. Enable npm/pip signature verification

**NIST Controls**: SR-11 - Component Authenticity, SR-4 - Provenance, SSDF PS.2 - Verify Acquired Software

---

## HIGH: Unpinned Dependencies (SCA-020, NIST SA-11)

**Standard**: SCA-020, NIST SP 800-53 SA-11, NIST SSDF PW.4

**Finding**: Dependencies without version pinning or hash verification

**Detection Patterns**:

### Python (requirements.txt)
```txt
# HIGH: No version pinning
Django
requests>=2.0  # Allows any version >= 2.0, including future vulnerable versions

# MEDIUM: Caret/tilde ranges too broad
Flask~=2.0  # Allows 2.x upgrades
```

### JavaScript (package.json)
```json
{
  "dependencies": {
    // HIGH: Caret allows minor/patch updates
    "express": "^4.17.1",  // Could pull 4.99.99
    
    // HIGH: Wildcard
    "lodash": "*",
    
    // HIGH: Latest tag
    "axios": "latest"
  }
}
```

### Go (go.mod)
```go
// MEDIUM: Indirect dependencies unspecified
require (
    github.com/gin-gonic/gin v1.7  // Missing patch version
)
```

**Risks**:
- Automatic updates may introduce vulnerabilities
- Build non-reproducibility
- Supply chain attack via dependency update
- Breaking changes in minor/patch versions

**Remediation**:

### Python - Pinned with Hashes
```txt
# requirements.txt with exact versions
Django==4.2.5 \
    --hash=sha256:8e0f1c2c2786b5c0e39fe1afce24c926040fad47c8ea8ad30aaf1188df29fc41

requests==2.31.0 \
    --hash=sha256:58cd2187c01e70e6e26505bca751777aa9f2ee0b7f4300988b709f44e013003f

# Generate hashes
pip-compile --generate-hashes requirements.in
```

### JavaScript - Exact Versions with Lock File
```json
{
  "dependencies": {
    "express": "4.18.2",  // Exact version
    "lodash": "4.17.21",
    "axios": "1.5.0"
  }
}
```

```bash
# Always commit lock files
git add package-lock.json
git add yarn.lock
git add Pipfile.lock
git add Cargo.lock
```

### Go - Exact Versions
```go
require (
    github.com/gin-gonic/gin v1.9.1  // Full semantic version
    github.com/golang-jwt/jwt/v5 v5.0.0
)
```

**NIST Controls**: SA-11 - Developer Security Testing, SSDF PW.4 - Reuse Existing Software with Secure Configuration

---

## HIGH: Missing Software Bill of Materials (SBOM) (NIST SA-10, EO 14028)

**Standard**: SCA-021, NIST SP 800-53 SA-10, NIST SSDF PO.1, Executive Order 14028

**Finding**: No SBOM documenting all software components

**Detection**: Look for absence of SBOM files (sbom.json, sbom.spdx, etc.)

**SBOM Requirements (EO 14028, NTIA Minimum Elements)**:
1. Supplier name
2. Component name
3. Version of component
4. Other unique identifiers (e.g., CPE, PURL)
5. Dependency relationship
6. Author of SBOM data
7. Timestamp

**Generation Tools**:

### Python
```bash
# CycloneDX SBOM
cyclonedx-py --requirements requirements.txt --output sbom.json --format json

# SPDX SBOM
pip install spdx-tools
spdx-tools convert -i requirements.txt -o sbom.spdx
```

### JavaScript
```bash
# CycloneDX SBOM
npm install -g @cyclonedx/cyclonedx-npm
cyclonedx-npm --output-file sbom.json

# Syft (multi-language)
syft packages dir:. -o spdx-json > sbom.spdx.json
```

### Java
```xml
<!-- Maven plugin for SBOM generation -->
<plugin>
    <groupId>org.cyclonedx</groupId>
    <artifactId>cyclonedx-maven-plugin</artifactId>
    <version>2.7.9</version>
    <executions>
        <execution>
            <goals>
                <goal>makeAggregateBom</goal>
            </goals>
        </execution>
    </executions>
</plugin>
```

**Remediation**:
1. Generate SBOM as part of build process
2. Commit SBOM to repository
3. Distribute SBOM with software releases
4. Automate SBOM updates on dependency changes

```yaml
# GitHub Actions SBOM generation
name: Generate SBOM
on: [push]
jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Generate SBOM
        run: |
          npm install -g @cyclonedx/cyclonedx-npm
          cyclonedx-npm --output-file sbom.json
      - name: Upload SBOM
        uses: actions/upload-artifact@v3
        with:
          name: sbom
          path: sbom.json
```

**NIST Controls**: SA-10 - Developer Configuration Management, SSDF PO.1 - Define Security Requirements

---

## MEDIUM: Insecure Dependency Download (CWE-494, NIST SR-3)

**Standard**: CWE-494, NIST SP 800-53 SR-3, SC-8, NIST SSDF PS.2

**Finding**: Dependencies downloaded over insecure channels (HTTP instead of HTTPS)

**Detection Patterns**:

### Python
```ini
# ~/.pip/pip.conf - MEDIUM: HTTP index
[global]
index-url = http://pypi.org/simple/  # Should be https://
```

### JavaScript
```bash
# MEDIUM: HTTP registry
npm config set registry http://registry.npmjs.org/  # Should be https://
```

### Maven (pom.xml)
```xml
<!-- MEDIUM: HTTP repository -->
<repository>
    <id>central</id>
    <url>http://repo.maven.apache.org/maven2</url>  <!-- Should be https:// -->
</repository>
```

### Go
```bash
# MEDIUM: GOPRIVATE without HTTPS enforcement
export GOPRIVATE=internal.company.com
# Should verify TLS: go env -w GOINSECURE=""
```

**Remediation**:
```bash
# Python - Force HTTPS
pip config set global.index-url https://pypi.org/simple/

# JavaScript - Force HTTPS
npm config set registry https://registry.npmjs.org/

# Maven - Use HTTPS repositories
<repository>
    <id>central</id>
    <url>https://repo.maven.apache.org/maven2</url>
</repository>

# Go - Enforce checksum verification
export GOSUMDB=sum.golang.org  # Default checksum database
```

**NIST Controls**: SR-3 - Supply Chain Controls, SC-8 - Transmission Confidentiality, SSDF PS.2 - Verify Acquired Software

---

## MEDIUM: No Dependency Integrity Checks (SCA-022, NIST SI-7)

**Standard**: SCA-022, NIST SP 800-53 SI-7, NIST SSDF PS.2

**Finding**: No cryptographic verification of downloaded dependencies

**Detection Patterns**:

### Python
```bash
# MEDIUM: No hash verification
pip install -r requirements.txt  # No --require-hashes flag

# requirements.txt without hashes
Django==4.2.5  # No hash
```

### JavaScript
```bash
# MEDIUM: npm install without lock file integrity check
npm install --no-package-lock  # Skips integrity verification
```

**Remediation**:

### Python - Hash Verification
```txt
# requirements.txt with hashes (generated by pip-compile --generate-hashes)
Django==4.2.5 \
    --hash=sha256:8e0f1c2c2786b5c0e39fe1afce24c926040fad47c8ea8ad30aaf1188df29fc41
requests==2.31.0 \
    --hash=sha256:58cd2187c01e70e6e26505bca751777aa9f2ee0b7f4300988b709f44e013003f
```

```bash
# Install with hash verification
pip install --require-hashes -r requirements.txt
```

### JavaScript - Lock File Integrity
```bash
# Verify integrity on install
npm ci  # Uses package-lock.json for reproducible builds with integrity checks

# Check for modifications
npm audit fix --package-lock-only
```

### Go - Checksum Verification
```bash
# go.sum file automatically created and verified
go mod verify  # Verifies checksums in go.sum
```

**NIST Controls**: SI-7 - Software Integrity, SI-7(1) - Integrity Checks, SSDF PS.2 - Verify Acquired Software

---

## MEDIUM: Build Process Not Reproducible (SCA-023, NIST SA-11)

**Standard**: SCA-023, NIST SP 800-53 SA-11, NIST SSDF PW.9

**Finding**: Builds are not deterministic or reproducible

**Detection Indicators**:
- No lock files committed
- Timestamps embedded in binaries
- Random build IDs
- No build environment specification

**Remediation**:

### Reproducible Builds Checklist
```bash
# 1. Pin all dependencies
git add package-lock.json
git add Pipfile.lock
git add go.sum
git add Cargo.lock

# 2. Document build environment
cat > BUILD.md <<EOF
# Build Environment
- OS: Ubuntu 22.04 LTS
- Python: 3.11.5
- Node.js: 18.17.0
- Go: 1.21.1
- Docker: 24.0.5

# Build Command
docker build --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) .
