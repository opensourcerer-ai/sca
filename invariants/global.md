# Global Security Invariants (v1)

## Secrets & Credentials

- **No committed secrets**: No tokens, private keys, seed words, credentials, session secrets, API keys in source code or config files
- **No logging of sensitive data**: No logging of credentials, tokens, session IDs, PII (SSN, credit cards, passwords, biometrics)
- **Environment variable security**:
  - Secrets in env vars MUST NOT be logged or printed
  - Env vars MUST NOT leak via error messages, stack traces, or debug output
  - Env vars containing secrets MUST be sanitized before external transmission
- **Reading keys from disk**:
  - Keys MUST only be read from secure paths with restricted permissions (0600 or stricter)
  - Keys MUST NOT be read from world-readable files or directories
  - Key files MUST be in secure storage (KMS, HSM, encrypted volumes)
  - Key file paths MUST NOT be logged or exposed in error messages

## Cryptography

- **Approved primitives only**: Use approved primitives and safe modes (no ECB; no homebrew crypto; no MD5/SHA1 for security)
- **Secure random number generation**: Use cryptographically secure RNGs for keys, tokens, nonces, IVs
- **TLS configuration**: Require TLS 1.2+, validate certificates, use strong cipher suites

## Injection Attacks (CRITICAL)

### SQL Injection
- **NEVER concatenate user input into SQL queries**
- **ALWAYS use parameterized queries or prepared statements**
- Patterns to flag as Critical:
  - String concatenation/interpolation in SQL: `"SELECT * FROM users WHERE id = " + userId`
  - Format strings in SQL: `f"SELECT * FROM users WHERE id = {userId}"`, `"... WHERE id = %s" % userId`
  - Template literals in SQL: `` `SELECT * FROM users WHERE id = ${userId}` ``

### Command Injection
- **NEVER pass unsanitized user input to shell commands**
- **AVOID shell execution entirely** (use native APIs instead of shelling out)
- Patterns to flag as Critical:
  - `os.system()`, `subprocess.call(shell=True)`, `exec()`, `eval()` with user input
  - `Runtime.exec()`, `ProcessBuilder` with shell syntax
  - Backticks, `system()`, `popen()`, `exec()` in any language with user data

### LDAP Injection
- **Escape special chars in LDAP filters**: `*`, `(`, `)`, `\`, NUL
- **Use parameterized LDAP queries** where available

### XPath Injection
- **Parameterize XPath queries**
- **Escape user input** before interpolation into XPath expressions

### NoSQL Injection
- **Validate/sanitize input for MongoDB, CouchDB, etc.**
- **Never pass raw user objects** to query methods (e.g., `db.collection.find(userInput)`)

### Template Injection (SSTI - Server-Side Template Injection)
- **Never render user-controlled template strings**
- **Use auto-escaping template engines** (Jinja2 with autoescape, React/Vue JSX)
- Patterns to flag: `template.render(userInput)`, `eval(templateString)` where user controls content

### XML External Entity (XXE) Injection
- **Disable external entity processing** in XML parsers
- **Use defusedxml or equivalent** in Python
- **Configure parsers to reject DTDs**

### Header Injection
- **Validate HTTP header values** (no CRLF: `\r`, `\n`)
- **Use framework header APIs** that auto-sanitize

### Path Traversal
- **Validate file paths** to prevent `../` traversal
- **Use allowlists for file access** (not denylists)
- **Canonicalize paths** before access checks
- Patterns to flag: `open(userInput)`, `File(userInput)`, path concatenation with user input

## Authorization

- **Authorization checks at every privileged operation** (not just entrypoint)
- **Deny by default** (explicit grants, not implicit)
- **Separation of duties**: No single user/role with full permissions
- **Validate ownership**: Users can only access their own resources
- **Insecure Direct Object Reference (IDOR)**: Check that IDs in URLs/requests belong to authenticated user

## Input Validation

- **All inputs validated and bounded**: Size, type, format, range
- **Allowlist validation preferred** over denylist
- **Reject unexpected input** (fail closed)
- **Normalize before validation** (Unicode normalization, path canonicalization)

## Dependencies

- **Lockfiles required**: `package-lock.json`, `Pipfile.lock`, `Cargo.lock`, `go.sum`, `Gemfile.lock`
- **Pinned versions in CI/CD**: Reproducible builds
- **Dependency scanning**: Regular CVE checks

## Build & Release

- **No unpinned remote scripts**: Build scripts MUST NOT run `curl | bash` or fetch/execute unverified code
- **Integrity verification**: Use checksums/signatures for downloaded artifacts
- **Immutable artifacts**: Published packages/images MUST NOT be mutable

## Network Security

- **All outbound network calls have timeouts** (prevent infinite hangs)
- **Rate limiting on APIs** (prevent DoS, abuse)
- **CORS properly configured** (least privilege origins)
- **CSRF protection** for state-changing operations

### SSL/TLS Requirements (CRITICAL)
- **TLS version**: MUST use TLS 1.2+ (flag TLS 1.0, 1.1, SSLv3 as Critical)
- **Certificate validation**: MUST validate server certificates in production
  - NEVER: `verify=False` (Python requests), `InsecureSkipVerify: true` (Go), `NODE_TLS_REJECT_UNAUTHORIZED=0` (Node.js)
  - Flag as CRITICAL: Any code disabling certificate validation
- **Certificate pinning**: RECOMMENDED for mobile/desktop apps connecting to known servers
- **Proper certificate chains**: Verify full chain, not just leaf certificate
- **Hostname verification**: MUST verify certificate hostname matches target
- **Weak cipher suites**: Disable NULL, EXPORT, DES, RC4, MD5-based ciphers
  - Prefer forward secrecy (ECDHE, DHE)
  - Example approved: `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`

### Non-SSL Connections (Flag as High, EXCEPT Unix Domain Sockets)
- **HTTP instead of HTTPS**: Flag all `http://` URLs (except localhost in dev)
  - Pattern: `http://api.example.com` in production config (HIGH)
  - Exception: `http://localhost`, `http://127.0.0.1` in development only
- **Plaintext protocols**: Flag FTP, Telnet, LDAP (use FTPS, SSH, LDAPS)
- **Database connections**: Require SSL/TLS (flag `sslmode=disable`, `useSSL=false`)
- **Acceptable exceptions**:
  - Unix domain sockets (local IPC)
  - Localhost connections (127.0.0.1, ::1) in non-production environments
  - Internal networks with network-level encryption (IPsec, WireGuard) - must document

### Certificate Management
- **Expired certificates**: Flag certificates with expiry < 30 days
- **Self-signed certificates**: Flag in production (High), acceptable in dev/test with documentation
- **Wildcard certificates**: Avoid for different trust domains (e.g., *.example.com for user.example.com AND admin.example.com)
- **Certificate storage**: Private keys MUST be in secure storage (KMS, HSM, encrypted), NEVER in source code

### Sensitive Data Written to Disk (CRITICAL)
- **Unencrypted sensitive data**: Flag writes of secrets/PII/financial data to unencrypted files
  - Patterns to detect:
    - `open(path, 'w').write(api_key)` where `api_key` matches key patterns
    - `File.write(password)` in plaintext
    - Logs/temp files containing tokens, SSNs, credit cards
- **World-readable files**: Sensitive files MUST have restrictive permissions (0600, not 0644 or 0777)
  - Check `chmod`, `os.chmod()`, `File.setReadable()` calls
- **Temp file security**: Use secure temp file APIs (`mkstemp`, `tempfile.NamedTemporaryFile` with `delete=True`)
  - NEVER: `/tmp/myapp-secret.txt` (predictable path)
- **Log files**: MUST NOT contain secrets (check log statements for password/token variables)
- **Crash dumps/core dumps**: Disable or encrypt (may contain keys in memory)
- **Database backups**: MUST be encrypted at rest
- **Swap/page files**: Sensitive data in memory may leak to swap (use `mlock()` for keys)

## Error Handling

- **No sensitive data in error messages** (stack traces, internal paths, SQL queries, connection strings)
- **Generic errors to users**, detailed logs to secure backend
- **No unhandled exceptions in production** (leads to info disclosure, crashes)

## Logging

- **Structured logging with log levels**
- **No secrets in logs** (passwords, tokens, keys, PII)
- **Audit logs for security events** (auth failures, privilege escalation, data access)
- **Log rotation and retention policies**

## Session Management

- **Secure session token generation** (cryptographic randomness, sufficient entropy)
- **HttpOnly, Secure, SameSite flags** on cookies
- **Session expiration and renewal**
- **Logout invalidates sessions** (server-side)

## File Upload

- **Validate file types** (magic bytes, not just extension)
- **Size limits enforced**
- **Store uploads outside webroot** (prevent execution)
- **Scan for malware** if high-risk context

## Deserialization

- **Never deserialize untrusted data** without validation (pickle, YAML, Java serialization)
- **Use safe serialization formats** (JSON, protobuf with schema validation)
- **Disable dangerous features** (YAML `!!python/object`, pickle `__reduce__`)

## SSRF (Server-Side Request Forgery)

- **Validate URLs** before making requests (allowlist domains)
- **Prevent access to internal IPs** (127.0.0.1, 169.254.169.254, private ranges)
- **Use network segmentation** (app servers can't reach internal infrastructure)

## XSS (Cross-Site Scripting)

- **Auto-escape output** in templates
- **Use CSP headers** (Content Security Policy)
- **Validate/sanitize HTML input** (use allowlist-based sanitizers like DOMPurify)
- **Avoid innerHTML**, use `textContent` or framework equivalents

## CSRF (Cross-Site Request Forgery)

- **CSRF tokens on state-changing operations**
- **SameSite cookie attribute**
- **Verify Origin/Referer headers** for API endpoints

## Information Disclosure

- **No sensitive data in HTML comments** or client-side code
- **No debug endpoints in production** (`/debug`, `/metrics` without auth)
- **No directory listing**
- **Server version hiding** (remove/obfuscate `Server` headers)

## Concurrency & Race Conditions

- **Protect shared state with locks** or use lock-free data structures
- **Avoid TOCTOU** (time-of-check-time-of-use) vulnerabilities
- **Atomic operations** for critical sections

## Reporting Guidelines

For each finding:
1. **Severity**: Critical (RCE, data breach) | High (auth bypass) | Medium (info leak) | Low (hardening)
2. **Evidence**: File path, line number, code snippet
3. **Impact**: Confidentiality, Integrity, Availability
4. **Remediation**: Specific fix with code example
5. **Compliance**: OWASP Top 10 category, CWE ID, regulatory requirements (PCI-DSS, GDPR, etc.)
