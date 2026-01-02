# Logging Security Invariants — Sensitive Data Detection (v1)

## Critical Principle
**NEVER log sensitive data**. Logs are often stored insecurely, transmitted over networks, aggregated in centralized systems, and accessible to operators, SREs, and third-party services (Datadog, Splunk, etc.). A single log statement can expose credentials to thousands of people.

---

## CRITICAL: Confirmed Sensitive Data in Logs

### Authentication Credentials (CRITICAL)
Flag as **Critical** if log statement clearly contains:

**Passwords**:
```python
# CRITICAL
logger.info(f"User login with password: {password}")
log.Printf("Password: %s", password)
console.log("User password:", password);
LOG.error("Failed auth with password: {}", password);
```

**API Keys / Access Tokens**:
```python
# CRITICAL
logger.debug(f"API key: {api_key}")
log.Info("Using token: " + access_token)
logger.warn("Invalid API key: {}", apiKey);
```

**Private Keys / Certificates**:
```python
# CRITICAL
log.write(f"Private key: {private_key}")
logger.info("Certificate: %s" % cert_pem)
```

**Session Tokens / JWTs**:
```python
# CRITICAL
logger.info(f"Session token: {session_id}")
log.Debug("JWT: " + jwt_token)
```

### Patterns for CRITICAL Detection
Search for log statements containing variables that match:
- `password`, `passwd`, `pwd`, `pass_word`, `user_password`, `admin_password`
- `api_key`, `apiKey`, `API_KEY`, `secret_key`, `secretKey`, `access_key`
- `token`, `access_token`, `refresh_token`, `auth_token`, `bearer_token`, `jwt`
- `private_key`, `privateKey`, `priv_key`, `secret`, `client_secret`
- `certificate`, `cert`, `pem`, `key_file`
- `session_id`, `sessionId`, `session_token`, `cookie` (if contains auth)

**Evidence Required**:
- File path + line number of log statement
- Variable name being logged
- Log level (debug, info, warn, error)
- Logging framework (logger, console.log, log.Printf, etc.)

---

## WARNING: Suspected Sensitive Data (Not Confirmed)

### Contextual Suspicion
Flag as **Warning** when:

1. **Variable name suggests sensitive data** + **logged at debug/trace level**:
```python
# WARNING: Suspicious - debug logging of auth-related variable
logger.debug(f"Auth header: {auth_header}")
log.Debug("Credentials object: %+v", creds)
console.debug("User object:", user);  // May contain password field
```

2. **Base64-encoded strings** being logged (may be credentials):
```python
# WARNING: Suspicious - base64 string near auth context
logger.info(f"Encoded token: {base64_string}")
```

3. **Full request/response bodies** logged (may contain secrets):
```python
# WARNING: Full body logged, may contain sensitive fields
logger.debug(f"Request body: {request.body}")
log.Info("Response: %s", json.dumps(response))
```

4. **Error messages with full exception** (may leak connection strings, file paths with keys):
```python
# WARNING: Full exception may contain sensitive context
logger.error(f"Database error: {e}")  // May contain connection string
except Exception as e:
    log.Error("Failed: %v", e)  // May contain secrets in error message
```

5. **Logging user input without sanitization**:
```python
# WARNING: User input logged verbatim - may be crafted to include secrets
logger.info(f"User entered: {user_input}")
log.Printf("Query param: %s", request.args.get('data'))
```

### Recommendation for Warnings
```
### Warning: Potential Sensitive Data in Logs

**Evidence**: `src/auth/login.py:45`
```python
logger.debug(f"Auth header: {auth_header}")
```

**Risk**: Debug logs may be enabled in production. `auth_header` likely contains Bearer token or Basic auth credentials.

**Cannot Confirm**: Variable value not visible in static analysis.

**Remediation**:
1. If `auth_header` contains credentials, NEVER log it
2. If needed for debugging, log only sanitized version:
```python
# Sanitize before logging
sanitized = auth_header.split()[0] if auth_header else "None"  # Log only "Bearer" or "Basic"
logger.debug(f"Auth type: {sanitized}")
```
3. Ensure debug logs are disabled in production
```

---

## Personally Identifiable Information (PII)

### CRITICAL: Confirmed PII
Flag as **Critical** if log clearly contains:

**Social Security Numbers (SSN)**:
```python
# CRITICAL
logger.info(f"SSN: {ssn}")
```
Pattern: Variable name contains `ssn`, `social_security`, `tax_id`

**Credit Card Numbers**:
```python
# CRITICAL
logger.debug(f"Card number: {card_number}")
log.Info("CC: " + credit_card)
```
Pattern: Variable name contains `card`, `credit_card`, `cc_number`, `pan`

**Email Addresses in Auth Context**:
```python
# CRITICAL (if with password)
logger.info(f"Login attempt: {email} with password {password}")
```

**Medical Records / Health Data**:
```python
# CRITICAL (HIPAA violation)
logger.info(f"Patient record: {medical_record}")
```
Pattern: Variable name contains `medical`, `diagnosis`, `prescription`, `health_record`

### WARNING: Suspected PII
Flag as **Warning** for:

**Email Addresses** (informational, but context-dependent):
```python
# WARNING: Email logged - acceptable for audit trails, but check context
logger.info(f"User {email} logged in")
```

**Full Names**:
```python
# WARNING: PII - only log if required for audit
logger.debug(f"Processing request for {first_name} {last_name}")
```

**IP Addresses** (PII under GDPR in some contexts):
```python
# WARNING: IP address - ensure compliance with privacy policy
logger.info(f"Request from IP: {ip_address}")
```

**Phone Numbers**:
```python
# WARNING: PII
logger.debug(f"Phone: {phone_number}")
```

**Addresses** (physical):
```python
# WARNING: PII
logger.info(f"Shipping to: {street_address}, {city}, {zip_code}")
```

---

## Financial Data (CRITICAL)

**Bank Account Numbers**:
```python
# CRITICAL
logger.info(f"Account: {account_number}")
```
Pattern: `account`, `bank_account`, `iban`, `routing_number`

**CVV / Security Codes**:
```python
# CRITICAL (PCI-DSS violation)
logger.debug(f"CVV: {cvv}")
```

**Transaction IDs** (WARNING if with amounts):
```python
# WARNING: Full transaction details
logger.info(f"Transaction {txn_id}: ${amount} from account {account}")
```

---

## Language-Specific Detection Patterns

### Python
```python
# Log statement patterns to search
logging.debug(...)
logging.info(...)
logger.debug(...)
logger.info(...)
logger.warn(...)
logger.error(...)
print(...)  # May go to stdout/logs in production
sys.stderr.write(...)

# Format variations
f"... {sensitive_var} ..."
"... %s ..." % sensitive_var
"... {}".format(sensitive_var)
```

### Go
```go
// Log statement patterns
log.Debug(...)
log.Info(...)
log.Printf(...)
log.Println(...)
logrus.WithFields(...).Info(...)
fmt.Printf(...)  // May go to logs if redirected

// Format variations
"... %s ...", sensitiveVar
"... " + sensitiveVar
fmt.Sprintf("... %v ...", sensitiveVar)
```

### JavaScript/TypeScript
```javascript
// Log statement patterns
console.log(...)
console.debug(...)
console.info(...)
console.warn(...)
console.error(...)
logger.debug(...)
logger.info(...)
winston.info(...)
pino.info(...)

// Format variations
`... ${sensitiveVar} ...`
"... " + sensitiveVar
```

### Java
```java
// Log statement patterns
logger.debug(...)
logger.info(...)
log.debug(...)
System.out.println(...)  // May go to logs
LOG.error(...)

// Format variations
String.format("... %s ...", sensitiveVar)
"... " + sensitiveVar
```

### C/C++
```c
// Log statement patterns
printf(...)
fprintf(stderr, ...)
syslog(...)
std::cout << ...

// Format variations
printf("... %s ...", sensitive_var)
fprintf(stderr, "... %s\n", password)
```

---

## Sanitization Patterns (Good Examples)

### Password Redaction
```python
# GOOD: Never log password at all
logger.info(f"Login attempt for user: {username}")  # No password

# ACCEPTABLE: Partial redaction if debugging needed (not recommended)
logger.debug(f"Password length: {len(password)}")
```

### Token Redaction
```python
# GOOD: Log only token prefix for correlation
token_prefix = token[:8] + "..." if len(token) > 8 else "***"
logger.info(f"Using token: {token_prefix}")

# GOOD: Hash the token for correlation
import hashlib
token_hash = hashlib.sha256(token.encode()).hexdigest()[:8]
logger.info(f"Token hash: {token_hash}")
```

### PII Masking
```python
# GOOD: Mask email
masked_email = email.split('@')[0][:3] + "***@" + email.split('@')[1]
logger.info(f"User: {masked_email}")

# GOOD: Mask credit card
masked_cc = "****-****-****-" + card_number[-4:]
logger.debug(f"Card ending: {masked_cc}")

# GOOD: Mask SSN
masked_ssn = "***-**-" + ssn[-4:]
```

### Request/Response Sanitization
```python
# GOOD: Sanitize sensitive fields before logging
def sanitize_request(data):
    sensitive_fields = ['password', 'token', 'api_key', 'ssn', 'credit_card']
    sanitized = data.copy()
    for field in sensitive_fields:
        if field in sanitized:
            sanitized[field] = "***REDACTED***"
    return sanitized

logger.debug(f"Request: {sanitize_request(request_data)}")
```

---

## Detection Methodology

### Static Analysis Steps
1. **Find all log statements** in codebase (use patterns above)
2. **Extract arguments** to log statements
3. **Check for sensitive variable names** (password, token, key, ssn, etc.)
4. **Check for direct string literals** containing secrets (hardcoded keys)
5. **Analyze context**:
   - Is this in auth/login code? (Higher risk)
   - Is this debug vs info level? (Debug more likely to leak)
   - Is variable marked as sensitive in type/comment?

### Variable Name Heuristics
Flag variables with names containing (case-insensitive):
- **Auth**: password, passwd, pwd, secret, key, token, auth, credential, apikey
- **PII**: ssn, social_security, email, phone, address, name, dob, birth
- **Financial**: card, credit_card, cvv, account, bank, iban, routing
- **Health**: medical, health, diagnosis, patient, prescription

### Logging Framework Detection
Search for imports/usage:
- Python: `import logging`, `from loguru import logger`, `import structlog`
- Go: `log.`, `logrus.`, `zap.`, `zerolog.`
- JS: `console.`, `winston.`, `pino.`, `bunyan.`
- Java: `Logger`, `LoggerFactory`, `System.out`, `System.err`

---

## Compliance & Regulations

### PCI-DSS (Payment Card Industry)
**Requirement 3.4**: "Render PAN unreadable anywhere it is stored"
- **CRITICAL**: Never log full credit card numbers (PAN)
- **CRITICAL**: Never log CVV/CVC codes
- Even masked PANs must follow standards (show only last 4 digits)

### HIPAA (Health Insurance Portability and Accountability Act)
- **CRITICAL**: Never log Protected Health Information (PHI)
- Includes: medical records, diagnoses, prescriptions, patient names + medical context
- Logs are considered "data at rest" and must be secured

### GDPR (General Data Protection Regulation)
- **WARNING/CRITICAL**: Minimize logging of personal data
- Must have legal basis for logging PII
- Logs must be secured and have retention policies
- Right to erasure applies to logs

### SOC 2 / ISO 27001
- Logs must not contain credentials or keys
- Access to logs must be restricted
- Log tampering must be prevented (immutable logs)

---

## Report Template

### Critical Finding Example
```markdown
### Critical: Password Logged in Authentication Flow

**Evidence**: `src/auth/handlers/login.go:89`
```go
log.Printf("Login attempt with username: %s, password: %s", username, password)
```

**Impact**: User passwords logged to application logs, visible to:
- All operators with log access
- Centralized logging system (Datadog/Splunk)
- Log files on disk (may be backed up unencrypted)
- Potential attackers who gain read access to logs

**Severity**: Critical - Direct credential exposure

**Compliance Violations**:
- OWASP A02:2021 (Cryptographic Failures)
- CWE-532 (Insertion of Sensitive Information into Log File)
- Violates principle of least privilege for credential access

**Remediation**:
```go
// REMOVE password from logs entirely
log.Printf("Login attempt for username: %s", username)

// If debugging needed, log only metadata
log.Debug("Login attempt received for user: %s (password length: %d)", username, len(password))
```

**Additional Actions**:
1. Rotate credentials for all users (passwords compromised via logs)
2. Audit all existing logs for exposed credentials
3. Implement log sanitization library
4. Add pre-commit hook to detect credential logging
```

### Warning Finding Example
```markdown
### Warning: Suspected Sensitive Data in Debug Logs

**Evidence**: `src/api/middleware.py:34`
```python
logger.debug(f"Full request: {request.json}")
```

**Risk**: Debug logs may be enabled in production. Request body may contain:
- API keys in headers
- Passwords in login requests
- PII in user data

**Cannot Confirm**: Static analysis cannot determine if `request.json` contains sensitive fields.

**Severity**: Warning (potential exposure, context-dependent)

**Remediation**:
```python
# Sanitize before logging
sanitized = sanitize_request(request.json)
logger.debug(f"Request (sanitized): {sanitized}")

# Or use structured logging with explicit field control
logger.debug("Request received", extra={
    "method": request.method,
    "path": request.path,
    "content_length": len(request.data)
})
```

**Additional Actions**:
1. Ensure debug logs disabled in production
2. Implement request sanitization function
3. Review all debug log statements for sensitive data
```

---

## Testing for Log Leaks

### Audit Checklist
- [ ] Search codebase for all log statements
- [ ] Identify variables with sensitive names being logged
- [ ] Check log levels (debug more risky than info)
- [ ] Review error handling (exceptions may contain secrets)
- [ ] Check if logs are encrypted at rest
- [ ] Verify log retention and deletion policies
- [ ] Confirm debug logs disabled in production
- [ ] Test log sanitization functions

### Automated Detection
```bash
# Grep for password logging (example)
git grep -n "log.*password" --and --not -e "password_hash" --not -e "password_length"

# Find API key logging
git grep -n "log.*api_key\|log.*apiKey\|log.*API_KEY"

# Find token logging
git grep -n "log.*token" --and --not -e "token_type" --not -e "csrf_token"
```

### Runtime Testing
```python
# Test log sanitization
def test_password_not_logged():
    with mock.patch('logging.Logger.info') as mock_log:
        authenticate(username="user", password="secret123")
        # Assert password not in any log call
        for call in mock_log.call_args_list:
            assert "secret123" not in str(call)
```

---

## Exceptions & Special Cases

### Acceptable Logging (with documentation)
1. **Audit trails**: Username, timestamp, action (no passwords)
2. **Security events**: Failed login attempts (username only, not password)
3. **Transaction IDs**: For correlation (no amounts or account details)
4. **Hashed/encrypted values**: If properly done and documented
5. **Anonymized data**: After proper anonymization (not just pseudonymization)

### Development vs Production
- **Dev/test**: More verbose logging acceptable (but still no hardcoded secrets)
- **Production**: Minimal logging, sanitize all user data, disable debug logs
- **Configuration**: Use environment variables to control log levels

### Performance Logging
- **Acceptable**: Request count, latency, error rates
- **Not acceptable**: Full request/response bodies without sanitization
