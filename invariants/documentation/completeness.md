# Documentation Completeness & Quality Invariants (v1)

## Overview

This invariant checks for missing or incomplete documentation in software projects. Well-documented code reduces security risks by ensuring correct usage, preventing misconfigurations, and enabling security reviews.

**CRITICAL**: Undocumented security-critical functionality can lead to misuse and vulnerabilities.

---

## CRITICAL: Missing Documentation for Security-Critical Components

### Security-Critical Components Requiring Documentation

**Flag as CRITICAL** if any of the following lack documentation:

1. **Authentication/Authorization systems**
   - Login/logout flows
   - Session management
   - Permission checks
   - OAuth/SAML implementations

2. **Cryptographic operations**
   - Key generation
   - Encryption/decryption
   - Signing/verification
   - Random number generation

3. **Input validation/sanitization**
   - User input handling
   - File upload processing
   - API parameter validation

4. **Security configurations**
   - CORS policies
   - CSP (Content Security Policy)
   - Rate limiting
   - Firewall rules

5. **Privileged operations**
   - Database migrations
   - Admin functions
   - System calls
   - File system access

### Detection Patterns

```python
# CRITICAL: Security-critical function without docstring
def authenticate_user(username, password):
    # No documentation explaining:
    # - What authentication method is used
    # - What happens on failure
    # - Whether it's vulnerable to timing attacks
    hash_stored = db.get_password_hash(username)
    return hash_password(password) == hash_stored
```

**Fix**:
```python
# GOOD: Documented security-critical function
def authenticate_user(username: str, password: str) -> bool:
    """
    Authenticate user credentials using constant-time comparison.

    Args:
        username: User identifier (case-sensitive)
        password: Plaintext password (will be hashed)

    Returns:
        True if credentials are valid, False otherwise

    Security:
        - Uses bcrypt for password hashing
        - Constant-time comparison prevents timing attacks
        - Rate-limited to 5 attempts per minute per IP
        - Logs failed attempts for monitoring

    Example:
        >>> authenticate_user("alice", "correct_password")
        True
        >>> authenticate_user("alice", "wrong_password")
        False
    """
    hash_stored = db.get_password_hash(username)
    return hmac.compare_digest(hash_password(password), hash_stored)
```

---

## HIGH: Missing API Documentation

### REST API Endpoints

**Flag as HIGH** if API endpoints lack documentation:

**Undocumented endpoint**:
```python
# HIGH: No documentation
@app.route('/api/delete_user', methods=['POST'])
def delete_user():
    user_id = request.json.get('id')
    db.delete(User, id=user_id)
    return {'status': 'ok'}
```

**Required documentation**:
```python
# GOOD: Complete API documentation
@app.route('/api/delete_user', methods=['POST'])
def delete_user():
    """
    Delete a user account (admin only).

    Request:
        POST /api/delete_user
        Content-Type: application/json
        Authorization: Bearer <admin_token>

        Body:
        {
            "id": "user_uuid"
        }

    Response:
        200 OK: {"status": "ok", "deleted_id": "user_uuid"}
        401 Unauthorized: {"error": "Admin access required"}
        404 Not Found: {"error": "User not found"}

    Security:
        - Requires admin role (checked via @require_admin decorator)
        - Logs deletion with admin user ID and timestamp
        - Cascade deletes user data per GDPR requirements
        - Cannot delete own account (returns 403)

    Example:
        $ curl -X POST https://api.example.com/api/delete_user \
               -H "Authorization: Bearer admin_token" \
               -H "Content-Type: application/json" \
               -d '{"id": "user123"}'
    """
    # Implementation...
```

### GraphQL/gRPC APIs

**Flag as HIGH** if schema lacks descriptions:

```graphql
# HIGH: No description
type Mutation {
  deleteUser(id: ID!): User
}
```

**GOOD**:
```graphql
# GOOD: Documented schema
type Mutation {
  """
  Delete a user account (admin only).

  Requires admin role. Logs deletion event.
  Returns null if user not found.

  Example:
    mutation {
      deleteUser(id: "user123") { id }
    }
  """
  deleteUser(
    "User ID to delete"
    id: ID!
  ): User
}
```

---

## MEDIUM: Missing Command-Line Documentation

### CLI Commands Without Man Pages or --help

**Flag as MEDIUM** if CLI commands lack documentation:

**Detection pattern**:
```bash
# Check for CLI executables without man pages
find bin/ -type f -executable | while read cmd; do
  cmd_name=$(basename "$cmd")
  if ! man "$cmd_name" 2>/dev/null && ! "$cmd" --help 2>/dev/null; then
    echo "MEDIUM: $cmd lacks man page and --help"
  fi
done
```

**Required elements for CLI documentation**:

1. **--help flag** (REQUIRED)
2. **Man page** (RECOMMENDED for installed tools)
3. **Examples section** (REQUIRED)
4. **Exit codes** (REQUIRED if non-zero exits used)

**Example man page template** (`docs/man/sca.1`):
```
.TH SCA 1 "2024-01-15" "SCA 1.0" "Security Control Agent Manual"
.SH NAME
sca \- Security Control Agent for invariant-driven auditing
.SH SYNOPSIS
.B sca
.RI [ OPTIONS ]
.I COMMAND
.RI [ ARGS ]
.SH DESCRIPTION
.B sca
performs read-only security audits using predefined invariants.
.SH COMMANDS
.TP
.B audit
Run security audit on repository
.TP
.B scope
Print file scope for analysis
.TP
.B diff
Compare audit reports (drift analysis)
.TP
.B bootstrap
Initialize sec-ctrl/ directory
.SH OPTIONS
.TP
.BR \-h ", " \-\-help
Show help message
.TP
.BR \-\-repo " " \fIPATH\fR
Repository path (default: current directory)
.TP
.BR \-\-ctrl-dir " " \fIPATH\fR
Control directory (default: sec-ctrl/)
.SH EXAMPLES
.PP
Run audit on current directory:
.PP
.nf
.RS
sca audit
.RE
.fi
.PP
Bootstrap control directory:
.PP
.nf
.RS
sca bootstrap
.RE
.fi
.SH EXIT STATUS
.TP
.B 0
No critical/high findings
.TP
.B 2
Critical/high findings exist (fail CI)
.TP
.B 3
Incomplete audit (configuration error)
.TP
.B 4
Agent not immutable (security violation)
.SH SEE ALSO
.BR sca\-audit (1),
.BR sca\-bootstrap (1)
.SH BUGS
Report bugs at https://github.com/your-org/sca/issues
```

---

## MEDIUM: Missing Configuration File Documentation

### Configuration Files Without Schema/Examples

**Flag as MEDIUM** if config files lack documentation:

**Undocumented config**:
```yaml
# config/security.yml (NO COMMENTS)
auth:
  method: jwt
  secret: ENV[JWT_SECRET]
  expiry: 3600
rate_limit:
  enabled: true
  max_requests: 100
```

**GOOD: Documented config**:
```yaml
# config/security.yml
# Security configuration for production deployment

auth:
  # Authentication method: jwt, oauth2, saml
  method: jwt

  # JWT secret key (MUST be set via environment variable)
  # Generate with: openssl rand -base64 32
  secret: ENV[JWT_SECRET]

  # Token expiry in seconds (default: 1 hour)
  # Security: Shorter expiry reduces token theft risk
  expiry: 3600

rate_limit:
  # Enable rate limiting (REQUIRED for production)
  enabled: true

  # Maximum requests per minute per IP
  # Adjust based on legitimate traffic patterns
  max_requests: 100
```

**Also require**:
- `config/security.yml.example` - Example with safe defaults
- `docs/configuration.md` - Full config reference

---

## MEDIUM: Missing Environment Variable Documentation

### Environment Variables Without .env.example

**Flag as MEDIUM** if code uses environment variables without documentation:

**Detection pattern**:
```python
# MEDIUM: Undocumented environment variable
secret_key = os.environ['SECRET_KEY']  # What format? How to generate?
database_url = os.getenv('DATABASE_URL')  # Required or optional?
```

**Required**: `.env.example` file:
```bash
# .env.example - Copy to .env and fill in values

# SECRET_KEY: Application secret for session signing (REQUIRED)
# Generate with: openssl rand -hex 32
# Security: NEVER commit actual value to git
SECRET_KEY=your_secret_key_here

# DATABASE_URL: PostgreSQL connection string (REQUIRED)
# Format: postgresql://user:password@host:port/database?sslmode=require
# Security: MUST use SSL in production (sslmode=require)
DATABASE_URL=postgresql://user:password@localhost:5432/mydb?sslmode=require

# LOG_LEVEL: Logging verbosity (OPTIONAL, default: INFO)
# Values: DEBUG, INFO, WARNING, ERROR
# Security: Use INFO or WARNING in production (avoid DEBUG)
LOG_LEVEL=INFO
```

---

## LOW: Missing README or Architecture Documentation

### Repository Without README.md

**Flag as LOW** if repository lacks:
- README.md in root directory
- Architecture/design documentation
- Security model documentation

**Required README sections**:
```markdown
# Project Name

Brief description (1-2 sentences)

## Features
- Feature 1
- Feature 2

## Installation

### Prerequisites
- Requirement 1
- Requirement 2

### Install Steps
\`\`\`bash
# Step-by-step installation
\`\`\`

## Usage

### Basic Example
\`\`\`bash
# Simple usage example
\`\`\`

### Advanced Examples
\`\`\`bash
# Complex scenarios
\`\`\`

## Configuration
See [Configuration Guide](docs/configuration.md)

## Security
- Authentication: [method]
- Authorization: [RBAC/ABAC/etc]
- Encryption: [TLS 1.2+, AES-256, etc]
- See [Security Architecture](docs/security.md) for details

## Development

### Running Tests
\`\`\`bash
make test
\`\`\`

### Building
\`\`\`bash
make build
\`\`\`

## Contributing
See [CONTRIBUTING.md](CONTRIBUTING.md)

## License
[License Type] - See [LICENSE](LICENSE)

## Support
- Issues: https://github.com/org/project/issues
- Docs: https://docs.example.com
- Security: security@example.com
```

---

## Detection Queries

### Find Undocumented Python Functions

```bash
# Find Python functions without docstrings
git grep -n "^def " --and --not -e '"""' --and --not -e "'''" *.py
```

### Find Undocumented API Endpoints

```bash
# Flask/FastAPI
git grep -n "@app.route\|@router.get\|@router.post" | while read line; do
  file=$(echo "$line" | cut -d: -f1)
  lineno=$(echo "$line" | cut -d: -f2)
  # Check if next 10 lines have docstring
  if ! sed -n "${lineno},$((lineno+10))p" "$file" | grep -q '"""'; then
    echo "MEDIUM: Undocumented endpoint in $file:$lineno"
  fi
done
```

### Find CLI Commands Without --help

```bash
# Check all executables for --help support
find bin/ -type f -executable | while read cmd; do
  if ! "$cmd" --help &>/dev/null; then
    echo "MEDIUM: $cmd does not support --help"
  fi
done
```

### Find Config Files Without Examples

```bash
# Check for config files without .example counterpart
find config/ -name "*.yml" -o -name "*.yaml" -o -name "*.json" | while read cfg; do
  if [ ! -f "${cfg}.example" ]; then
    echo "MEDIUM: Missing ${cfg}.example"
  fi
done
```

---

## Documentation Quality Checklist

For each security-critical component, verify:

- [ ] **Function/class docstring** with description, args, returns, raises
- [ ] **Security notes** section in docstring
- [ ] **Examples** showing correct usage
- [ ] **API documentation** (if applicable)
- [ ] **Configuration schema** with descriptions and examples
- [ ] **Environment variables** documented in .env.example
- [ ] **Man pages** for CLI tools
- [ ] **Exit codes** documented
- [ ] **Error messages** documented
- [ ] **Architecture diagram** showing security boundaries

---

## Automated Documentation Generation

### Enforce Docstring Requirements

**Python** (using pydocstyle):
```bash
# .pydocstyle
[pydocstyle]
convention = google
match = (?!test_).*\.py
match_dir = (?!tests)[^\.].*

# CI check
pydocstyle src/
```

**Fail build** if critical functions lack docstrings:
```python
# conftest.py or pre-commit hook
import ast
import sys

def check_security_functions_have_docs(file_path):
    """Enforce docstrings on security-critical functions"""
    security_keywords = ['auth', 'crypto', 'password', 'token', 'validate', 'sanitize']

    with open(file_path) as f:
        tree = ast.parse(f.read())

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            func_name = node.name.lower()
            if any(kw in func_name for kw in security_keywords):
                if not ast.get_docstring(node):
                    print(f"CRITICAL: {file_path}:{node.lineno} - "
                          f"Security function '{node.name}' lacks docstring")
                    return False
    return True
```

### Generate API Documentation

**OpenAPI/Swagger**:
```python
# FastAPI auto-generates OpenAPI spec
from fastapi import FastAPI

app = FastAPI(
    title="My API",
    description="Complete API documentation",
    version="1.0.0",
)

@app.post("/users", summary="Create a new user")
def create_user(user: UserCreate):
    """
    Create a new user account.

    - **username**: Unique identifier (3-20 chars, alphanumeric)
    - **email**: Valid email address
    - **password**: Min 12 chars, must include uppercase, number, symbol

    Returns the created user with generated UUID.
    """
    ...
```

### Generate Man Pages from Argparse

```python
# Use argparse-manpage
import argparse
from argparse_manpage import get_manpage

parser = argparse.ArgumentParser(
    prog='sca',
    description='Security Control Agent for invariant-driven auditing'
)
# ... add arguments ...

# Generate man page
with open('docs/man/sca.1', 'w') as f:
    f.write(get_manpage(parser))
```

---

## Compliance Requirements

### PCI-DSS
- Document all system components and data flows
- Maintain network diagrams
- Document security policies

### HIPAA
- Document PHI handling procedures
- Maintain audit trail documentation
- Document encryption methods

### SOC 2
- Document system architecture
- Security controls documentation
- Incident response procedures

### GDPR
- Document data processing activities
- Privacy policy and data retention
- Data subject rights procedures

---

## Reporting Template

```markdown
### Medium: Missing Documentation for Security Function

**Evidence**: `src/auth/oauth.py:45`
```python
def validate_oauth_token(token):
    # No docstring
    decoded = jwt.decode(token, SECRET_KEY)
    return decoded['user_id']
```

**Risk**:
- Unclear token validation logic
- No documentation of required claims
- Missing security properties (expiry check, signature validation)
- Developers may misuse function

**Severity**: Medium - Undocumented security-critical function

**Remediation**:
Add comprehensive docstring with security properties:
```python
def validate_oauth_token(token: str) -> str:
    """
    Validate OAuth 2.0 JWT access token.

    Args:
        token: Bearer token from Authorization header

    Returns:
        User ID extracted from token claims

    Raises:
        JWTExpiredError: If token has expired
        JWTInvalidSignatureError: If signature validation fails
        InvalidTokenError: If token is malformed or missing required claims

    Security:
        - Verifies HMAC-SHA256 signature using SECRET_KEY
        - Checks expiration time (exp claim)
        - Requires 'user_id' claim
        - Validates issuer matches expected value
        - Constant-time signature comparison

    Example:
        >>> token = "eyJ0eXAiOiJKV1QiLCJhbGc..."
        >>> user_id = validate_oauth_token(token)
        >>> print(user_id)
        "user_12345"
    """
    try:
        decoded = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=['HS256'],
            options={'verify_exp': True}
        )
        return decoded['user_id']
    except jwt.ExpiredSignatureError:
        raise JWTExpiredError("Token has expired")
    except jwt.InvalidSignatureError:
        raise JWTInvalidSignatureError("Invalid token signature")
```
```
```

---

## Summary

**Documentation is a security control**. Missing documentation for security-critical code:
- Increases likelihood of misuse
- Prevents effective security reviews
- Makes incident response harder
- Violates compliance requirements (PCI-DSS, HIPAA, SOC 2, GDPR)

**Required documentation**:
1. Security-critical functions → CRITICAL
2. API endpoints → HIGH
3. CLI commands and man pages → MEDIUM
4. Configuration files and schemas → MEDIUM
5. Environment variables → MEDIUM
6. README and architecture → LOW

**Automated enforcement**:
- Pre-commit hooks for docstring requirements
- CI checks for missing documentation
- Auto-generation from code (OpenAPI, man pages)
- Documentation coverage metrics
