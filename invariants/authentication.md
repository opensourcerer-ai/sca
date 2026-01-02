# Authentication and Identity Management Security Invariants (v1)

## Overview

This file defines security invariants for authentication, credential management, and identity verification aligned with:
- **NIST SP 800-53 Rev 5**: IA (Identification and Authentication) family
- **NIST SP 800-63-3**: Digital Identity Guidelines (AAL1/AAL2/AAL3)
- **NIST SP 800-171**: Requirements 3.5.x (Identification and Authentication)
- **OWASP**: A07:2021 (Identification and Authentication Failures)
- **PCI-DSS**: Requirement 8.x (Identify and authenticate access)

---

## CRITICAL: Hard-coded Credentials (CWE-798, NIST IA-5)

**Standard**: CWE-798, OWASP A07:2021, NIST SP 800-53 IA-5(1), PCI-DSS 8.3.1

**Finding**: Hard-coded passwords, API keys, tokens in source code

**Detection Patterns**:

### Python
```python
# CRITICAL: Hard-coded password
password = "Admin123!"
db_password = "p@ssw0rd"
credentials = {"username": "admin", "password": "secret123"}

# CRITICAL: Hard-coded API key
api_key = "sk_live_51H..."
API_KEY = "AIzaSyD..."

# CRITICAL: Hard-coded token
jwt_secret = "my-secret-key"
oauth_token = "ghp_abc123..."
```

### JavaScript/TypeScript
```javascript
// CRITICAL: Hard-coded credentials
const password = 'Admin123!';
const dbConfig = {
  password: 'mysql_password',
  apiKey: 'sk_test_...'
};

// CRITICAL: JWT secret
const JWT_SECRET = 'hardcoded-secret';
```

### Java
```java
// CRITICAL: Hard-coded password
String password = "Admin123!";
String dbPassword = "p@ssw0rd";

// CRITICAL: Hard-coded API key
private static final String API_KEY = "AIzaSyD...";
```

### Go
```go
// CRITICAL: Hard-coded credentials
const password = "Admin123!"
dbPassword := "p@ssw0rd"

// CRITICAL: API key
apiKey := "sk_live_..."
```

**Remediation**:
```python
# GOOD: Environment variables
import os
password = os.environ.get('DB_PASSWORD')
api_key = os.environ.get('API_KEY')

# GOOD: Secret management service
from vault import VaultClient
vault = VaultClient()
password = vault.get_secret('database/password')
```

**NIST Controls**: IA-5(1) - Password-based authentication, IA-5(7) - No embedded unencrypted static authenticators

---

## CRITICAL: Weak Password Requirements (CWE-521, NIST IA-5, AAL1)

**Standard**: CWE-521, SCA-011, NIST SP 800-63B AAL1, NIST SP 800-53 IA-5(1), PCI-DSS 8.3.6

**Finding**: Password policies that don't meet minimum security requirements

**Detection Patterns**:

### Python
```python
# CRITICAL: No minimum length
if len(password) < 6:  # Too short, minimum should be 8+

# CRITICAL: No complexity requirements
def validate_password(password):
    return len(password) >= 8  # Missing: uppercase, lowercase, digits, special chars

# CRITICAL: Common password allowed
allowed_passwords = ['password', '123456', 'admin']  # Known weak passwords
```

### JavaScript
```javascript
// CRITICAL: Weak password regex
const passwordRegex = /^.{6,}$/;  // Only length, no complexity

// CRITICAL: No password strength check
function isValidPassword(password) {
  return password.length >= 6;  // Too weak
}
```

**NIST SP 800-63B Requirements (AAL1 Minimum)**:
- ✅ Minimum 8 characters (12+ recommended)
- ✅ Check against common password lists
- ✅ Check for context-specific words (username, service name)
- ✅ No composition rules required (complexity can reduce entropy)
- ✅ Allow all printable ASCII characters + spaces
- ✅ Support Unicode characters
- ❌ No periodic password change requirements (NIST discourages this)

**Remediation**:
```python
# GOOD: NIST-compliant password validation
import re
from zxcvbn import zxcvbn  # Password strength estimator

def validate_password_nist_compliant(password, username, service_name):
    """NIST SP 800-63B compliant password validation"""
    
    # Minimum length
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    
    # Check against common passwords (top 10k)
    if password.lower() in load_common_passwords():
        return False, "Password is too common"
    
    # Check for username in password
    if username.lower() in password.lower():
        return False, "Password cannot contain username"
    
    # Check for service name in password
    if service_name.lower() in password.lower():
        return False, "Password cannot contain service name"
    
    # Use zxcvbn for entropy estimation
    strength = zxcvbn(password, user_inputs=[username, service_name])
    if strength['score'] < 3:  # 0-4 scale, 3 = strong
        return False, f"Password is too weak: {strength['feedback']['warning']}"
    
    return True, "Password meets requirements"
```

**NIST Controls**: IA-5(1)(a) - Minimum password complexity

---

## CRITICAL: Insecure Password Storage (CWE-759, CWE-327, NIST IA-5)

**Standard**: CWE-759, CWE-327, OWASP A02:2021, NIST SP 800-53 IA-5(1)(c), PCI-DSS 8.3.2

**Finding**: Passwords stored in plaintext or with weak hashing

**Detection Patterns**:

### Plaintext Storage
```python
# CRITICAL: Plaintext password storage
user.password = request.form['password']  # No hashing
db.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
           (username, password))  # Storing plaintext

# CRITICAL: Reversible encryption
encrypted_password = aes_encrypt(password, key)  # Encryption is not hashing
```

### Weak Hashing Algorithms
```python
# CRITICAL: MD5 for passwords
import hashlib
password_hash = hashlib.md5(password.encode()).hexdigest()

# CRITICAL: SHA-1 for passwords
password_hash = hashlib.sha1(password.encode()).hexdigest()

# CRITICAL: SHA-256 without salt
password_hash = hashlib.sha256(password.encode()).hexdigest()  # No salt, vulnerable to rainbow tables

# CRITICAL: SHA-256 with static salt
password_hash = hashlib.sha256((password + "static_salt").encode()).hexdigest()  # Static salt
```

### Java
```java
// CRITICAL: MD5 for passwords
MessageDigest md = MessageDigest.getInstance("MD5");
byte[] hash = md.digest(password.getBytes());

// CRITICAL: SHA-256 without salt
MessageDigest sha = MessageDigest.getInstance("SHA-256");
byte[] hash = sha.digest(password.getBytes());
```

**NIST-Approved Password Hashing** (FIPS 140-2 compliant):
- ✅ **PBKDF2** (NIST SP 800-132) - Minimum 10,000 iterations (100,000+ recommended)
- ✅ **bcrypt** - Cost factor ≥ 12 (industry standard)
- ✅ **scrypt** - High memory cost
- ✅ **Argon2id** - Winner of Password Hashing Competition, best choice

**Remediation**:

### Python (PBKDF2 - NIST approved)
```python
# GOOD: PBKDF2 with random salt
import hashlib
import os

def hash_password_pbkdf2(password: str) -> tuple:
    """NIST SP 800-132 compliant password hashing"""
    salt = os.urandom(32)  # 256-bit random salt
    iterations = 100000  # NIST recommends minimum 10,000
    hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations)
    return salt, hash, iterations

def verify_password_pbkdf2(password: str, stored_salt: bytes, stored_hash: bytes, iterations: int) -> bool:
    hash = hashlib.pbkdf2_hmac('sha256', password.encode(), stored_salt, iterations)
    return hash == stored_hash
```

### Python (bcrypt - industry standard)
```python
# GOOD: bcrypt
import bcrypt

def hash_password_bcrypt(password: str) -> bytes:
    """bcrypt with cost factor 12"""
    salt = bcrypt.gensalt(rounds=12)  # Cost factor, 12 is good balance
    return bcrypt.hashpw(password.encode(), salt)

def verify_password_bcrypt(password: str, stored_hash: bytes) -> bool:
    return bcrypt.checkpw(password.encode(), stored_hash)
```

### Python (Argon2id - best practice)
```python
# BEST: Argon2id
from argon2 import PasswordHasher

ph = PasswordHasher(
    time_cost=2,       # Number of iterations
    memory_cost=65536, # 64 MiB
    parallelism=4,     # Number of threads
    hash_len=32,       # 256-bit output
    salt_len=16        # 128-bit salt
)

def hash_password_argon2(password: str) -> str:
    """Argon2id - winner of PHC, OWASP recommended"""
    return ph.hash(password)

def verify_password_argon2(password: str, stored_hash: str) -> bool:
    try:
        ph.verify(stored_hash, password)
        return True
    except:
        return False
```

**NIST Controls**: IA-5(1)(c) - Store and transmit only cryptographically-protected passwords

---

## HIGH: Missing Multi-Factor Authentication (SCA-012, NIST AAL2)

**Standard**: SCA-012, NIST SP 800-63B AAL2, NIST SP 800-53 IA-2(1), PCI-DSS 8.3

**Finding**: Privileged operations or sensitive data access without MFA

**Detection Patterns**:

### Python
```python
# HIGH: Admin access without MFA
@app.route('/admin')
def admin_panel():
    if current_user.is_authenticated:  # Only password, no MFA
        return render_template('admin.html')

# HIGH: Financial transaction without MFA
def transfer_funds(from_account, to_account, amount):
    if current_user.is_authenticated:  # Only single factor
        execute_transfer(from_account, to_account, amount)
```

### JavaScript
```javascript
// HIGH: Privileged endpoint without MFA
app.post('/api/admin/delete-user', requireAuth, (req, res) => {
  // Only checks session cookie, no MFA
  User.delete(req.body.userId);
});
```

**NIST AAL2 Requirements**:
- 🔐 Two distinct authentication factors
- ✅ Approved authenticators: Memorized secret + (OTP device OR cryptographic software OR cryptographic hardware)
- ✅ Verifier impersonation resistance (e.g., no SMS OTP alone for AAL2)

**Remediation**:
```python
# GOOD: Require MFA for sensitive operations
from functools import wraps

def require_mfa(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            abort(401)
        
        # Check if user has verified MFA this session
        if not session.get('mfa_verified'):
            return redirect(url_for('verify_mfa', next=request.url))
        
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin')
@require_mfa
def admin_panel():
    return render_template('admin.html')

# MFA verification endpoint
@app.route('/verify-mfa', methods=['GET', 'POST'])
def verify_mfa():
    if request.method == 'POST':
        totp_code = request.form['totp_code']
        
        # Verify TOTP code
        totp = pyotp.TOTP(current_user.mfa_secret)
        if totp.verify(totp_code, valid_window=1):
            session['mfa_verified'] = True
            session.permanent = True
            app.permanent_session_lifetime = timedelta(hours=1)
            return redirect(request.args.get('next') or url_for('index'))
        
        flash('Invalid MFA code')
    
    return render_template('verify_mfa.html')
```

**NIST Controls**: IA-2(1) - Multi-factor authentication for network access to privileged accounts

---

## HIGH: Insecure Session Management (CWE-384, NIST AC-11, AC-12)

**Standard**: CWE-384, OWASP A07:2021, NIST SP 800-53 AC-11, AC-12, PCI-DSS 8.2.8

**Finding**: Session tokens with insufficient entropy, no expiration, or predictable

**Detection Patterns**:

### Python (Flask)
```python
# HIGH: Predictable session token
session['user_id'] = user.id  # Flask generates secure tokens by default, but check SECRET_KEY

# CRITICAL: Weak secret key
app.secret_key = 'dev'  # Predictable
app.secret_key = '123456'  # Weak

# HIGH: No session timeout
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=365)  # Too long

# HIGH: Session fixation vulnerability
@app.route('/login', methods=['POST'])
def login():
    user = authenticate(request.form['username'], request.form['password'])
    if user:
        session['user_id'] = user.id  # Should regenerate session ID after login
```

### JavaScript (Express)
```javascript
// HIGH: Insecure session configuration
app.use(session({
  secret: 'keyboard cat',  // CRITICAL: Weak secret
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: false,  // HIGH: Should be true (HTTPS only)
    httpOnly: false,  // CRITICAL: Should be true (XSS protection)
    maxAge: 86400000 * 365  // HIGH: 1 year too long
  }
}));
```

### Java
```java
// HIGH: No session timeout
session.setMaxInactiveInterval(-1);  // Never expires

// CRITICAL: Insecure cookie
Cookie sessionCookie = new Cookie("JSESSIONID", sessionId);
sessionCookie.setSecure(false);  // Not HTTPS-only
sessionCookie.setHttpOnly(false);  // XSS vulnerable
```

**NIST Requirements**:
- **AC-11**: Session lock after 15 minutes of inactivity
- **AC-12**: Session termination after defined conditions
- **AC-12(1)**: User-initiated session logout

**Remediation**:

### Python (Flask) - Secure Configuration
```python
# GOOD: Secure session configuration
import secrets

# Generate strong secret key
app.secret_key = secrets.token_hex(32)  # 256-bit key

# Set session timeout
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)  # 1 hour timeout
app.config['SESSION_COOKIE_SECURE'] = True  # HTTPS only
app.config['SESSION_COOKIE_HTTPONLY'] = True  # No JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection

# Regenerate session ID on login (prevent session fixation)
@app.route('/login', methods=['POST'])
def login():
    user = authenticate(request.form['username'], request.form['password'])
    if user:
        # Regenerate session ID
        session.clear()
        session.regenerate()  # If using Flask-Session
        
        session['user_id'] = user.id
        session.permanent = True
        return redirect(url_for('index'))
```

### JavaScript (Express) - Secure Configuration
```javascript
// GOOD: Secure session configuration
const session = require('express-session');
const crypto = require('crypto');

app.use(session({
  secret: crypto.randomBytes(32).toString('hex'),  // Strong random secret
  resave: false,
  saveUninitialized: false,  // Don't create session until something stored
  cookie: {
    secure: true,  // HTTPS only
    httpOnly: true,  // XSS protection
    maxAge: 3600000,  // 1 hour
    sameSite: 'strict'  // CSRF protection
  },
  rolling: true  // Reset maxAge on every request (sliding window)
}));

// Regenerate session on login
app.post('/login', async (req, res) => {
  const user = await authenticate(req.body.username, req.body.password);
  if (user) {
    req.session.regenerate((err) => {
      if (err) return res.status(500).send('Session error');
      
      req.session.userId = user.id;
      res.redirect('/dashboard');
    });
  }
});
```

**NIST Controls**: AC-11 - Session lock, AC-12 - Session termination, SC-23 - Session authenticity

---

## MEDIUM: Missing Account Lockout (CWE-307, NIST AC-7)

**Standard**: CWE-307, SCA-013, NIST SP 800-53 AC-7, PCI-DSS 8.1.6

**Finding**: No protection against brute-force authentication attempts

**Detection Patterns**:

### Python
```python
# MEDIUM: No rate limiting or lockout
@app.route('/login', methods=['POST'])
def login():
    user = User.query.filter_by(username=request.form['username']).first()
    if user and user.check_password(request.form['password']):
        login_user(user)
        return redirect(url_for('index'))
    # No tracking of failed attempts
    flash('Invalid username or password')
    return redirect(url_for('login'))
```

**NIST AC-7 Requirements**:
- Enforce limit of **3-10 consecutive invalid login attempts** within **15 minutes**
- Lock account for **30 minutes** or until administrator unlocks
- Delay between login attempts (progressive delay recommended)

**Remediation**:
```python
# GOOD: Account lockout with NIST AC-7 compliance
from datetime import datetime, timedelta
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")  # Rate limiting
def login():
    username = request.form['username']
    password = request.form['password']
    
    user = User.query.filter_by(username=username).first()
    
    # Check if account is locked
    if user and user.is_locked():
        return jsonify({
            'error': 'Account locked due to multiple failed login attempts. Try again in 30 minutes.'
        }), 403
    
    # Authenticate
    if user and user.check_password(password):
        # Reset failed attempts on successful login
        user.failed_login_attempts = 0
        user.last_failed_login = None
        user.account_locked_until = None
        db.session.commit()
        
        login_user(user)
        return redirect(url_for('index'))
    
    # Record failed attempt
    if user:
        user.failed_login_attempts += 1
        user.last_failed_login = datetime.utcnow()
        
        # Lock account after 5 failed attempts
        if user.failed_login_attempts >= 5:
            user.account_locked_until = datetime.utcnow() + timedelta(minutes=30)
            db.session.commit()
            
            # Send notification to user
            send_security_alert(user.email, "Account locked due to multiple failed login attempts")
            
            return jsonify({
                'error': 'Account locked due to multiple failed login attempts.'
            }), 403
        
        db.session.commit()
    
    # Generic error message (don't reveal if username exists)
    flash('Invalid username or password')
    return redirect(url_for('login'))

# User model addition
class User(db.Model):
    # ... existing fields ...
    failed_login_attempts = db.Column(db.Integer, default=0)
    last_failed_login = db.Column(db.DateTime, nullable=True)
    account_locked_until = db.Column(db.DateTime, nullable=True)
    
    def is_locked(self):
        if self.account_locked_until is None:
            return False
        
        if datetime.utcnow() < self.account_locked_until:
            return True
        
        # Lock expired, reset
        self.failed_login_attempts = 0
        self.account_locked_until = None
        db.session.commit()
        return False
```

**NIST Controls**: AC-7 - Unsuccessful login attempts, AC-7(1) - Automatic account lock

---

## MEDIUM: Username Enumeration (CWE-203, SCA-014)

**Standard**: CWE-203, SCA-014, OWASP A07:2021

**Finding**: Different responses reveal whether username exists

**Detection Patterns**:

### Python
```python
# MEDIUM: Username enumeration via error messages
@app.route('/login', methods=['POST'])
def login():
    user = User.query.filter_by(username=request.form['username']).first()
    if not user:
        flash('Username does not exist')  # Reveals username doesn't exist
        return redirect(url_for('login'))
    
    if not user.check_password(request.form['password']):
        flash('Incorrect password')  # Reveals username exists
        return redirect(url_for('login'))

# MEDIUM: Username enumeration via timing
@app.route('/login', methods=['POST'])
def login():
    user = User.query.filter_by(username=request.form['username']).first()
    if not user:
        return redirect(url_for('login'))  # Fast return
    
    if user.check_password(request.form['password']):  # Slow bcrypt check
        login_user(user)
```

### Password Reset
```python
# MEDIUM: Enumeration via password reset
@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    email = request.form['email']
    user = User.query.filter_by(email=email).first()
    
    if user:
        send_reset_email(user.email)
        flash('Password reset email sent')
    else:
        flash('Email not found')  # Reveals email doesn't exist
```

**Remediation**:
```python
# GOOD: Constant-time checks, generic error messages
import hmac

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    user = User.query.filter_by(username=username).first()
    
    # Always perform hash check (even if user doesn't exist) to prevent timing attacks
    if user:
        password_valid = user.check_password(password)
    else:
        # Dummy hash check to match timing
        dummy_hash = bcrypt.hashpw(b'dummy', bcrypt.gensalt())
        bcrypt.checkpw(password.encode(), dummy_hash)
        password_valid = False
    
    if user and password_valid:
        login_user(user)
        return redirect(url_for('index'))
    
    # Generic error message
    flash('Invalid username or password')
    return redirect(url_for('login'))

# GOOD: Password reset without enumeration
@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    email = request.form['email']
    user = User.query.filter_by(email=email).first()
    
    # Always send reset email (even if user doesn't exist)
    if user:
        send_reset_email(user.email, user.generate_reset_token())
    
    # Generic success message (don't reveal if email exists)
    flash('If an account with that email exists, a password reset link has been sent.')
    return redirect(url_for('login'))
```

**NIST Controls**: IA-4 - Identifier management, IA-8 - Identification and authentication (non-organizational users)

---

## LOW: Insufficient Credential Rotation (SCA-015, NIST IA-5)

**Standard**: SCA-015, NIST SP 800-53 IA-5(1)(d), PCI-DSS 8.2.4

**Finding**: API keys, tokens, secrets not rotated regularly

**Detection Patterns**:

```python
# LOW: Static API key with no rotation
API_KEY = os.environ.get('API_KEY')  # When was this last rotated?

# No rotation policy detected
# No expiration timestamp
# No automatic rotation mechanism
```

**NIST IA-5(1)(d) Requirements**:
- Change authenticators under defined circumstances (compromise, time-based)
- API keys should have expiration dates
- Automatic rotation preferred

**Remediation**:
```python
# GOOD: API key rotation with expiration
from datetime import datetime, timedelta
import secrets

class APIKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key_hash = db.Column(db.String(128), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    last_used = db.Column(db.DateTime)
    revoked = db.Column(db.Boolean, default=False)
    
    @staticmethod
    def generate(user_id, validity_days=90):
        """Generate new API key with 90-day expiration"""
        key = secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        
        api_key = APIKey(
            key_hash=key_hash,
            user_id=user_id,
            expires_at=datetime.utcnow() + timedelta(days=validity_days)
        )
        db.session.add(api_key)
        db.session.commit()
        
        return key  # Return once, never stored
    
    def is_valid(self):
        if self.revoked:
            return False
        if datetime.utcnow() > self.expires_at:
            return False
        return True
    
    @staticmethod
    def rotate_expiring_keys():
        """Automatically rotate keys expiring in 7 days"""
        expiring_soon = APIKey.query.filter(
            APIKey.expires_at < datetime.utcnow() + timedelta(days=7),
            APIKey.revoked == False
        ).all()
        
        for old_key in expiring_soon:
            # Notify user to rotate
            send_notification(old_key.user, "API key expires soon, please rotate")
```

**NIST Controls**: IA-5(1)(d) - Change authenticators, IA-5(7) - No embedded authenticators

---

## Summary Table

| Finding | Severity | Standard | NIST Control | Remediation Priority |
|---------|----------|----------|--------------|---------------------|
| Hard-coded credentials | Critical | CWE-798, OWASP A07 | IA-5(1), IA-5(7) | Immediate |
| Weak password requirements | Critical | CWE-521 | IA-5(1)(a) | High |
| Insecure password storage | Critical | CWE-759, CWE-327 | IA-5(1)(c) | Immediate |
| Missing MFA for privileged access | High | SCA-012 | IA-2(1) | High |
| Insecure session management | High | CWE-384 | AC-11, AC-12 | High |
| Missing account lockout | Medium | CWE-307 | AC-7 | Medium |
| Username enumeration | Medium | CWE-203 | IA-4 | Medium |
| Insufficient credential rotation | Low | SCA-015 | IA-5(1)(d) | Low |

---

## Compliance Mapping

### NIST SP 800-53 Rev 5 Controls
- **IA-2**: Identification and Authentication (Organizational Users)
- **IA-2(1)**: Multi-factor authentication for network access
- **IA-4**: Identifier Management
- **IA-5**: Authenticator Management
- **IA-5(1)**: Password-based authentication
- **IA-5(7)**: No embedded unencrypted static authenticators
- **AC-7**: Unsuccessful logon attempts
- **AC-11**: Session lock
- **AC-12**: Session termination

### NIST SP 800-63B (Digital Identity)
- **AAL1**: Single-factor authentication
- **AAL2**: Multi-factor authentication
- **AAL3**: Hardware-based cryptographic authentication

### PCI-DSS v4.0
- **8.2.4**: Change user passwords/passphrases at least every 90 days
- **8.2.8**: Do not allow reuse of previous passwords
- **8.3.1**: Incorporate MFA for all access
- **8.3.6**: Authentication policies and procedures are documented

### OWASP Top 10 2021
- **A07:2021**: Identification and Authentication Failures

---

## Testing

### Automated Checks
```bash
# Search for hard-coded credentials
git grep -iE "(password|api_key|secret).*=.*['\"]"

# Search for MD5/SHA1 password hashing
git grep -E "md5|sha1.*password"

# Search for weak session configuration
git grep -iE "session.*secret.*=.*['\"].{1,10}['\"]"
```

### Manual Review
1. Review authentication flow for MFA requirements
2. Test password reset for username enumeration
3. Verify session expiration timing
4. Test account lockout after failed attempts
5. Review API key rotation policies
