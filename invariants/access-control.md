# Access Control Security Invariants (v1)

## Overview

This file defines security invariants for access control, authorization, and least privilege aligned with:
- **NIST SP 800-53 Rev 5**: AC (Access Control) family
- **NIST SP 800-171**: Requirements 3.1.x (Access Control)
- **NIST CSF 2.0**: PR.AC (Identity Management, Authentication and Access Control)
- **OWASP**: A01:2021 (Broken Access Control)
- **PCI-DSS**: Requirement 7.x (Restrict access to cardholder data)

---

## CRITICAL: Missing Authorization Checks (CWE-285, NIST AC-3)

**Standard**: CWE-285, OWASP A01:2021, NIST SP 800-53 AC-3, PCI-DSS 7.1

**Finding**: Functions or endpoints that don't verify user permissions before granting access

**Detection Patterns**:

### Python (Flask)
```python
# CRITICAL: No authorization check
@app.route('/api/users/<int:user_id>/delete', methods=['DELETE'])
def delete_user(user_id):
    # Anyone authenticated can delete any user!
    user = User.query.get(user_id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({'status': 'deleted'})

# CRITICAL: Only authentication, no authorization
@app.route('/api/admin/settings', methods=['GET'])
@login_required  # Checks if logged in, but not if user is admin
def admin_settings():
    return jsonify(get_admin_settings())
```

### JavaScript (Express)
```javascript
// CRITICAL: No authorization
app.delete('/api/users/:userId', requireAuth, (req, res) => {
  // requireAuth only checks if logged in, not permissions
  User.deleteOne({ _id: req.params.userId });
  res.json({ status: 'deleted' });
});

// CRITICAL: Client-side role check (can be bypassed)
app.get('/api/admin/data', (req, res) => {
  // Relying on client to not call this is NOT security
  res.json(sensitive_data);
});
```

### Java (Spring)
```java
// CRITICAL: No authorization annotation
@DeleteMapping("/api/users/{userId}")
public ResponseEntity<String> deleteUser(@PathVariable Long userId) {
    // Missing @PreAuthorize or @Secured annotation
    userRepository.deleteById(userId);
    return ResponseEntity.ok("deleted");
}
```

**NIST AC-3 Requirements**:
- Enforce approved authorizations for logical access
- Implement Role-Based Access Control (RBAC) or Attribute-Based Access Control (ABAC)
- Deny by default (fail secure)

**Remediation**:

### Python (Flask) - RBAC Implementation
```python
# GOOD: Proper authorization with role checks
from functools import wraps

def require_role(*roles):
    """Decorator to enforce role-based access control"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401, "Authentication required")
            
            if not any(current_user.has_role(role) for role in roles):
                abort(403, "Insufficient permissions")
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/api/users/<int:user_id>/delete', methods=['DELETE'])
@require_role('admin', 'user_manager')
def delete_user(user_id):
    """Only admins or user managers can delete users"""
    user = User.query.get_or_404(user_id)
    
    # Additional check: prevent self-deletion
    if user.id == current_user.id:
        abort(400, "Cannot delete your own account")
    
    db.session.delete(user)
    db.session.commit()
    
    # Audit log
    audit_log('USER_DELETED', user_id=user.id, deleted_by=current_user.id)
    
    return jsonify({'status': 'deleted'})

# Resource-based authorization
@app.route('/api/documents/<int:doc_id>', methods=['GET'])
@login_required
def get_document(doc_id):
    """Check if user has permission to access THIS document"""
    doc = Document.query.get_or_404(doc_id)
    
    # Check ownership or sharing
    if not (doc.owner_id == current_user.id or 
            current_user in doc.shared_with or
            current_user.has_role('admin')):
        abort(403, "You don't have permission to access this document")
    
    return jsonify(doc.to_dict())
```

### Java (Spring Security) - Method-Level Security
```java
// GOOD: Method-level authorization
import org.springframework.security.access.prepost.PreAuthorize;

@DeleteMapping("/api/users/{userId}")
@PreAuthorize("hasRole('ADMIN') or hasRole('USER_MANAGER')")
public ResponseEntity<String> deleteUser(@PathVariable Long userId, 
                                          @AuthenticationPrincipal UserDetails currentUser) {
    User user = userRepository.findById(userId)
        .orElseThrow(() -> new ResourceNotFoundException("User not found"));
    
    // Prevent self-deletion
    if (user.getUsername().equals(currentUser.getUsername())) {
        throw new IllegalArgumentException("Cannot delete your own account");
    }
    
    userRepository.deleteById(userId);
    
    // Audit log
    auditService.log("USER_DELETED", userId, currentUser.getUsername());
    
    return ResponseEntity.ok("deleted");
}

// Resource-based authorization
@GetMapping("/api/documents/{docId}")
public ResponseEntity<Document> getDocument(@PathVariable Long docId,
                                             @AuthenticationPrincipal UserDetails currentUser) {
    Document doc = documentRepository.findById(docId)
        .orElseThrow(() -> new ResourceNotFoundException("Document not found"));
    
    // Check permissions
    if (!doc.canBeAccessedBy(currentUser.getUsername())) {
        throw new AccessDeniedException("Insufficient permissions");
    }
    
    return ResponseEntity.ok(doc);
}
```

**NIST Controls**: AC-3 - Access Enforcement, AC-6 - Least Privilege

---

## CRITICAL: Insecure Direct Object References (IDOR) (CWE-639, OWASP A01)

**Standard**: CWE-639, OWASP A01:2021, NIST SP 800-53 AC-3

**Finding**: Accessing resources using user-supplied IDs without authorization checks

**Detection Patterns**:

### Python
```python
# CRITICAL: IDOR vulnerability
@app.route('/api/orders/<int:order_id>')
@login_required
def get_order(order_id):
    # User can access ANY order by changing the ID
    order = Order.query.get(order_id)
    return jsonify(order.to_dict())

# CRITICAL: Mass assignment vulnerability
@app.route('/api/users/<int:user_id>', methods=['PATCH'])
def update_user(user_id):
    user = User.query.get(user_id)
    # User can set ANY field, including 'is_admin'
    user.update(**request.json)
    db.session.commit()
```

### JavaScript
```javascript
// CRITICAL: IDOR in GraphQL
const resolvers = {
  Query: {
    order: (_, { id }) => {
      // No ownership check
      return Order.findById(id);
    }
  }
};
```

**Remediation**:
```python
# GOOD: Resource ownership validation
@app.route('/api/orders/<int:order_id>')
@login_required
def get_order(order_id):
    """Ensure user can only access their own orders"""
    order = Order.query.get_or_404(order_id)
    
    # Check ownership
    if order.user_id != current_user.id and not current_user.has_role('admin'):
        abort(403, "Access denied")
    
    return jsonify(order.to_dict())

# GOOD: Whitelist allowed fields
@app.route('/api/users/<int:user_id>', methods=['PATCH'])
@login_required
def update_user(user_id):
    # Users can only update themselves (unless admin)
    if user_id != current_user.id and not current_user.has_role('admin'):
        abort(403, "Can only update your own profile")
    
    user = User.query.get_or_404(user_id)
    
    # Whitelist of allowed fields
    allowed_fields = {'email', 'name', 'phone'}
    
    # Admins can update additional fields
    if current_user.has_role('admin'):
        allowed_fields.update({'is_active', 'role'})
    
    # Filter request data
    update_data = {k: v for k, v in request.json.items() if k in allowed_fields}
    
    user.update(**update_data)
    db.session.commit()
    
    return jsonify(user.to_dict())
```

**NIST Controls**: AC-3 - Access Enforcement, AC-4 - Information Flow Enforcement

---

## HIGH: Privilege Escalation (CWE-269, NIST AC-6)

**Standard**: CWE-269, SCA-016, OWASP A01:2021, NIST SP 800-53 AC-6

**Finding**: Users can elevate their privileges or perform administrative actions

**Detection Patterns**:

### Python
```python
# HIGH: User can set their own role
@app.route('/api/profile/update', methods=['POST'])
@login_required
def update_profile():
    current_user.name = request.form['name']
    current_user.role = request.form['role']  # CRITICAL: User controls role!
    db.session.commit()

# HIGH: No validation of role assignment
@app.route('/api/users/<int:user_id>/set-role', methods=['POST'])
@login_required
def set_user_role(user_id):
    user = User.query.get(user_id)
    user.role = request.form['role']  # Any role? Even 'super_admin'?
    db.session.commit()
```

### JavaScript
```javascript
// HIGH: Trusting client-supplied role
app.post('/api/signup', (req, res) => {
  const user = new User({
    username: req.body.username,
    password: hashPassword(req.body.password),
    role: req.body.role  // CRITICAL: Client controls initial role!
  });
  user.save();
});
```

**NIST AC-6 Requirements**:
- Employ least privilege principle
- Restrict privileged functions to authorized users
- Audit privilege usage

**Remediation**:
```python
# GOOD: Privilege separation
@app.route('/api/profile/update', methods=['POST'])
@login_required
def update_profile():
    """Users can only update non-privileged fields"""
    # Whitelist of user-editable fields (excludes 'role', 'is_active', etc.)
    allowed_fields = {'name', 'email', 'phone', 'bio'}
    
    for field, value in request.json.items():
        if field in allowed_fields:
            setattr(current_user, field, value)
    
    db.session.commit()
    return jsonify(current_user.to_dict())

# GOOD: Role assignment requires admin
@app.route('/api/users/<int:user_id>/set-role', methods=['POST'])
@require_role('admin')
def set_user_role(user_id):
    """Only admins can assign roles"""
    user = User.query.get_or_404(user_id)
    new_role = request.form['role']
    
    # Validate role exists and is not restricted
    valid_roles = {'user', 'moderator', 'admin'}
    restricted_roles = {'super_admin', 'system'}  # Only DB/system can set these
    
    if new_role not in valid_roles:
        abort(400, f"Invalid role: {new_role}")
    
    if new_role in restricted_roles:
        abort(403, f"Cannot assign restricted role: {new_role}")
    
    # Audit log before change
    audit_log('ROLE_CHANGED', 
              user_id=user.id, 
              old_role=user.role, 
              new_role=new_role, 
              changed_by=current_user.id)
    
    user.role = new_role
    db.session.commit()
    
    return jsonify({'status': 'role updated'})

# GOOD: Secure signup with default role
@app.route('/api/signup', methods=['POST'])
def signup():
    """New users always start with 'user' role"""
    user = User(
        username=request.form['username'],
        password=hash_password(request.form['password']),
        role='user'  # Default role, not client-supplied
    )
    db.session.add(user)
    db.session.commit()
    
    return jsonify({'status': 'account created'}), 201
```

**NIST Controls**: AC-6 - Least Privilege, AC-6(1) - Authorize access to security functions

---

## HIGH: Path Traversal (CWE-22, NIST AC-3)

**Standard**: CWE-22, OWASP A01:2021, NIST SP 800-53 AC-3, AC-4

**Finding**: File access based on user input without validation

**Detection Patterns**:

### Python
```python
# HIGH: Path traversal vulnerability
@app.route('/files/<path:filename>')
def download_file(filename):
    # User can access ANY file: /files/../../etc/passwd
    return send_file(f'/var/www/uploads/{filename}')

# HIGH: Zip extraction without validation
def extract_upload(zip_path, extract_to):
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_to)  # Zip slip vulnerability
```

### JavaScript (Node.js)
```javascript
// HIGH: Path traversal
app.get('/api/files/:filename', (req, res) => {
  const filepath = path.join(__dirname, 'uploads', req.params.filename);
  // If filename is "../../../etc/passwd", reads arbitrary file
  res.sendFile(filepath);
});
```

**Remediation**:
```python
# GOOD: Path validation and canonicalization
import os
from pathlib import Path

@app.route('/files/<path:filename>')
@login_required
def download_file(filename):
    """Securely serve user files with path validation"""
    
    # Define allowed directory
    upload_dir = Path('/var/www/uploads').resolve()
    
    # Construct requested file path
    requested_file = (upload_dir / filename).resolve()
    
    # Ensure requested file is within upload directory (prevents traversal)
    if not str(requested_file).startswith(str(upload_dir)):
        abort(403, "Access denied: path traversal attempt detected")
    
    # Ensure file exists
    if not requested_file.exists() or not requested_file.is_file():
        abort(404, "File not found")
    
    # Check if user owns the file
    file_record = File.query.filter_by(path=str(requested_file)).first()
    if not file_record or (file_record.owner_id != current_user.id and 
                            not current_user.has_role('admin')):
        abort(403, "Access denied")
    
    # Audit log
    audit_log('FILE_ACCESSED', file_id=file_record.id, user_id=current_user.id)
    
    return send_file(requested_file)

# GOOD: Safe zip extraction
def extract_upload_safe(zip_path, extract_to):
    """Extract zip while preventing zip slip attacks"""
    extract_to = Path(extract_to).resolve()
    
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        for member in zip_ref.namelist():
            # Construct extraction path
            member_path = (extract_to / member).resolve()
            
            # Ensure within extraction directory
            if not str(member_path).startswith(str(extract_to)):
                raise ValueError(f"Zip slip attempt detected: {member}")
            
            # Extract safely
            zip_ref.extract(member, extract_to)
```

**NIST Controls**: AC-3 - Access Enforcement, AC-4 - Information Flow Enforcement, SI-10 - Information Input Validation

---

## MEDIUM: Missing Function-Level Access Control (SCA-017)

**Standard**: SCA-017, OWASP A01:2021, NIST SP 800-53 AC-3

**Finding**: API endpoints or functions callable by unauthorized users

**Detection Patterns**:

### Python
```python
# MEDIUM: Sensitive function without decorator
def reset_all_passwords():
    """Admin function but no access control!"""
    for user in User.query.all():
        user.password = generate_temp_password()
    db.session.commit()

# Called from endpoint without authorization
@app.route('/admin/reset-passwords', methods=['POST'])
def admin_reset_passwords():
    reset_all_passwords()  # Function has no auth check
    return jsonify({'status': 'done'})
```

**Remediation**:
```python
# GOOD: Function-level access control
from flask import g

def require_admin_function(f):
    """Decorator for sensitive functions"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not g.user or not g.user.has_role('admin'):
            raise PermissionError("Admin access required")
        return f(*args, **kwargs)
    return decorated

@require_admin_function
def reset_all_passwords():
    """Reset all user passwords - ADMIN ONLY"""
    audit_log('MASS_PASSWORD_RESET', user_id=g.user.id)
    
    for user in User.query.all():
        user.password = generate_temp_password()
        send_password_reset_email(user)
    
    db.session.commit()

@app.route('/admin/reset-passwords', methods=['POST'])
@require_role('admin')
def admin_reset_passwords():
    reset_all_passwords()
    return jsonify({'status': 'passwords reset'})
```

**NIST Controls**: AC-3 - Access Enforcement, AC-6 - Least Privilege

---

## MEDIUM: Horizontal Privilege Escalation (CWE-639, OWASP A01)

**Standard**: CWE-639, OWASP A01:2021, NIST SP 800-53 AC-3

**Finding**: Users accessing other users' data at the same privilege level

**Detection Patterns**:

### Python
```python
# MEDIUM: User can access other user's private messages
@app.route('/api/messages/<int:message_id>')
@login_required
def get_message(message_id):
    # Checks authentication, but not if THIS user should see THIS message
    message = Message.query.get(message_id)
    return jsonify(message.to_dict())
```

**Remediation**:
```python
# GOOD: Ownership verification
@app.route('/api/messages/<int:message_id>')
@login_required
def get_message(message_id):
    """Ensure user can only access their own messages"""
    message = Message.query.get_or_404(message_id)
    
    # Check if user is sender or recipient
    if not (message.sender_id == current_user.id or 
            message.recipient_id == current_user.id):
        abort(403, "You don't have access to this message")
    
    return jsonify(message.to_dict())

# Alternative: Query with ownership filter
@app.route('/api/messages/<int:message_id>')
@login_required
def get_message_v2(message_id):
    """Query directly with ownership filter"""
    message = Message.query.filter(
        Message.id == message_id,
        or_(Message.sender_id == current_user.id,
            Message.recipient_id == current_user.id)
    ).first_or_404()
    
    return jsonify(message.to_dict())
```

**NIST Controls**: AC-3 - Access Enforcement

---

## LOW: Overly Permissive CORS (CWE-942, NIST AC-4)

**Standard**: CWE-942, SCA-018, NIST SP 800-53 AC-4, SC-7

**Finding**: CORS configuration allows requests from any origin

**Detection Patterns**:

### Python (Flask)
```python
# LOW: Wildcard CORS
from flask_cors import CORS
CORS(app, resources={r"/api/*": {"origins": "*"}})  # Any origin allowed

# LOW: Reflected origin
@app.after_request
def add_cors_headers(response):
    origin = request.headers.get('Origin')
    response.headers['Access-Control-Allow-Origin'] = origin  # Reflects any origin
    return response
```

### JavaScript (Express)
```javascript
// LOW: Wildcard CORS
const cors = require('cors');
app.use(cors());  // Allows all origins

// LOW: Dynamic origin without validation
app.use(cors({
  origin: (origin, callback) => callback(null, origin)  // Accepts any origin
}));
```

**Remediation**:
```python
# GOOD: Whitelist allowed origins
from flask_cors import CORS

ALLOWED_ORIGINS = [
    'https://app.example.com',
    'https://dashboard.example.com'
]

# Development-only localhost
if app.config['ENV'] == 'development':
    ALLOWED_ORIGINS.append('http://localhost:3000')

CORS(app, resources={
    r"/api/*": {
        "origins": ALLOWED_ORIGINS,
        "methods": ["GET", "POST", "PUT", "DELETE"],
        "allow_headers": ["Content-Type", "Authorization"],
        "expose_headers": ["X-Total-Count"],
        "supports_credentials": True,
        "max_age": 3600
    }
})

# Manual CORS check
@app.after_request
def check_cors(response):
    origin = request.headers.get('Origin')
    
    if origin in ALLOWED_ORIGINS:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
    
    return response
```

**NIST Controls**: AC-4 - Information Flow Enforcement, SC-7 - Boundary Protection

---

## Summary Table

| Finding | Severity | Standard | NIST Control | Remediation Priority |
|---------|----------|----------|--------------|---------------------|
| Missing authorization checks | Critical | CWE-285, OWASP A01 | AC-3 | Immediate |
| Insecure Direct Object References (IDOR) | Critical | CWE-639, OWASP A01 | AC-3 | Immediate |
| Privilege escalation | High | CWE-269 | AC-6 | High |
| Path traversal | High | CWE-22, OWASP A01 | AC-3, AC-4 | High |
| Missing function-level access control | Medium | SCA-017 | AC-3, AC-6 | Medium |
| Horizontal privilege escalation | Medium | CWE-639 | AC-3 | Medium |
| Overly permissive CORS | Low | CWE-942 | AC-4, SC-7 | Low |

---

## Compliance Mapping

### NIST SP 800-53 Rev 5 Controls
- **AC-3**: Access Enforcement
- **AC-4**: Information Flow Enforcement
- **AC-6**: Least Privilege
- **AC-6(1)**: Authorize Access to Security Functions
- **AC-6(9)**: Log Use of Privileged Functions
- **AC-17**: Remote Access

### NIST SP 800-171 Requirements
- **3.1.1**: Limit system access to authorized users
- **3.1.2**: Limit system access to authorized transactions
- **3.1.5**: Employ least privilege
- **3.1.7**: Prevent non-privileged users from executing privileged functions

### NIST CSF 2.0
- **PR.AC-1**: Identities and credentials managed
- **PR.AC-3**: Remote access is managed
- **PR.AC-4**: Access permissions and authorizations are managed
- **PR.AC-6**: Identities are proofed and bound to credentials
- **PR.AC-7**: Users, devices, and other assets are authenticated

### PCI-DSS v4.0
- **7.1**: Access to system components and cardholder data limited
- **7.2**: Access control mechanisms enforce user access
- **7.3**: Access control mechanisms in place for all system components

### OWASP Top 10 2021
- **A01:2021**: Broken Access Control

---

## Testing

### Automated Checks
```bash
# Search for missing authorization decorators
git grep -E "@app.route.*\(.*DELETE|PUT|PATCH" | grep -v "@require"

# Search for IDOR vulnerabilities (query by ID without ownership check)
git grep -E "\.query\.get\(.*_id\)" | grep -v "current_user"

# Search for wildcard CORS
git grep -E "origins.*=.*\*|Access-Control-Allow-Origin.*\*"
```

### Manual Review
1. Test each API endpoint with different user roles
2. Attempt to access other users' resources by ID manipulation
3. Try to escalate privileges through parameter tampering
4. Verify path traversal protection with `../` patterns
5. Check CORS configuration against allowed origins
