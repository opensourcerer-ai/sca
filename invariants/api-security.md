# API Security Invariants (v1)

## Overview

This file defines security invariants for API security across REST, GraphQL, gRPC, and other API patterns aligned with:
- **OWASP API Security Top 10 (2023)**: Complete coverage of API-specific risks
- **NIST SP 800-53 Rev 5**: AC (Access Control), SC (System and Communications Protection)
- **NIST SP 800-204**: Security Strategies for Microservices-based Application Systems
- **NIST SP 800-63-3**: Digital Identity Guidelines
- **PCI-DSS**: Requirements 6.5.x, 8.x (API authentication)
- **OWASP Top 10 2021**: A01 (Broken Access Control), A07 (Identification and Authentication Failures)

**Scope**: Analysis of API implementation code in repositories (REST, GraphQL, gRPC, WebSocket APIs).

---

## CRITICAL: Broken Object Level Authorization (OWASP API1:2023)

**Standard**: OWASP API1:2023, CWE-639, SCA-301

**Finding**: API endpoints access objects using IDs from user input without authorization checks

**Detection Patterns**:

### REST APIs - Python (Flask)
```python
# CRITICAL: No authorization check
@app.route('/api/users/<user_id>')
def get_user(user_id):
    user = User.query.get(user_id)
    return jsonify(user.to_dict())  # Any authenticated user can view any user

# CRITICAL: Order access without ownership check
@app.route('/api/orders/<order_id>')
@login_required
def get_order(order_id):
    order = Order.query.get(order_id)
    return jsonify(order.to_dict())  # User can access any order by changing ID
```

### REST APIs - JavaScript (Express)
```javascript
// CRITICAL: No authorization
app.get('/api/documents/:id', authenticate, async (req, res) => {
  const doc = await Document.findById(req.params.id);
  res.json(doc);  // CRITICAL: No ownership check
});

// CRITICAL: Delete without authorization
app.delete('/api/posts/:id', authenticate, async (req, res) => {
  await Post.deleteOne({ _id: req.params.id });  // Anyone can delete any post
  res.json({ status: 'deleted' });
});
```

### GraphQL
```graphql
# CRITICAL: GraphQL resolver without authorization
type Query {
  user(id: ID!): User
  order(id: ID!): Order
}

# Resolver without authorization
const resolvers = {
  Query: {
    user: (_, { id }) => User.findById(id),  // CRITICAL: No auth check
    order: (_, { id }) => Order.findById(id)  // CRITICAL: No auth check
  }
}
```

### Java (Spring)
```java
// CRITICAL: No authorization check
@GetMapping("/api/users/{userId}")
public ResponseEntity<User> getUser(@PathVariable Long userId) {
    User user = userRepository.findById(userId).orElseThrow();
    return ResponseEntity.ok(user);  // CRITICAL: No ownership/permission check
}
```

**Remediation**:

```python
# GOOD: Authorization with ownership check
@app.route('/api/users/<user_id>')
@login_required
def get_user(user_id):
    user = User.query.get_or_404(user_id)
    
    # Check authorization: user can only view themselves or admin can view anyone
    if user.id != current_user.id and not current_user.has_role('admin'):
        abort(403, "You don't have permission to view this user")
    
    return jsonify(user.to_dict())

# GOOD: Order access with ownership verification
@app.route('/api/orders/<order_id>')
@login_required
def get_order(order_id):
    # Query with ownership filter built-in
    order = Order.query.filter_by(
        id=order_id,
        user_id=current_user.id
    ).first_or_404(description="Order not found or access denied")
    
    return jsonify(order.to_dict())

# GOOD: GraphQL with authorization
const resolvers = {
  Query: {
    order: async (_, { id }, context) => {
      const order = await Order.findById(id);
      
      // Check ownership
      if (order.userId !== context.user.id && !context.user.isAdmin) {
        throw new ForbiddenError("Access denied");
      }
      
      return order;
    }
  }
}
```

**OWASP API Security**: API1:2023 - Broken Object Level Authorization

---

## CRITICAL: Broken Authentication (OWASP API2:2023)

**Standard**: OWASP API2:2023, CWE-287, SCA-302

**Finding**: API authentication mechanisms that can be bypassed or are improperly implemented

**Detection Patterns**:

### Missing Authentication
```python
# CRITICAL: Public API endpoint for sensitive data
@app.route('/api/admin/users')
def admin_users():
    # No @login_required or authentication check
    users = User.query.all()
    return jsonify([u.to_dict() for u in users])

# CRITICAL: API key in URL parameter (logged, cached)
@app.route('/api/data')
def get_data():
    api_key = request.args.get('api_key')  # CRITICAL: In URL
    if api_key == VALID_KEY:
        return jsonify(sensitive_data)
```

### Weak Token Validation
```javascript
// CRITICAL: JWT without signature verification
app.get('/api/profile', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  const decoded = jwt.decode(token);  // CRITICAL: No verify(), just decode
  
  const user = getUserById(decoded.userId);
  res.json(user);
});

// CRITICAL: No token expiration check
app.post('/api/action', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  const decoded = jwt.verify(token, SECRET);
  // No exp claim check - expired tokens still work
  
  performAction(decoded.userId);
});
```

### API Key Exposure
```python
# CRITICAL: API key in response
@app.route('/api/user/profile')
def profile():
    user = current_user
    return jsonify({
        'name': user.name,
        'email': user.email,
        'api_key': user.api_key  # CRITICAL: Exposing API key
    })
```

**Remediation**:

```python
# GOOD: Proper authentication
from functools import wraps
import jwt
from datetime import datetime

def require_api_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # API key in header, not URL
        api_key = request.headers.get('X-API-Key')
        
        if not api_key:
            abort(401, "API key required")
        
        # Validate API key
        key_record = APIKey.query.filter_by(
            key_hash=hash_api_key(api_key),
            revoked=False
        ).first()
        
        if not key_record:
            abort(401, "Invalid API key")
        
        # Check expiration
        if datetime.utcnow() > key_record.expires_at:
            abort(401, "API key expired")
        
        # Update last used
        key_record.last_used = datetime.utcnow()
        db.session.commit()
        
        return f(*args, **kwargs)
    return decorated

# GOOD: JWT with proper verification
def verify_jwt_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        if not token:
            abort(401, "Token required")
        
        try:
            # Verify signature AND expiration
            payload = jwt.decode(
                token,
                SECRET_KEY,
                algorithms=['HS256'],
                options={'verify_exp': True}  # Enforce expiration
            )
            
            # Additional checks
            if 'userId' not in payload:
                abort(401, "Invalid token payload")
            
            # Store user context
            g.user_id = payload['userId']
            
        except jwt.ExpiredSignatureError:
            abort(401, "Token expired")
        except jwt.InvalidTokenError:
            abort(401, "Invalid token")
        
        return f(*args, **kwargs)
    return decorated

@app.route('/api/profile')
@verify_jwt_token
def profile():
    user = User.query.get(g.user_id)
    return jsonify({
        'name': user.name,
        'email': user.email
        # NEVER return api_key
    })
```

**OWASP API Security**: API2:2023 - Broken Authentication

---

## CRITICAL: Broken Object Property Level Authorization (OWASP API3:2023)

**Standard**: OWASP API3:2023, CWE-213, SCA-303

**Finding**: API returns excessive data or allows modification of sensitive properties

**Detection Patterns**:

### Excessive Data Exposure
```python
# CRITICAL: Returning all user fields including sensitive data
@app.route('/api/users')
def list_users():
    users = User.query.all()
    return jsonify([user.__dict__ for user in users])  # CRITICAL: Includes password_hash, ssn, etc.

# CRITICAL: No field filtering
class UserSchema(ma.Schema):
    class Meta:
        fields = '__all__'  # CRITICAL: Exposes all fields
```

### Mass Assignment
```python
# CRITICAL: Mass assignment vulnerability
@app.route('/api/users/<user_id>', methods=['PATCH'])
def update_user(user_id):
    user = User.query.get(user_id)
    
    # User can set ANY field including is_admin, role, etc.
    for key, value in request.json.items():
        setattr(user, key, value)  # CRITICAL: No field whitelist
    
    db.session.commit()
    return jsonify(user.to_dict())
```

### GraphQL Field Exposure
```graphql
# CRITICAL: GraphQL type exposing sensitive fields
type User {
  id: ID!
  email: String!
  password_hash: String!  # CRITICAL: Should never be in schema
  ssn: String!  # CRITICAL: Sensitive PII
  salary: Float!  # CRITICAL: Sensitive data
}
```

**Remediation**:

```python
# GOOD: Explicit field whitelisting with Marshmallow
class UserPublicSchema(ma.Schema):
    """Public user fields - safe to expose"""
    id = fields.Int()
    username = fields.Str()
    name = fields.Str()
    created_at = fields.DateTime()

class UserPrivateSchema(UserPublicSchema):
    """Private fields - only for user themselves or admin"""
    email = fields.Str()
    phone = fields.Str()

@app.route('/api/users')
def list_users():
    users = User.query.all()
    schema = UserPublicSchema(many=True)
    return jsonify(schema.dump(users))

# GOOD: Field whitelist for updates
@app.route('/api/users/<user_id>', methods=['PATCH'])
@login_required
def update_user(user_id):
    user = User.query.get_or_404(user_id)
    
    # Authorization check
    if user.id != current_user.id and not current_user.has_role('admin'):
        abort(403)
    
    # Whitelist of allowed fields for regular users
    allowed_fields = {'name', 'email', 'phone', 'bio'}
    
    # Admins can update additional fields
    if current_user.has_role('admin'):
        allowed_fields.update({'is_active', 'role'})
    
    # Only update whitelisted fields
    for key, value in request.json.items():
        if key in allowed_fields:
            setattr(user, key, value)
        else:
            abort(400, f"Field '{key}' cannot be modified")
    
    db.session.commit()
    return jsonify(UserPrivateSchema().dump(user))

# GOOD: GraphQL with field-level authorization
type User {
  id: ID!
  username: String!
  email: String! @auth(requires: OWNER_OR_ADMIN)
  phone: String @auth(requires: OWNER_OR_ADMIN)
  # password_hash, ssn, salary NOT in schema
}
```

**OWASP API Security**: API3:2023 - Broken Object Property Level Authorization

---

## HIGH: Unrestricted Resource Consumption (OWASP API4:2023)

**Standard**: OWASP API4:2023, CWE-770, SCA-304

**Finding**: API lacks rate limiting, pagination, or resource constraints

**Detection Patterns**:

### No Rate Limiting
```python
# HIGH: No rate limiting
@app.route('/api/login', methods=['POST'])
def login():
    # Attacker can brute force passwords with unlimited attempts
    username = request.json['username']
    password = request.json['password']
    # ... authentication logic

# HIGH: Expensive operation without throttling
@app.route('/api/report/generate', methods=['POST'])
def generate_report():
    # No rate limit on expensive PDF generation
    report = generate_large_pdf(request.json)
    return send_file(report)
```

### No Pagination
```javascript
// HIGH: No pagination - returns all records
app.get('/api/users', async (req, res) => {
  const users = await User.find({});  // Could return millions of records
  res.json(users);
});

// HIGH: User-controlled limit without max
app.get('/api/posts', async (req, res) => {
  const limit = parseInt(req.query.limit) || 100;  // User can set limit=1000000
  const posts = await Post.find({}).limit(limit);
  res.json(posts);
});
```

### No Request Size Limits
```python
# HIGH: No request body size limit
@app.route('/api/upload', methods=['POST'])
def upload():
    # Attacker can send multi-GB request
    data = request.get_json()  # No size limit
    process_data(data)
```

**Remediation**:

```python
# GOOD: Rate limiting with Flask-Limiter
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="redis://localhost:6379"
)

@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")  # Prevent brute force
def login():
    username = request.json['username']
    password = request.json['password']
    # ... authentication logic

@app.route('/api/report/generate', methods=['POST'])
@limiter.limit("3 per hour")  # Expensive operation
@login_required
def generate_report():
    report = generate_large_pdf(request.json)
    return send_file(report)

# GOOD: Pagination with max limit
@app.route('/api/users')
def list_users():
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 20, type=int), 100)  # Max 100
    
    pagination = User.query.paginate(
        page=page,
        per_page=per_page,
        error_out=False
    )
    
    return jsonify({
        'items': UserPublicSchema(many=True).dump(pagination.items),
        'total': pagination.total,
        'page': pagination.page,
        'pages': pagination.pages
    })

# GOOD: Request size limit
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max

@app.before_request
def check_content_length():
    if request.content_length and request.content_length > app.config['MAX_CONTENT_LENGTH']:
        abort(413, "Request too large")
```

**OWASP API Security**: API4:2023 - Unrestricted Resource Consumption

---

## HIGH: Broken Function Level Authorization (OWASP API5:2023)

**Standard**: OWASP API5:2023, CWE-285, SCA-305

**Finding**: API endpoints perform privileged actions without proper role checks

**Detection Patterns**:

### Missing Role Checks
```python
# HIGH: Admin endpoint without role check
@app.route('/api/admin/delete-user/<user_id>', methods=['DELETE'])
@login_required  # Only checks authentication, not authorization
def delete_user(user_id):
    user = User.query.get(user_id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({'status': 'deleted'})

# HIGH: Privilege escalation via function access
@app.route('/api/promote/<user_id>', methods=['POST'])
@login_required
def promote_user(user_id):
    # Any authenticated user can promote anyone to admin
    user = User.query.get(user_id)
    user.role = 'admin'
    db.session.commit()
```

### GraphQL Mutation Without Authorization
```javascript
// HIGH: Mutation without role check
const resolvers = {
  Mutation: {
    deleteUser: async (_, { id }, context) => {
      // No check if context.user is admin
      await User.deleteOne({ _id: id });
      return { success: true };
    },
    
    updateUserRole: async (_, { id, role }, context) => {
      // Any logged-in user can change roles
      await User.updateOne({ _id: id }, { role });
      return User.findById(id);
    }
  }
}
```

**Remediation**:

```python
# GOOD: Role-based access control
from functools import wraps

def require_role(*roles):
    """Decorator to enforce role-based access"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401, "Authentication required")
            
            if not any(current_user.has_role(role) for role in roles):
                abort(403, f"Requires one of: {', '.join(roles)}")
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/api/admin/delete-user/<user_id>', methods=['DELETE'])
@require_role('admin', 'super_admin')
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    
    # Prevent self-deletion
    if user.id == current_user.id:
        abort(400, "Cannot delete your own account")
    
    # Audit log
    audit_log('USER_DELETED', user_id=user.id, deleted_by=current_user.id)
    
    db.session.delete(user)
    db.session.commit()
    return jsonify({'status': 'deleted'})

@app.route('/api/promote/<user_id>', methods=['POST'])
@require_role('admin')
def promote_user(user_id):
    user = User.query.get_or_404(user_id)
    new_role = request.json.get('role')
    
    # Validate role
    valid_roles = ['user', 'moderator', 'admin']
    if new_role not in valid_roles:
        abort(400, f"Invalid role: {new_role}")
    
    # Super admin role cannot be assigned via API
    if new_role == 'super_admin':
        abort(403, "Cannot assign super_admin role via API")
    
    # Audit log
    audit_log('ROLE_CHANGED', 
              user_id=user.id, 
              old_role=user.role, 
              new_role=new_role,
              changed_by=current_user.id)
    
    user.role = new_role
    db.session.commit()
    return jsonify(UserPrivateSchema().dump(user))

# GOOD: GraphQL with authorization
const resolvers = {
  Mutation: {
    deleteUser: async (_, { id }, context) => {
      // Check admin role
      if (!context.user || !context.user.roles.includes('admin')) {
        throw new ForbiddenError("Admin access required");
      }
      
      // Prevent self-deletion
      if (id === context.user.id) {
        throw new UserInputError("Cannot delete your own account");
      }
      
      await auditLog('USER_DELETED', { userId: id, deletedBy: context.user.id });
      await User.deleteOne({ _id: id });
      return { success: true };
    }
  }
}
```

**OWASP API Security**: API5:2023 - Broken Function Level Authorization

---

## MEDIUM: Unrestricted Access to Sensitive Business Flows (OWASP API6:2023)

**Standard**: OWASP API6:2023, CWE-799, SCA-306

**Finding**: API lacks protection against automated abuse of business logic

**Detection Patterns**:

```python
# MEDIUM: No protection against automated ticket purchasing
@app.route('/api/tickets/purchase', methods=['POST'])
@login_required
def purchase_tickets():
    # Bot can buy all tickets instantly
    event_id = request.json['event_id']
    quantity = request.json['quantity']
    
    reserve_tickets(current_user.id, event_id, quantity)
    return jsonify({'status': 'reserved'})

# MEDIUM: No CAPTCHA for sensitive operation
@app.route('/api/password-reset', methods=['POST'])
def request_password_reset():
    # Attacker can enumerate users by requesting resets
    email = request.json['email']
    send_reset_email(email)
    return jsonify({'status': 'sent'})

# MEDIUM: Referral code abuse
@app.route('/api/referral/claim', methods=['POST'])
@login_required
def claim_referral_bonus():
    # User can create multiple accounts to abuse referrals
    referral_code = request.json['code']
    credit_bonus(current_user.id, referral_code)
```

**Remediation**:

```python
# GOOD: Rate limiting + device fingerprinting for sensitive flows
from flask_limiter import Limiter

@app.route('/api/tickets/purchase', methods=['POST'])
@login_required
@limiter.limit("10 per hour", key_func=lambda: current_user.id)  # Per-user limit
def purchase_tickets():
    event_id = request.json['event_id']
    quantity = request.json['quantity']
    
    # Check if user has pending reservations
    pending = Reservation.query.filter_by(
        user_id=current_user.id,
        status='pending',
        created_at > datetime.utcnow() - timedelta(minutes=15)
    ).count()
    
    if pending >= 3:
        abort(429, "Too many pending reservations")
    
    # Quantity limit per transaction
    if quantity > 10:
        abort(400, "Maximum 10 tickets per transaction")
    
    reserve_tickets(current_user.id, event_id, quantity)
    return jsonify({'status': 'reserved'})

# GOOD: CAPTCHA for password reset
import requests

@app.route('/api/password-reset', methods=['POST'])
@limiter.limit("3 per hour", key_func=get_remote_address)
def request_password_reset():
    email = request.json['email']
    captcha_token = request.json.get('captcha_token')
    
    # Verify CAPTCHA
    captcha_response = requests.post('https://www.google.com/recaptcha/api/siteverify', data={
        'secret': RECAPTCHA_SECRET,
        'response': captcha_token,
        'remoteip': request.remote_addr
    }).json()
    
    if not captcha_response.get('success'):
        abort(400, "CAPTCHA verification failed")
    
    # Always return same response (prevent enumeration)
    send_reset_email_if_exists(email)
    return jsonify({'status': 'If account exists, reset email sent'})

# GOOD: Referral abuse prevention
@app.route('/api/referral/claim', methods=['POST'])
@login_required
def claim_referral_bonus():
    referral_code = request.json['code']
    
    # Check if user already claimed a referral
    if current_user.referral_claimed:
        abort(400, "Referral bonus already claimed")
    
    # Verify account age (prevent fresh account abuse)
    if datetime.utcnow() - current_user.created_at < timedelta(days=7):
        abort(400, "Account must be 7 days old to claim referral")
    
    # Verify account activity (not just created for referral)
    if current_user.order_count < 1:
        abort(400, "Must make a purchase before claiming referral")
    
    # Check referrer
    referrer = User.query.filter_by(referral_code=referral_code).first()
    if not referrer:
        abort(404, "Invalid referral code")
    
    # Prevent self-referral
    if referrer.id == current_user.id:
        abort(400, "Cannot use your own referral code")
    
    credit_bonus(current_user.id, referral_code)
    current_user.referral_claimed = True
    db.session.commit()
```

**OWASP API Security**: API6:2023 - Unrestricted Access to Sensitive Business Flows

---

## HIGH: Server Side Request Forgery (OWASP API7:2023)

**Standard**: OWASP API7:2023, CWE-918, SCA-307

**Finding**: API fetches remote resources based on user input without validation

**Note**: Detailed SSRF patterns covered in `network-security.md` SCA-873. This section focuses on API-specific SSRF scenarios.

**Detection Patterns**:

```python
# HIGH: Webhook URL without validation
@app.route('/api/webhooks/register', methods=['POST'])
@login_required
def register_webhook():
    url = request.json['url']
    
    # No validation - attacker can point to internal services
    webhook = Webhook(user_id=current_user.id, url=url)
    db.session.add(webhook)
    db.session.commit()
    
    # Test webhook (SSRF vulnerability)
    requests.post(url, json={'test': True})

# HIGH: Avatar URL fetch
@app.route('/api/profile/avatar', methods=['POST'])
def set_avatar():
    url = request.json['avatar_url']
    
    # Fetch user-provided URL
    response = requests.get(url)  # SSRF
    
    # Save image
    with open(f'avatars/{current_user.id}.jpg', 'wb') as f:
        f.write(response.content)
```

**Remediation**: See `network-security.md:SCA-873` for comprehensive SSRF protection patterns.

**OWASP API Security**: API7:2023 - Server Side Request Forgery

---

## CRITICAL: Security Misconfiguration (OWASP API8:2023)

**Standard**: OWASP API8:2023, CWE-16, SCA-308

**Finding**: API exposed with insecure default configurations

**Detection Patterns**:

### Debug Mode in Production
```python
# CRITICAL: Debug mode enabled
if __name__ == '__main__':
    app.run(debug=True)  # CRITICAL: In production code

# CRITICAL: Flask debug via environment
app = Flask(__name__)
app.config['DEBUG'] = True  # CRITICAL
```

### Verbose Error Messages
```python
# CRITICAL: Exposing stack traces
@app.errorhandler(Exception)
def handle_error(error):
    return jsonify({
        'error': str(error),
        'traceback': traceback.format_exc()  # CRITICAL: Exposes code structure
    }), 500
```

### CORS Misconfiguration
```python
# CRITICAL: Allow all origins
from flask_cors import CORS
CORS(app, resources={r"/*": {"origins": "*"}})  # CRITICAL

# CRITICAL: Reflected origin
@app.after_request
def add_cors(response):
    response.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin')  # CRITICAL
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response
```

### Missing Security Headers
```javascript
// CRITICAL: No security headers
app.get('/api/data', (req, res) => {
  res.json(data);
  // Missing: X-Content-Type-Options, X-Frame-Options, CSP, etc.
});
```

**Remediation**:

```python
# GOOD: Environment-based configuration
import os

class Config:
    DEBUG = False
    TESTING = False
    SECRET_KEY = os.environ.get('SECRET_KEY')
    
class DevelopmentConfig(Config):
    DEBUG = True  # Only in dev

class ProductionConfig(Config):
    DEBUG = False  # Explicitly disabled

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig
}

app.config.from_object(config[os.environ.get('FLASK_ENV', 'production')])

# GOOD: Generic error messages to clients
@app.errorhandler(Exception)
def handle_error(error):
    # Log detailed error internally
    app.logger.error(f"Error: {error}", exc_info=True)
    
    # Generic message to client
    if isinstance(error, HTTPException):
        return jsonify({'error': error.description}), error.code
    
    return jsonify({'error': 'Internal server error'}), 500

# GOOD: Strict CORS
ALLOWED_ORIGINS = [
    'https://app.example.com',
    'https://dashboard.example.com'
]

if app.config['ENV'] == 'development':
    ALLOWED_ORIGINS.append('http://localhost:3000')

CORS(app, resources={
    r"/api/*": {
        "origins": ALLOWED_ORIGINS,
        "methods": ["GET", "POST", "PUT", "DELETE"],
        "allow_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True,
        "max_age": 3600
    }
})

# GOOD: Security headers
from flask_talisman import Talisman

Talisman(app, 
    force_https=True,
    strict_transport_security=True,
    content_security_policy={
        'default-src': "'self'",
        'script-src': "'self'",
        'style-src': "'self'"
    }
)

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response
```

**OWASP API Security**: API8:2023 - Security Misconfiguration

---

## MEDIUM: Improper Inventory Management (OWASP API9:2023)

**Standard**: OWASP API9:2023, SCA-309

**Finding**: Lack of API documentation, versioning, or deprecated endpoints still active

**Detection Patterns**:

### No API Versioning
```python
# MEDIUM: No versioning in routes
@app.route('/api/users')  # What version is this?
def get_users():
    pass

# MEDIUM: Breaking changes without version bump
@app.route('/api/products')
def get_products():
    # Changed response format - breaks existing clients
    return jsonify([{'id': p.id, 'name': p.name} for p in products])  # Was returning full objects
```

### Deprecated Endpoints Still Active
```python
# MEDIUM: Deprecated endpoint not disabled
@app.route('/api/v1/login', methods=['POST'])
def login_v1():
    # Old authentication method with vulnerabilities
    # Should be disabled but still responds
    username = request.json['username']
    password = request.json['password']  # No rate limiting in v1
    # ...
```

### Undocumented Endpoints
```python
# MEDIUM: Debug/internal endpoints in production
@app.route('/api/internal/reset-db')  # Not documented
def reset_database():
    # Dangerous endpoint, no auth
    db.drop_all()
    db.create_all()

@app.route('/api/debug/users')  # Internal endpoint
def debug_users():
    # Returns sensitive debug info
    return jsonify([u.__dict__ for u in User.query.all()])
```

**Remediation**:

```python
# GOOD: API versioning
from flask import Blueprint

# Version 1 API
api_v1 = Blueprint('api_v1', __name__, url_prefix='/api/v1')

@api_v1.route('/users')
def get_users_v1():
    # Old implementation
    pass

# Version 2 API
api_v2 = Blueprint('api_v2', __name__, url_prefix='/api/v2')

@api_v2.route('/users')
def get_users_v2():
    # New implementation with pagination
    pass

app.register_blueprint(api_v1)
app.register_blueprint(api_v2)

# GOOD: Deprecation headers and sunset
@api_v1.route('/login', methods=['POST'])
def login_v1():
    # Add deprecation headers
    response = jsonify({'token': generate_token()})
    response.headers['Deprecation'] = 'true'
    response.headers['Sunset'] = 'Sat, 31 Dec 2024 23:59:59 GMT'
    response.headers['Link'] = '</api/v2/auth/login>; rel="successor-version"'
    
    return response

# GOOD: Disable deprecated endpoints
@api_v1.route('/old-endpoint')
def old_endpoint():
    abort(410, "This endpoint has been deprecated. Use /api/v2/new-endpoint")

# GOOD: OpenAPI documentation
from flask_swagger_ui import get_swaggerui_blueprint

SWAGGER_URL = '/api/docs'
API_URL = '/static/swagger.json'

swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={'app_name': "My API"}
)

app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)

# GOOD: Remove debug endpoints in production
if app.config['ENV'] != 'development':
    # Debug routes not registered in production
    pass
else:
    @app.route('/api/debug/users')
    @require_role('developer')
    def debug_users():
        return jsonify([u.__dict__ for u in User.query.all()])
```

**OWASP API Security**: API9:2023 - Improper Inventory Management

---

## MEDIUM: Unsafe Consumption of APIs (OWASP API10:2023)

**Standard**: OWASP API10:2023, CWE-20, SCA-310

**Finding**: API consumes data from third-party APIs without proper validation

**Detection Patterns**:

```python
# MEDIUM: Trusting third-party API response without validation
@app.route('/api/weather')
def get_weather():
    city = request.args.get('city')
    
    # Call third-party weather API
    response = requests.get(f'https://api.weather.com/v1/weather?city={city}')
    data = response.json()
    
    # Directly use third-party data without validation
    return jsonify({
        'temperature': data['temp'],  # Could be missing, wrong type, or malicious
        'forecast': data['forecast']
    })

# MEDIUM: No timeout on third-party API call
@app.route('/api/exchange-rate')
def get_exchange_rate():
    # No timeout - if third-party is slow, blocks our API
    response = requests.get('https://api.exchangerate.com/latest')
    return jsonify(response.json())

# MEDIUM: No error handling for third-party API
@app.route('/api/translate')
def translate():
    text = request.json['text']
    
    # If translation API is down, our API crashes
    response = requests.post('https://api.translate.com/v1/translate', json={'text': text})
    return jsonify(response.json())
```

**Remediation**:

```python
# GOOD: Validate third-party API responses
from marshmallow import Schema, fields, ValidationError

class WeatherResponseSchema(Schema):
    """Expected schema from weather API"""
    temp = fields.Float(required=True)
    forecast = fields.Str(required=True)
    humidity = fields.Float()

@app.route('/api/weather')
def get_weather():
    city = request.args.get('city')
    
    try:
        # Timeout on third-party call
        response = requests.get(
            f'https://api.weather.com/v1/weather',
            params={'city': city},
            timeout=(5, 10)  # 5s connect, 10s read
        )
        response.raise_for_status()
        
        # Validate response structure
        schema = WeatherResponseSchema()
        data = schema.load(response.json())
        
        # Sanitize data before returning
        return jsonify({
            'temperature': float(data['temp']),
            'forecast': str(data['forecast'])[:500]  # Limit length
        })
        
    except requests.Timeout:
        app.logger.error("Weather API timeout")
        abort(504, "Weather service unavailable")
    except requests.RequestException as e:
        app.logger.error(f"Weather API error: {e}")
        abort(502, "Weather service error")
    except ValidationError as e:
        app.logger.error(f"Invalid weather API response: {e}")
        abort(502, "Invalid weather data received")

# GOOD: Circuit breaker for third-party APIs
from pybreaker import CircuitBreaker

# Circuit breaker: open after 5 failures, half-open after 60s
translation_breaker = CircuitBreaker(fail_max=5, timeout_duration=60)

@translation_breaker
def call_translation_api(text):
    response = requests.post(
        'https://api.translate.com/v1/translate',
        json={'text': text},
        timeout=10
    )
    response.raise_for_status()
    return response.json()

@app.route('/api/translate', methods=['POST'])
def translate():
    text = request.json.get('text', '')
    
    if len(text) > 5000:
        abort(400, "Text too long")
    
    try:
        result = call_translation_api(text)
        
        # Validate response
        if 'translated_text' not in result:
            raise ValueError("Invalid response format")
        
        return jsonify({'translated': result['translated_text']})
        
    except CircuitBreakerError:
        app.logger.error("Translation API circuit breaker open")
        abort(503, "Translation service temporarily unavailable")
    except Exception as e:
        app.logger.error(f"Translation error: {e}")
        abort(502, "Translation service error")
```

**OWASP API Security**: API10:2023 - Unsafe Consumption of APIs

---

## Summary Table

| Finding | Severity | Standard | OWASP API | SCA ID |
|---------|----------|----------|-----------|---------|
| Broken Object Level Authorization | Critical | OWASP API1:2023, CWE-639 | API1 | SCA-301 |
| Broken Authentication | Critical | OWASP API2:2023, CWE-287 | API2 | SCA-302 |
| Broken Object Property Level Authorization | Critical | OWASP API3:2023, CWE-213 | API3 | SCA-303 |
| Unrestricted Resource Consumption | High | OWASP API4:2023, CWE-770 | API4 | SCA-304 |
| Broken Function Level Authorization | High | OWASP API5:2023, CWE-285 | API5 | SCA-305 |
| Unrestricted Access to Business Flows | Medium | OWASP API6:2023, CWE-799 | API6 | SCA-306 |
| Server Side Request Forgery | High | OWASP API7:2023, CWE-918 | API7 | SCA-307 |
| Security Misconfiguration | Critical | OWASP API8:2023, CWE-16 | API8 | SCA-308 |
| Improper Inventory Management | Medium | OWASP API9:2023 | API9 | SCA-309 |
| Unsafe Consumption of APIs | Medium | OWASP API10:2023, CWE-20 | API10 | SCA-310 |

---

## Compliance Mapping

### OWASP API Security Top 10 (2023)
- **API1:2023**: Broken Object Level Authorization
- **API2:2023**: Broken Authentication
- **API3:2023**: Broken Object Property Level Authorization
- **API4:2023**: Unrestricted Resource Consumption
- **API5:2023**: Broken Function Level Authorization
- **API6:2023**: Unrestricted Access to Sensitive Business Flows
- **API7:2023**: Server Side Request Forgery
- **API8:2023**: Security Misconfiguration
- **API9:2023**: Improper Inventory Management
- **API10:2023**: Unsafe Consumption of APIs

### NIST SP 800-53 Rev 5 Controls
- **AC-3**: Access Enforcement
- **AC-6**: Least Privilege
- **IA-2**: Identification and Authentication
- **IA-5**: Authenticator Management
- **SC-5**: Denial of Service Protection
- **SC-7**: Boundary Protection
- **SI-10**: Information Input Validation

### NIST Special Publications
- **SP 800-204**: Security Strategies for Microservices-based Application Systems
- **SP 800-63-3**: Digital Identity Guidelines

### PCI-DSS v4.0
- **6.5.1**: Injection flaws
- **6.5.3**: Insecure cryptographic storage
- **6.5.8**: Improper access control
- **8.2**: User authentication and password management

### OWASP Top 10 2021
- **A01:2021**: Broken Access Control
- **A02:2021**: Cryptographic Failures
- **A05:2021**: Security Misconfiguration
- **A07:2021**: Identification and Authentication Failures

---

## Testing

### Automated Checks
```bash
# Search for missing authorization checks
git grep -E "@app.route.*<.*id>" | grep -v "@login_required\|@require"

# Search for mass assignment vulnerabilities
git grep -E "setattr.*request\.(json|form)|update\(\*\*request"

# Search for missing rate limiting
git grep -E "@app.route.*/login|/api/" | grep -v "@limiter"

# Search for debug mode
git grep -iE "debug\s*=\s*True|DEBUG.*True"

# Search for wildcard CORS
git grep -E "origins.*=.*\*|Access-Control-Allow-Origin.*\*"

# Search for missing pagination
git grep -E "\.all\(\)|\.find\(\{\}\)" 

# Search for API keys in responses
git grep -iE "api_key|apiKey|access_token" | grep "return jsonify"
```

### Manual Review
1. Test each API endpoint with different user roles
2. Attempt to access other users' resources by ID manipulation
3. Try mass assignment by adding extra fields in requests
4. Test rate limiting by sending rapid requests
5. Check for proper pagination and max limits
6. Verify API versioning and deprecation headers
7. Test third-party API failure scenarios
8. Review error messages for information disclosure

---

## GraphQL-Specific Patterns

### Introspection in Production
```graphql
# CRITICAL: Introspection enabled in production
{
  __schema {
    types {
      name
      fields {
        name
      }
    }
  }
}
```

**Remediation**:
```python
# Disable introspection in production
schema = graphene.Schema(
    query=Query,
    mutation=Mutation,
    auto_camelcase=False
)

if not app.config['DEBUG']:
    schema.introspect = False  # Disable in production
```

### Query Depth/Complexity Limits
```python
# GOOD: GraphQL query complexity limits
from graphql import GraphQLError

def depth_limit_validator(max_depth):
    def validate(context, node, ancestors):
        if len(ancestors) > max_depth:
            raise GraphQLError(f'Query exceeds max depth of {max_depth}')
    return validate

schema = graphene.Schema(
    query=Query,
    validation_rules=[depth_limit_validator(10)]
)
```

---

## gRPC-Specific Patterns

### Missing Authentication Interceptor
```python
# CRITICAL: gRPC service without authentication
class UserService(user_pb2_grpc.UserServiceServicer):
    def GetUser(self, request, context):
        # No authentication check
        user = db.get_user(request.user_id)
        return user_pb2.UserResponse(user=user)
```

**Remediation**:
```python
# GOOD: gRPC authentication interceptor
import grpc
from grpc import StatusCode

class AuthInterceptor(grpc.ServerInterceptor):
    def intercept_service(self, continuation, handler_call_details):
        # Get metadata (headers)
        metadata = dict(handler_call_details.invocation_metadata)
        
        # Check authorization token
        token = metadata.get('authorization', '').replace('Bearer ', '')
        
        if not token or not validate_token(token):
            context = grpc.ServicerContext()
            context.abort(StatusCode.UNAUTHENTICATED, "Invalid or missing token")
        
        return continuation(handler_call_details)

# Add interceptor to server
server = grpc.server(
    futures.ThreadPoolExecutor(max_workers=10),
    interceptors=[AuthInterceptor()]
)
```

---

## Remediation Priority

1. **Critical** (Immediate):
   - SCA-301: Fix broken object level authorization
   - SCA-302: Implement proper authentication
   - SCA-303: Prevent mass assignment and data exposure
   - SCA-308: Disable debug mode, fix CORS

2. **High** (Within 30 days):
   - SCA-304: Add rate limiting and pagination
   - SCA-305: Implement function-level authorization
   - SCA-307: SSRF protection (see network-security.md)

3. **Medium** (Within 90 days):
   - SCA-306: Business flow protection
   - SCA-309: API versioning and documentation
   - SCA-310: Third-party API validation

---

## References

- **OWASP API Security Top 10 (2023)**: https://owasp.org/API-Security/
- **NIST SP 800-204**: https://csrc.nist.gov/publications/detail/sp/800-204/final
- **REST Security Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html
- **GraphQL Security**: https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
