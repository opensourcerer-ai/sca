# Database Security Invariants — Unencrypted Sensitive Data (v1)

## Critical Principle
**Sensitive data in databases MUST be encrypted** both in transit (TLS) and at rest (TDE/column encryption). Databases are high-value targets and often compromised via SQL injection, stolen backups, or insider threats.

---

## CRITICAL: Unencrypted Database Connections

### Missing SSL/TLS in Connection Strings
Flag as **Critical** if database connection lacks encryption:

**PostgreSQL**:
```python
# CRITICAL: No SSL
conn = psycopg2.connect("host=db.example.com dbname=prod user=app password=secret")
conn = psycopg2.connect(host="db.example.com", sslmode="disable")

# ACCEPTABLE
conn = psycopg2.connect("host=db.example.com dbname=prod sslmode=require")
conn = psycopg2.connect(host="db.example.com", sslmode="verify-full")
```

**MySQL**:
```python
# CRITICAL: No SSL
conn = mysql.connector.connect(host="db.example.com", user="app", password="secret")
conn = mysql.connector.connect(host="db.example.com", ssl_disabled=True)

# ACCEPTABLE
conn = mysql.connector.connect(
    host="db.example.com",
    ssl_ca="/path/to/ca.pem",
    ssl_verify_cert=True
)
```

**MongoDB**:
```python
# CRITICAL: No TLS
client = MongoClient("mongodb://user:pass@db.example.com:27017/mydb")
client = MongoClient("mongodb://db.example.com", tls=False)

# ACCEPTABLE
client = MongoClient("mongodb://db.example.com", tls=True, tlsAllowInvalidCertificates=False)
```

**SQL Server**:
```csharp
// CRITICAL: Encryption disabled
string connString = "Server=db.example.com;Database=mydb;User Id=sa;Password=secret;Encrypt=False;";

// ACCEPTABLE
string connString = "Server=db.example.com;Database=mydb;User Id=sa;Password=secret;Encrypt=True;TrustServerCertificate=False;";
```

**Redis**:
```python
# CRITICAL: No TLS
redis_client = redis.Redis(host='cache.example.com', port=6379, password='secret')

# ACCEPTABLE (Redis 6+)
redis_client = redis.Redis(
    host='cache.example.com',
    port=6380,
    password='secret',
    ssl=True,
    ssl_cert_reqs='required'
)
```

### Detection Patterns
Search for connection strings with:
- `sslmode=disable` or `sslmode=allow` (PostgreSQL)
- `ssl_disabled=True` or `useSSL=false` (MySQL)
- `tls=False` or `ssl=False` (MongoDB, Redis)
- `Encrypt=False` or `Encrypt=No` (SQL Server)
- Missing `ssl_ca`, `ssl_cert`, `tls` parameters when connecting to remote hosts
- URLs starting with `mysql://`, `postgresql://` without `?sslmode=require`

### Exceptions (WARNING, not CRITICAL)
- **Localhost connections**: `host=localhost`, `host=127.0.0.1`, `host=::1`
- **Unix domain sockets**: `/var/run/postgresql/.s.PGSQL.5432`
- **Development environments** (if clearly marked): Config files named `dev.yml`, `local.py`

**Evidence Required**:
- File path + line number of connection code
- Connection string or parameters
- Hostname (remote vs localhost)
- Environment (production vs development)

---

## CRITICAL: Sensitive Data in Plaintext Columns

### Schema Analysis
Flag as **Critical** if database schema or ORM models define sensitive fields without encryption:

**SQL CREATE TABLE Statements**:
```sql
-- CRITICAL: Sensitive data not encrypted
CREATE TABLE users (
    id INT PRIMARY KEY,
    username VARCHAR(255),
    email VARCHAR(255),
    password VARCHAR(255),           -- Should be hashed (bcrypt/argon2), not encrypted
    credit_card_number VARCHAR(16),  -- CRITICAL: Must be encrypted
    ssn VARCHAR(11),                 -- CRITICAL: Must be encrypted
    api_key TEXT                     -- CRITICAL: Must be encrypted
);

-- ACCEPTABLE: Encrypted columns (example with PostgreSQL pgcrypto)
CREATE TABLE users (
    id INT PRIMARY KEY,
    username VARCHAR(255),
    email VARCHAR(255),
    password_hash VARCHAR(255),                    -- Hashed, not plaintext
    credit_card_encrypted BYTEA,                   -- Encrypted column
    ssn_encrypted BYTEA,                           -- Encrypted column
    api_key_encrypted BYTEA                        -- Encrypted column
);
```

**Django ORM Models**:
```python
# CRITICAL: Sensitive fields not encrypted
class User(models.Model):
    username = models.CharField(max_length=255)
    email = models.EmailField()
    password = models.CharField(max_length=255)      # Should use User.set_password()
    credit_card = models.CharField(max_length=16)    # CRITICAL: Plaintext
    ssn = models.CharField(max_length=11)            # CRITICAL: Plaintext
    api_key = models.TextField()                     # CRITICAL: Plaintext

# ACCEPTABLE: Using django-encrypted-model-fields or similar
from encrypted_model_fields.fields import EncryptedCharField

class User(models.Model):
    username = models.CharField(max_length=255)
    email = models.EmailField()
    password = models.CharField(max_length=255)      # Django handles hashing
    credit_card = EncryptedCharField(max_length=16)  # Encrypted
    ssn = EncryptedCharField(max_length=11)          # Encrypted
    api_key = EncryptedCharField()                   # Encrypted
```

**SQLAlchemy Models**:
```python
# CRITICAL: Plaintext sensitive fields
class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(255))
    email = Column(String(255))
    password = Column(String(255))              # Should be hashed
    credit_card_number = Column(String(16))     # CRITICAL: Plaintext
    ssn = Column(String(11))                    # CRITICAL: Plaintext
    api_secret = Column(Text)                   # CRITICAL: Plaintext

# ACCEPTABLE: Using sqlalchemy-utils encrypted types
from sqlalchemy_utils import EncryptedType
from sqlalchemy_utils.types.encrypted.encrypted_type import AesEngine

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(255))
    email = Column(String(255))
    password_hash = Column(String(255))         # Hashed
    credit_card_number = Column(EncryptedType(String, SECRET_KEY, AesEngine, 'pkcs5'))
    ssn = Column(EncryptedType(String, SECRET_KEY, AesEngine, 'pkcs5'))
    api_secret = Column(EncryptedType(Text, SECRET_KEY, AesEngine, 'pkcs5'))
```

**MongoDB Schema Validation**:
```javascript
// CRITICAL: No field-level encryption
db.createCollection("users", {
  validator: {
    $jsonSchema: {
      properties: {
        username: { type: "string" },
        email: { type: "string" },
        password: { type: "string" },           // Should be hashed
        creditCard: { type: "string" },         // CRITICAL: Plaintext
        ssn: { type: "string" },                // CRITICAL: Plaintext
        apiKey: { type: "string" }              // CRITICAL: Plaintext
      }
    }
  }
});

// ACCEPTABLE: MongoDB Client-Side Field Level Encryption
const encryptedFieldsMap = {
  "mydb.users": {
    fields: [
      {
        path: "creditCard",
        bsonType: "string",
        keyId: [UUID("...")]
      },
      {
        path: "ssn",
        bsonType: "string",
        keyId: [UUID("...")]
      }
    ]
  }
};
```

### Sensitive Field Name Patterns
Flag column/field names containing (case-insensitive):
- **Payment**: `credit_card`, `card_number`, `cvv`, `cvc`, `card_cvv`, `pan`, `payment_method`
- **Identity**: `ssn`, `social_security`, `tax_id`, `passport`, `drivers_license`, `national_id`
- **Auth**: `password` (should be hashed, not encrypted), `api_key`, `secret_key`, `access_token`, `refresh_token`, `private_key`
- **Health**: `medical_record`, `diagnosis`, `prescription`, `health_data`
- **Financial**: `bank_account`, `routing_number`, `iban`, `swift`, `account_number`
- **Biometric**: `fingerprint`, `face_data`, `retina_scan`, `biometric`

### Data Types That Suggest Plaintext
- `VARCHAR`, `TEXT`, `CHAR` for sensitive fields (not `BYTEA`, `VARBINARY`, `BLOB`)
- No encryption wrapper types (`EncryptedCharField`, `EncryptedType`, etc.)

**Evidence Required**:
- File path + line number of schema definition or ORM model
- Field/column name
- Data type
- Whether encryption is used

---

## WARNING: Suspected Unencrypted Sensitive Data

### Contextual Suspicion
Flag as **Warning** when:

1. **Generic field names that MAY contain sensitive data**:
```python
# WARNING: "notes" field may contain PII
class Patient(models.Model):
    name = models.CharField(max_length=255)
    notes = models.TextField()  # May contain diagnoses, prescriptions

# WARNING: "metadata" field may contain secrets
class User(models.Model):
    username = models.CharField(max_length=255)
    metadata = models.JSONField()  # Unknown contents
```

2. **Email addresses without explicitly stating encryption policy**:
```python
# WARNING: Email is PII under GDPR
class User(models.Model):
    email = models.EmailField()  # Should document if encrypted or why not
```

3. **Phone numbers**:
```python
# WARNING: Phone numbers are PII
class Contact(models.Model):
    phone = models.CharField(max_length=20)  # Should be encrypted or justify
```

4. **JSON/BLOB fields that may contain structured sensitive data**:
```sql
-- WARNING: JSONB may contain nested sensitive fields
CREATE TABLE audit_logs (
    id SERIAL PRIMARY KEY,
    event_data JSONB  -- Unknown contents, may have passwords, tokens
);
```

5. **IP addresses** (PII under GDPR):
```python
# WARNING: IP address is personal data
class Session(models.Model):
    ip_address = models.GenericIPAddressField()
```

### Recommendation for Warnings
```markdown
### Warning: Potential Sensitive Data in Unencrypted Field

**Evidence**: `models/user.py:15`
```python
class User(models.Model):
    phone = models.CharField(max_length=20)
```

**Risk**: Phone numbers are considered PII under GDPR and other privacy regulations. Storing in plaintext:
- Increases risk of privacy breach if database compromised
- May violate data protection regulations
- Complicates compliance with right to erasure

**Cannot Confirm**: Static analysis cannot determine if phone numbers are sensitive in your context (e.g., business phone vs personal).

**Severity**: Warning (potential compliance issue)

**Remediation**:
If phone numbers are personal:
```python
from encrypted_model_fields.fields import EncryptedCharField

class User(models.Model):
    phone = EncryptedCharField(max_length=20)
```

Or document why encryption is not required (e.g., "Business phone numbers only, not personal data").
```

---

## Database Encryption at Rest (TDE)

### Transparent Data Encryption (TDE)
Flag as **High** if production database lacks encryption at rest and contains sensitive data:

**PostgreSQL**:
- Check for `pgcrypto` extension usage or full-disk encryption
- Look for encrypted tablespaces

**MySQL**:
- Check for `ENCRYPTION='Y'` in CREATE TABLE or ALTER TABLE
- InnoDB encryption keyring configuration

**SQL Server**:
- Check for Transparent Data Encryption (TDE) enabled
- Certificate-based encryption configuration

**MongoDB**:
- Check for WiredTiger encryption at rest configuration
- Key management service integration

**AWS RDS/Aurora**:
- Check if encryption enabled in Terraform/CloudFormation
```hcl
# WARNING: RDS instance without encryption
resource "aws_db_instance" "default" {
  allocated_storage = 20
  engine            = "postgres"
  storage_encrypted = false  # Should be true
}

# ACCEPTABLE
resource "aws_db_instance" "default" {
  allocated_storage = 20
  engine            = "postgres"
  storage_encrypted = true
  kms_key_id        = aws_kms_key.db.arn
}
```

### Detection Patterns
Search Infrastructure-as-Code files:
- Terraform: `storage_encrypted = false`, missing `kms_key_id`
- CloudFormation: `StorageEncrypted: false`
- Kubernetes: Database StatefulSet without encrypted PersistentVolumes

**Evidence Required**:
- IaC file path + line number
- Database type and version
- Encryption configuration status

---

## Backup Encryption

### Unencrypted Backup Scripts
Flag as **High** if backup scripts don't encrypt output:

```bash
# CRITICAL: Unencrypted backup
pg_dump mydb > /backups/mydb.sql
mysqldump -u root -p mydb > /backups/mydb.sql

# ACCEPTABLE: Encrypted backup
pg_dump mydb | gpg --encrypt --recipient admin@example.com > /backups/mydb.sql.gpg
mysqldump -u root -p mydb | openssl enc -aes-256-cbc -salt -out /backups/mydb.sql.enc
```

```python
# CRITICAL: Unencrypted S3 upload
s3_client.upload_file('/tmp/backup.sql', 'my-bucket', 'backup.sql')

# ACCEPTABLE: S3 server-side encryption
s3_client.upload_file(
    '/tmp/backup.sql',
    'my-bucket',
    'backup.sql',
    ExtraArgs={'ServerSideEncryption': 'aws:kms', 'SSEKMSKeyId': key_id}
)
```

**Detection Patterns**:
- `pg_dump`, `mysqldump`, `mongodump` without encryption pipe
- S3/GCS upload without `ServerSideEncryption` or `sse-kms`
- rsync/scp without encrypted destination

---

## Query Analysis for Sensitive Data

### SELECT Queries Revealing Sensitive Columns
Flag as **Info** (for awareness) when queries select sensitive fields:

```python
# INFO: Query selects sensitive data - ensure results are handled securely
cursor.execute("SELECT username, email, credit_card_number FROM users WHERE id = %s", (user_id,))

# Recommendation: Only select needed fields
cursor.execute("SELECT username, email FROM users WHERE id = %s", (user_id,))
```

### INSERT/UPDATE with Plaintext Sensitive Data
Flag as **Critical** if inserting/updating sensitive data without encryption:

```python
# CRITICAL: Inserting plaintext credit card
cursor.execute(
    "INSERT INTO payments (user_id, credit_card) VALUES (%s, %s)",
    (user_id, credit_card_number)
)

# ACCEPTABLE: Application-level encryption before insert
encrypted_cc = encrypt_field(credit_card_number, encryption_key)
cursor.execute(
    "INSERT INTO payments (user_id, credit_card_encrypted) VALUES (%s, %s)",
    (user_id, encrypted_cc)
)
```

### Stored Procedures with Sensitive Data
```sql
-- CRITICAL: Stored procedure returns sensitive data in plaintext
CREATE PROCEDURE GetUserDetails(IN userId INT)
BEGIN
    SELECT username, email, password, ssn, credit_card
    FROM users
    WHERE id = userId;
END;

-- ACCEPTABLE: Stored procedure uses masking/encryption
CREATE PROCEDURE GetUserDetails(IN userId INT)
BEGIN
    SELECT
        username,
        email,
        password_hash,  -- Hashed, not plaintext
        CONCAT('***-**-', RIGHT(ssn, 4)) AS ssn_masked,
        CONCAT('****-****-****-', RIGHT(credit_card, 4)) AS cc_masked
    FROM users
    WHERE id = userId;
END;
```

---

## Compliance & Best Practices

### PCI-DSS Requirements
**Requirement 3**: Protect stored cardholder data
- **CRITICAL**: Full PAN (Primary Account Number) must be encrypted or tokenized
- **CRITICAL**: Never store CVV/CVC after authorization
- **CRITICAL**: Encryption keys must be stored separately from encrypted data

### HIPAA Requirements
**Security Rule**: Electronic Protected Health Information (ePHI)
- **CRITICAL**: Must encrypt ePHI at rest if not physically secured
- **CRITICAL**: Encryption keys must be managed securely
- Backup encryption required

### GDPR Requirements
**Article 32**: Security of processing
- Encryption of personal data recommended as security measure
- Pseudonymization + encryption for high-risk processing
- Must assess risk and implement appropriate safeguards

---

## Detection Methodology

### Static Analysis Steps
1. **Find database connections**: Search for `connect()`, `createConnection()`, database driver imports
2. **Check connection parameters**: Look for `ssl`, `tls`, `encrypt` parameters
3. **Find schema definitions**: SQL files, ORM models (Django, SQLAlchemy, Sequelize, etc.)
4. **Identify sensitive fields**: Match field names against sensitive patterns
5. **Check encryption**: Look for encrypted column types, application-level encryption
6. **Review IaC**: Terraform, CloudFormation for TDE, encryption at rest

### Runtime Testing
```python
# Test: Verify database connection uses TLS
import ssl
conn = psycopg2.connect(...)
assert conn.info.ssl_in_use  # PostgreSQL
assert conn.get_server_info()['ssl']  # MySQL

# Test: Verify field is encrypted
user = User.objects.get(id=1)
# Raw DB value should be encrypted (BYTEA/BLOB), not plaintext
cursor.execute("SELECT credit_card_encrypted FROM users WHERE id = 1")
raw_value = cursor.fetchone()[0]
assert isinstance(raw_value, bytes)  # Should be binary, not string
assert raw_value != user.credit_card  # Decrypted value != raw value
```

---

## Reporting Template

### Critical Finding Example
```markdown
### Critical: Credit Card Numbers Stored in Plaintext

**Evidence**: `models.py:25-30`
```python
class Payment(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    credit_card_number = models.CharField(max_length=16)  # PLAINTEXT
    cvv = models.CharField(max_length=4)                   # PLAINTEXT
    expiry_date = models.CharField(max_length=5)
```

**Database Schema**: Table `payments`, columns `credit_card_number`, `cvv`

**Impact**:
- 10,000+ credit card numbers stored in plaintext
- Database backups contain unencrypted PANs
- Any attacker with database access gains full card details
- **PCI-DSS violation**: Requirement 3.4 mandates encryption

**Severity**: Critical - Payment card data breach

**Compliance Violations**:
- PCI-DSS Requirement 3.4 (Render PAN unreadable)
- PCI-DSS Requirement 3.2 (Do not store CVV after authorization)
- CWE-311 (Missing Encryption of Sensitive Data)
- CWE-312 (Cleartext Storage of Sensitive Information)

**Remediation**:
1. **IMMEDIATE**: Stop storing CVV (PCI-DSS violation, must delete)
2. **HIGH PRIORITY**: Encrypt existing credit card data
3. **RECOMMENDED**: Use tokenization service (Stripe, Braintree) instead of storing cards

```python
from encrypted_model_fields.fields import EncryptedCharField

class Payment(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    # Option 1: Encrypt in database
    credit_card_number = EncryptedCharField(max_length=16)
    # Option 2: Tokenize (better)
    payment_token = models.CharField(max_length=255)  # Token from payment processor
    # NEVER store CVV
    expiry_date = models.CharField(max_length=5)
```

4. Migrate existing data:
```python
# Encrypt existing plaintext cards
for payment in Payment.objects.all():
    # Encrypt using field-level encryption
    payment.save()  # EncryptedCharField handles encryption
```

**Additional Actions**:
- Notify payment processor of potential breach
- Consider PCI forensic investigation
- Review compliance status (may affect merchant account)
```

---

## Encryption Key Management

### Key Storage (CRITICAL)
Flag as **Critical** if encryption keys stored insecurely:

```python
# CRITICAL: Encryption key hardcoded
ENCRYPTION_KEY = "mysecretkey12345"

# CRITICAL: Key in config file
config.yml:
  encryption_key: "base64encodedkey=="

# ACCEPTABLE: Key from KMS
import boto3
kms = boto3.client('kms')
response = kms.decrypt(CiphertextBlob=encrypted_key)
ENCRYPTION_KEY = response['Plaintext']

# ACCEPTABLE: Key from environment variable (sourced from secrets manager)
ENCRYPTION_KEY = os.environ['DB_ENCRYPTION_KEY']  # Injected by secrets manager
```

### Key Rotation
Flag as **High** if no key rotation mechanism:

```python
# WARNING: No key rotation support
class User(models.Model):
    ssn = EncryptedCharField(max_length=11)  # What if key is compromised?

# ACCEPTABLE: Multiple key versions
class User(models.Model):
    ssn = EncryptedCharField(max_length=11)
    encryption_key_version = models.IntegerField(default=1)
```

---

## Testing Checklist

### Database Security Audit
- [ ] All production database connections use TLS
- [ ] Certificate validation enabled (not `InsecureSkipVerify`)
- [ ] Sensitive fields encrypted at application or database level
- [ ] Encryption keys stored in KMS/HSM, not hardcoded
- [ ] TDE enabled for databases at rest
- [ ] Backups encrypted
- [ ] No CVV/CVV2 stored (PCI-DSS)
- [ ] Access to unencrypted data logged and restricted
- [ ] Key rotation policy documented and tested
