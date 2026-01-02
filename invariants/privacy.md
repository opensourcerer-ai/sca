# Privacy and Data Protection Security Invariants (v1)

## Overview

This file defines security invariants for privacy, personally identifiable information (PII), and data protection aligned with:
- **NIST SP 800-53 Rev 5**: PT (Privacy Controls) family
- **NIST Privacy Framework**: Core functions (Identify-P, Govern-P, Control-P, Communicate-P, Protect-P)
- **GDPR**: EU General Data Protection Regulation (Articles 5-47)
- **CCPA/CPRA**: California Consumer Privacy Act
- **HIPAA**: Health Insurance Portability and Accountability Act (§ 164.502, 164.524)
- **ISO/IEC 27701**: Privacy Information Management

**SCA Identifier Range**: SCA-200 to SCA-299

---

## CRITICAL: PII Collection Without Consent (SCA-201, GDPR Art. 6, NIST PT-2)

**Standard**: SCA-201, GDPR Article 6 (Lawfulness), NIST SP 800-53 PT-2, CCPA § 1798.100

**Finding**: Collecting personally identifiable information without user consent or legal basis

**Detection Patterns**:

### Python
```python
# CRITICAL: No consent mechanism
def create_user_account(email, name, phone, address, ssn):
    """Collects PII without consent"""
    user = User(
        email=email,
        name=name,
        phone=phone,
        address=address,
        ssn=ssn  # CRITICAL: Sensitive PII without consent
    )
    db.session.add(user)
    db.session.commit()

# CRITICAL: Implicit consent (not explicit)
@app.route('/signup', methods=['POST'])
def signup():
    # No checkbox for consent, just collects data
    user = User(**request.form)
    save_user(user)
```

### JavaScript
```javascript
// CRITICAL: Tracking without consent
function trackUser() {
  // No consent banner or opt-in
  analytics.track({
    userId: getUserId(),
    email: getEmail(),
    location: getGeolocation(),  // PII
    browsing_history: getBrowsingHistory()
  });
}
```

**GDPR Requirements** (Article 6 - Legal Basis):
1. **Consent**: Freely given, specific, informed, unambiguous
2. **Contract**: Necessary for contract performance
3. **Legal Obligation**: Required by law
4. **Vital Interests**: Protect life
5. **Public Task**: Exercise of official authority
6. **Legitimate Interests**: Balancing test (not for public authorities)

**Remediation**:

```python
# GOOD: Explicit consent with granular control
from datetime import datetime
from enum import Enum

class ConsentPurpose(Enum):
    ESSENTIAL_SERVICES = "essential_services"  # Required for service
    ANALYTICS = "analytics"  # Optional
    MARKETING = "marketing"  # Optional
    THIRD_PARTY_SHARING = "third_party_sharing"  # Optional

class UserConsent(db.Model):
    """Track user consent per purpose"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    purpose = db.Column(db.Enum(ConsentPurpose))
    consented = db.Column(db.Boolean, default=False)
    consent_date = db.Column(db.DateTime)
    withdrawal_date = db.Column(db.DateTime, nullable=True)
    consent_method = db.Column(db.String(50))  # 'explicit_checkbox', 'opt_in_email', etc.
    ip_address = db.Column(db.String(45))  # Evidence of consent

@app.route('/signup', methods=['POST'])
def signup_with_consent():
    """User signup with explicit consent"""
    # Essential data collection (legal basis: contract performance)
    user = User(
        email=request.form['email'],
        name=request.form['name']
    )
    db.session.add(user)
    db.session.commit()

    # Record consent for each purpose
    consent_purposes = {
        ConsentPurpose.ESSENTIAL_SERVICES: True,  # Always true for signup
        ConsentPurpose.ANALYTICS: request.form.get('consent_analytics') == 'on',
        ConsentPurpose.MARKETING: request.form.get('consent_marketing') == 'on',
        ConsentPurpose.THIRD_PARTY_SHARING: request.form.get('consent_third_party') == 'on',
    }

    for purpose, consented in consent_purposes.items():
        consent = UserConsent(
            user_id=user.id,
            purpose=purpose,
            consented=consented,
            consent_date=datetime.utcnow() if consented else None,
            consent_method='explicit_checkbox',
            ip_address=request.remote_addr
        )
        db.session.add(consent)

    db.session.commit()

    # Audit log
    audit_log('USER_CONSENT_RECORDED', user_id=user.id, consents=consent_purposes)

    return jsonify({'status': 'created', 'user_id': user.id})

# Consent verification before processing
def can_use_pii_for_purpose(user_id: int, purpose: ConsentPurpose) -> bool:
    """Check if user consented to this purpose"""
    consent = UserConsent.query.filter_by(
        user_id=user_id,
        purpose=purpose,
        consented=True
    ).filter(
        UserConsent.withdrawal_date.is_(None)
    ).first()

    return consent is not None

# Before analytics
if can_use_pii_for_purpose(current_user.id, ConsentPurpose.ANALYTICS):
    track_analytics(current_user)
```

**NIST Controls**: PT-2 - Authority to Process PII, PT-3 - PII Processing Purposes

**GDPR Penalties**: Up to €20 million or 4% of global annual turnover

---

## CRITICAL: Data Minimization Violation (SCA-202, GDPR Art. 5, NIST PT-3)

**Standard**: SCA-202, GDPR Article 5(1)(c) (Data Minimization), NIST SP 800-53 PT-3

**Finding**: Collecting more PII than necessary for stated purpose

**Detection Patterns**:

### Python
```python
# CRITICAL: Excessive data collection
class UserProfile(db.Model):
    email = db.Column(db.String(120), nullable=False)
    name = db.Column(db.String(100))

    # CRITICAL: Why collect all this for a newsletter signup?
    date_of_birth = db.Column(db.Date)  # Not needed
    ssn = db.Column(db.String(11))  # Not needed
    passport_number = db.Column(db.String(20))  # Not needed
    medical_history = db.Column(db.Text)  # Not needed
    political_affiliation = db.Column(db.String(50))  # Special category data!
    religious_beliefs = db.Column(db.String(50))  # Special category data!

# CRITICAL: Collecting data "just in case"
def register_for_newsletter(email, name, phone, address, employer, salary):
    # Only email needed for newsletter, rest is excessive
    subscriber = NewsletterSubscriber(**locals())
    save(subscriber)
```

**GDPR Principles** (Article 5):
- **Lawfulness, fairness, transparency**
- **Purpose limitation**: Collected for specified, explicit, legitimate purposes
- **Data minimization**: Adequate, relevant, limited to what is necessary
- **Accuracy**: Kept accurate and up to date
- **Storage limitation**: Kept only as long as necessary
- **Integrity and confidentiality**: Secure processing

**Remediation**:

```python
# GOOD: Minimal data collection
class NewsletterSubscriber(db.Model):
    """Only collect data necessary for newsletter"""
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    # Optional: first name for personalization
    first_name = db.Column(db.String(50), nullable=True)
    subscribed_at = db.Column(db.DateTime, default=datetime.utcnow)
    consent_date = db.Column(db.DateTime, nullable=False)
    # No DOB, SSN, address, etc. - not needed!

# Data Minimization Checklist
def data_minimization_review():
    """Review all PII fields against necessity"""
    required_checks = [
        "Is this field necessary for the stated purpose?",
        "Can we achieve the purpose without this field?",
        "Is there a less invasive alternative?",
        "How long do we need to retain this data?",
        "Can we anonymize or pseudonymize this data?"
    ]
    return required_checks
```

**NIST Controls**: PT-3 - PII Processing Purposes, PM-25 - Minimization of PII

---

## HIGH: Missing Privacy Notice (SCA-203, GDPR Art. 13-14, NIST PT-5)

**Standard**: SCA-203, GDPR Articles 13-14 (Information to Data Subject), NIST SP 800-53 PT-5, CCPA § 1798.100

**Finding**: No privacy notice informing users how their PII is processed

**Detection**: Look for absence of privacy policy, cookie banner, or data processing disclosures

**GDPR Requirements** (Article 13 - Minimum Disclosures):
1. Identity and contact details of controller
2. Contact details of data protection officer (if applicable)
3. Purposes and legal basis for processing
4. Legitimate interests (if applicable)
5. Recipients or categories of recipients
6. Intention to transfer data to third countries
7. Retention period
8. Rights: access, rectification, erasure, restriction, objection, portability
9. Right to withdraw consent
10. Right to lodge complaint with supervisory authority
11. Whether providing PII is statutory/contractual requirement
12. Existence of automated decision-making (including profiling)

**Remediation**:

```python
# GOOD: Privacy notice template
PRIVACY_NOTICE = """
# Privacy Notice

## Data Controller
Company Name: Acme Corp
Address: 123 Main St, City, Country
Email: privacy@acme.com
DPO: dpo@acme.com

## Data We Collect
- **Account Information**: Email, name (legal basis: contract performance)
- **Usage Data**: IP address, browsing history (legal basis: legitimate interests)
- **Marketing Data**: Email, preferences (legal basis: consent)

## Purpose of Processing
1. Provide and maintain our service (contractual necessity)
2. Improve our service through analytics (legitimate interests)
3. Send promotional emails (consent - you can opt out anytime)

## Data Recipients
- Cloud hosting provider (AWS) for data storage
- Email service provider (SendGrid) for transactional emails
- Analytics provider (Google Analytics) - pseudonymized data only

## Data Retention
- Account data: Retained while account is active, deleted 30 days after account closure
- Analytics data: Anonymized after 14 months
- Marketing data: Deleted immediately upon opt-out

## Your Rights (GDPR)
You have the right to:
- **Access**: Request a copy of your personal data
- **Rectification**: Correct inaccurate data
- **Erasure**: Request deletion (\"right to be forgotten\")
- **Restriction**: Limit how we process your data
- **Portability**: Receive your data in machine-readable format
- **Object**: Object to processing based on legitimate interests
- **Withdraw Consent**: For consent-based processing
- **Lodge Complaint**: With your local data protection authority

To exercise your rights, contact: privacy@acme.com

## International Transfers
Your data may be transferred to the United States. We use Standard Contractual Clauses
(SCCs) approved by the European Commission to ensure adequate protection.

## Automated Decision-Making
We do not use automated decision-making or profiling that produces legal effects.

Last Updated: 2024-01-15
"""

@app.route('/privacy-policy')
def privacy_policy():
    """Display privacy notice"""
    return render_template('privacy_policy.html', notice=PRIVACY_NOTICE)

# Cookie consent banner
@app.route('/')
def index():
    if not request.cookies.get('cookie_consent'):
        return render_template('index.html', show_cookie_banner=True)
    return render_template('index.html')
```

**NIST Controls**: PT-5 - Privacy Notice, TR-1 - Privacy Notice

**GDPR Penalties**: Up to €20 million or 4% of global annual turnover

---

## HIGH: No Data Subject Rights Implementation (SCA-204, GDPR Art. 15-22, NIST PT-7)

**Standard**: SCA-204, GDPR Articles 15-22 (Data Subject Rights), NIST SP 800-53 PT-7, CCPA § 1798.105

**Finding**: No mechanism for users to exercise privacy rights (access, erasure, portability)

**GDPR Data Subject Rights**:
- **Right to Access** (Art. 15): Copy of personal data
- **Right to Rectification** (Art. 16): Correct inaccurate data
- **Right to Erasure** (Art. 17): "Right to be forgotten"
- **Right to Restriction** (Art. 18): Limit processing
- **Right to Data Portability** (Art. 20): Machine-readable format
- **Right to Object** (Art. 21): Object to processing

**Remediation**:

```python
# GOOD: Implement all GDPR rights
from io import BytesIO
import json

class DataSubjectRightsController:
    """Handle GDPR data subject rights requests"""

    @staticmethod
    def export_user_data(user_id: int) -> dict:
        """Right to Access (GDPR Art. 15) - Export all user data"""
        user = User.query.get_or_404(user_id)

        # Collect all user data from all tables
        user_data = {
            'account': {
                'email': user.email,
                'name': user.name,
                'created_at': user.created_at.isoformat(),
            },
            'profile': user.profile.to_dict() if user.profile else None,
            'orders': [order.to_dict() for order in user.orders],
            'addresses': [addr.to_dict() for addr in user.addresses],
            'consent_records': [c.to_dict() for c in user.consents],
            'login_history': [login.to_dict() for login in user.login_history[-50:]],  # Last 50
        }

        # Audit log
        audit_log('DATA_EXPORT_REQUESTED', user_id=user_id)

        return user_data

    @staticmethod
    def export_as_json(user_id: int) -> BytesIO:
        """Right to Data Portability (GDPR Art. 20) - Machine-readable format"""
        data = DataSubjectRightsController.export_user_data(user_id)

        json_str = json.dumps(data, indent=2, ensure_ascii=False)
        buffer = BytesIO(json_str.encode('utf-8'))
        buffer.seek(0)

        return buffer

    @staticmethod
    def delete_user_data(user_id: int, reason: str = None):
        """Right to Erasure (GDPR Art. 17) - \"Right to be forgotten\""""
        user = User.query.get_or_404(user_id)

        # Check if deletion can be refused
        # (e.g., legal obligation to retain data, ongoing contract)
        if user.has_active_subscription():
            raise ValueError("Cannot delete data while subscription is active")

        if user.has_pending_legal_claims():
            raise ValueError("Cannot delete data due to legal claims")

        # Audit log BEFORE deletion
        audit_log('DATA_DELETION_REQUESTED', user_id=user_id, reason=reason,
                  user_email=user.email, user_name=user.name)

        # Delete or anonymize data
        # Strategy 1: Hard delete (if legally permissible)
        db.session.delete(user.profile)
        for order in user.orders:
            order.user_id = None  # Anonymize instead of delete (for financial records)
            order.customer_email = '[deleted]'

        db.session.delete(user)

        # Strategy 2: Soft delete (mark as deleted)
        # user.deleted_at = datetime.utcnow()
        # user.email = f'deleted_{user.id}@deleted.local'
        # user.name = '[Deleted User]'

        db.session.commit()

        # Send confirmation email (if possible)
        send_deletion_confirmation(user.email)

@app.route('/api/privacy/export-data', methods=['POST'])
@login_required
def export_my_data():
    """User requests data export"""
    buffer = DataSubjectRightsController.export_as_json(current_user.id)

    return send_file(
        buffer,
        mimetype='application/json',
        as_attachment=True,
        download_name=f'user_data_{current_user.id}_{datetime.utcnow().strftime("%Y%m%d")}.json'
    )

@app.route('/api/privacy/delete-account', methods=['POST'])
@login_required
def delete_my_account():
    """User requests account deletion"""
    # Require re-authentication for sensitive operation
    if not verify_password(request.form['password']):
        abort(401, "Password verification failed")

    reason = request.form.get('reason', 'User requested deletion')

    try:
        DataSubjectRightsController.delete_user_data(current_user.id, reason)
        return jsonify({'status': 'Account deleted successfully'})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/privacy/update-data', methods=['PATCH'])
@login_required
def rectify_my_data():
    """Right to Rectification (GDPR Art. 16)"""
    allowed_fields = {'name', 'email', 'phone', 'address'}

    for field, value in request.json.items():
        if field in allowed_fields:
            setattr(current_user, field, value)

    db.session.commit()
    audit_log('DATA_RECTIFICATION', user_id=current_user.id, fields=list(request.json.keys()))

    return jsonify({'status': 'Data updated'})
```

**NIST Controls**: PT-7 - Redress, PT-8 - Computer Matching Requirements

**Response Time**: GDPR requires response within **1 month** (extendable by 2 months if complex)

---

## MEDIUM: Inadequate Data Retention (SCA-205, GDPR Art. 5, NIST PT-3)

**Standard**: SCA-205, GDPR Article 5(1)(e) (Storage Limitation), NIST SP 800-53 PT-3, PT-6

**Finding**: PII retained longer than necessary for processing purposes

**Detection Patterns**:

```python
# MEDIUM: No retention policy
class User(db.Model):
    # Data kept forever, even after account deletion
    email = db.Column(db.String(120))
    created_at = db.Column(db.DateTime)
    # No deleted_at or retention_until fields

# MEDIUM: Indefinite log retention
def log_user_action(user_id, action):
    # Logs kept forever
    log_entry = ActivityLog(user_id=user_id, action=action)
    db.session.add(log_entry)
```

**Remediation**:

```python
# GOOD: Data retention policy
class DataRetentionPolicy:
    """Define retention periods per data type"""

    RETENTION_PERIODS = {
        'account_data': timedelta(days=30),  # 30 days after account deletion
        'analytics_data': timedelta(days=425),  # 14 months (GDPR recommendation)
        'marketing_data': timedelta(days=0),  # Delete immediately on opt-out
        'financial_records': timedelta(days=2555),  # 7 years (legal requirement)
        'audit_logs': timedelta(days=2190),  # 6 years
        'session_data': timedelta(hours=24),
    }

    @staticmethod
    def schedule_deletion(data_type: str, data_id: int):
        """Schedule data for automatic deletion"""
        retention_period = DataRetentionPolicy.RETENTION_PERIODS.get(data_type)
        if not retention_period:
            raise ValueError(f"Unknown data type: {data_type}")

        delete_after = datetime.utcnow() + retention_period

        deletion_job = ScheduledDeletion(
            data_type=data_type,
            data_id=data_id,
            delete_after=delete_after
        )
        db.session.add(deletion_job)
        db.session.commit()

# Automatic deletion job
def cleanup_expired_data():
    """Run daily to delete expired data"""
    now = datetime.utcnow()

    # Find expired deletions
    expired = ScheduledDeletion.query.filter(
        ScheduledDeletion.delete_after <= now,
        ScheduledDeletion.deleted_at.is_(None)
    ).all()

    for item in expired:
        # Delete based on data type
        if item.data_type == 'account_data':
            user = User.query.get(item.data_id)
            if user:
                db.session.delete(user)

        elif item.data_type == 'analytics_data':
            analytics = AnalyticsEvent.query.filter(
                AnalyticsEvent.created_at < now - timedelta(days=425)
            ).delete()

        # Mark as deleted
        item.deleted_at = now
        db.session.commit()

        audit_log('AUTOMATIC_DATA_DELETION', data_type=item.data_type, data_id=item.data_id)

# Schedule cleanup job
from apscheduler.schedulers.background import BackgroundScheduler
scheduler = BackgroundScheduler()
scheduler.add_job(cleanup_expired_data, 'cron', hour=2)  # Run at 2 AM daily
scheduler.start()
```

**NIST Controls**: PT-3 - PII Processing Purposes, PT-6 - System of Records Notice

---

## MEDIUM: Insecure Cross-Border Data Transfers (SCA-206, GDPR Art. 44-50)

**Standard**: SCA-206, GDPR Chapter V (Transfers to Third Countries), NIST SP 800-53 AC-4

**Finding**: Transferring PII to countries without adequate data protection

**GDPR Requirements** for international transfers:
- **Adequacy Decision** (Art. 45): EU Commission approves country as safe
- **Appropriate Safeguards** (Art. 46): Standard Contractual Clauses (SCCs), Binding Corporate Rules (BCRs)
- **Derogations** (Art. 49): Explicit consent, contract necessity, public interest

**Detection Patterns**:

```python
# MEDIUM: Transfer to US without safeguards
def store_user_data(user):
    # CRITICAL: Sending EU citizen data to US without SCCs
    aws_client = boto3.client('s3', region_name='us-east-1')
    aws_client.put_object(Bucket='user-data', Key=f'user_{user.id}.json', Body=user.to_json())

# MEDIUM: Third-party API in non-adequate country
def send_marketing_email(user):
    # Sending to US-based email provider without safeguards
    sendgrid_api.send(to=user.email, subject='Promo', body='...')
```

**Remediation**:

```python
# GOOD: Use EU region with appropriate safeguards
class GDPRCompliantDataStorage:
    """Store data in EU or with appropriate safeguards"""

    # EU regions (GDPR-compliant by default)
    EU_REGIONS = {'eu-west-1', 'eu-central-1', 'eu-north-1'}

    # Countries with adequacy decision
    ADEQUATE_COUNTRIES = {
        'GB', 'CH', 'CA', 'JP', 'KR', 'NZ', 'AR', 'UY'
        # Note: EU-US Data Privacy Framework (2023) provides adequacy for US companies
    }

    def __init__(self):
        # Use EU region by default
        self.s3_client = boto3.client('s3', region_name='eu-central-1')

    def store_user_data(self, user):
        """Store in EU region"""
        # Encrypt before storage
        encrypted_data = encrypt_pii(user.to_json())

        self.s3_client.put_object(
            Bucket='user-data-eu',
            Key=f'user_{user.id}.json',
            Body=encrypted_data,
            ServerSideEncryption='AES256'
        )

        audit_log('DATA_STORED', user_id=user.id, region='eu-central-1')

# Standard Contractual Clauses (SCCs)
SCC_TEMPLATE = """
STANDARD CONTRACTUAL CLAUSES (EU Commission Decision C(2021) 3972)

Data Exporter: [Your Company]
Data Importer: [Third-Party Processor]

CLAUSE 1: PURPOSE AND SCOPE
These Clauses apply to the transfer of personal data as specified in Annex I.

CLAUSE 2: EFFECT AND INVARIABILITY OF THE CLAUSES
(a) These Clauses set out appropriate safeguards pursuant to Article 46(1) and (2)(c) GDPR.

[... Full SCCs text ...]

ANNEX I - LIST OF PARTIES
Data exporter: [Company details]
Data importer: AWS, SendGrid, etc.

ANNEX II - DESCRIPTION OF TRANSFER
Categories of data: Email, name, usage data
Purpose: Email delivery, cloud hosting
"""

# Document third-party transfers
THIRD_PARTY_PROCESSORS = {
    'aws': {
        'name': 'Amazon Web Services',
        'country': 'US',
        'safeguards': 'Standard Contractual Clauses (2021)',
        'dpa_signed': '2024-01-15',
        'purpose': 'Cloud hosting'
    },
    'sendgrid': {
        'name': 'SendGrid (Twilio)',
        'country': 'US',
        'safeguards': 'EU-US Data Privacy Framework',
        'dpa_signed': '2024-01-10',
        'purpose': 'Email delivery'
    }
}
```

**NIST Controls**: AC-4 - Information Flow Enforcement, SC-7 - Boundary Protection

---

## Summary Table

| Finding | Severity | Standard | NIST Control | Remediation Priority |
|---------|----------|----------|--------------|---------------------|
| PII collection without consent | Critical | SCA-201, GDPR Art. 6 | PT-2 | Immediate |
| Data minimization violation | Critical | SCA-202, GDPR Art. 5(c) | PT-3, PM-25 | Immediate |
| Missing privacy notice | High | SCA-203, GDPR Art. 13-14 | PT-5, TR-1 | High |
| No data subject rights | High | SCA-204, GDPR Art. 15-22 | PT-7, PT-8 | High |
| Inadequate data retention | Medium | SCA-205, GDPR Art. 5(e) | PT-3, PT-6 | Medium |
| Insecure cross-border transfers | Medium | SCA-206, GDPR Art. 44-50 | AC-4, SC-7 | Medium |

---

## Compliance Mapping

### NIST SP 800-53 Rev 5 (Privacy Controls)
- **PT-2**: Authority to Process PII
- **PT-3**: PII Processing Purposes
- **PT-5**: Privacy Notice
- **PT-6**: System of Records Notice
- **PT-7**: Redress
- **PT-8**: Computer Matching Requirements
- **PM-25**: Minimization of PII
- **TR-1**: Privacy Notice

### GDPR (EU General Data Protection Regulation)
- **Article 5**: Principles (lawfulness, minimization, accuracy, storage limitation)
- **Article 6**: Lawfulness of processing
- **Article 13-14**: Information to data subject
- **Article 15-22**: Data subject rights
- **Article 44-50**: Transfers to third countries

### CCPA/CPRA (California)
- **§ 1798.100**: Right to know
- **§ 1798.105**: Right to delete
- **§ 1798.110**: Right to access
- **§ 1798.115**: Right to know about disclosures

### HIPAA (Healthcare)
- **§ 164.502**: Uses and disclosures of PHI
- **§ 164.524**: Access to PHI
- **§ 164.526**: Amendment of PHI

---

## Testing

### Automated Checks
```bash
# Check for consent mechanisms
git grep -E "consent|gdpr_consent|cookie_consent"

# Check for privacy policy
git grep -iE "privacy.policy|privacy_notice"

# Check for data export functionality
git grep -iE "export.*data|data.*portability|download.*data"

# Check for data deletion
git grep -iE "delete.*account|right.*forgotten|erasure"
```

### Manual Review
1. Review data collection forms for consent checkboxes
2. Verify privacy notice completeness
3. Test data export functionality
4. Test account deletion process
5. Review data retention policies
6. Verify cross-border transfer safeguards

### Compliance Testing
```python
# GDPR compliance checklist
def gdpr_compliance_audit():
    checks = {
        'lawful_basis_documented': False,
        'privacy_notice_published': False,
        'consent_mechanism_implemented': False,
        'data_export_functionality': False,
        'data_deletion_functionality': False,
        'retention_policy_defined': False,
        'dpo_appointed': False,  # If > 250 employees or special category data
        'dpia_conducted': False,  # If high risk processing
        'breach_notification_procedure': False,
    }

    # Verify each check
    # ...

    return checks
```
