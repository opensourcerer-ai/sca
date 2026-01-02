# In-Repository AI Agent Security Invariants (v1)

## Overview

This file defines security invariants for AI agents, prompts, configurations, and model files that reside within source code repositories.

**Scope**: Agent code, prompts, configs, model files, deployment manifests

**Standards Aligned**:
- **NIST AI RMF**: GOVERN, MAP, MEASURE, MANAGE
- **OWASP LLM Top 10**: LLM01 (Prompt Injection), LLM03 (Training Data Poisoning), LLM05 (Supply Chain)
- **NIST SP 800-53**: CM-3 (Configuration Management), SA-10 (Developer Configuration Management)
- **ISO/IEC 42001**: AI Management System

**SCA Identifier Range**: SCA-1009 to SCA-1099

---

## CRITICAL: Hardcoded Secrets in Prompt Files (SCA-1009, CWE-798)

**Standard**: SCA-1009, CWE-798 (Use of Hard-coded Credentials), OWASP LLM-05

**Finding**: System prompts or agent configurations containing API keys, passwords, or credentials

**Detection Patterns**:

### Prompt Files (.txt, .md, .prompt)
```markdown
# CRITICAL: API key in system prompt
You are a helpful assistant with access to the following tools:

- weather_api: Use API key sk_live_abc123xyz to call https://api.weather.com
- database: Connect to postgresql://admin:password123@db.internal.com/prod

When the user asks about weather, use the weather API.
```

### Agent Config Files (.yaml, .json)
```yaml
# CRITICAL: Credentials in agent config
agent:
  name: "CustomerSupportBot"
  model: "gpt-4"
  tools:
    - name: "database_query"
      config:
        host: "prod-db.internal.com"
        user: "admin"
        password: "SuperSecret123"  # CRITICAL
        database: "customers"

    - name: "sendgrid_email"
      api_key: "SG.abc123def456"  # CRITICAL
```

### Python Agent Scripts
```python
# CRITICAL: Hardcoded API key in agent tool
class WeatherTool:
    def __init__(self):
        # CRITICAL: Hardcoded
        self.api_key = "sk_weather_abc123xyz"

    def get_weather(self, location):
        response = requests.get(
            "https://api.weather.com/forecast",
            headers={"Authorization": f"Bearer {self.api_key}"}
        )
        return response.json()
```

**Remediation**:

```markdown
# GOOD: No credentials in system prompt
You are a helpful assistant with access to the following tools:

- weather_api: Calls the weather service (credentials managed securely)
- database: Queries the customer database (uses OAuth2 with scoped permissions)

When the user asks about weather, use the weather API tool.
```

```yaml
# GOOD: Environment variables for credentials
agent:
  name: "CustomerSupportBot"
  model: "gpt-4"
  tools:
    - name: "database_query"
      config:
        host: "${DB_HOST}"
        user: "${DB_USER}"
        password: "${DB_PASSWORD}"  # From environment
        database: "customers"

    - name: "sendgrid_email"
      api_key: "${SENDGRID_API_KEY}"  # From environment
```

```python
# GOOD: Credentials from environment
import os

class WeatherTool:
    def __init__(self):
        self.api_key = os.environ.get('WEATHER_API_KEY')
        if not self.api_key:
            raise ValueError("WEATHER_API_KEY environment variable not set")
```

**NIST Controls**: IA-5(7) - No embedded unencrypted static authenticators, CM-3 - Configuration change control

---

## CRITICAL: Overly Permissive Agent Instructions (SCA-1010, OWASP LLM-08)

**Standard**: SCA-1010, OWASP LLM-08 (Excessive Agency), NIST AI RMF MANAGE-1.1

**Finding**: System prompts granting agent unrestricted access or dangerous capabilities

**Detection Patterns**:

### Prompt Files
```markdown
# CRITICAL: Overly permissive
You are an autonomous agent with FULL ACCESS to the system. You can:

- Execute ANY shell command without restriction
- Read, write, or delete ANY file on the filesystem
- Make ANY API call to ANY service
- Modify ANY database table
- Send emails to ANY recipient

You should take initiative and complete tasks without asking for permission.
```

### Agent Config
```yaml
# CRITICAL: No restrictions
agent:
  autonomy_level: "full"  # CRITICAL: Unrestricted
  require_approval: false  # CRITICAL: No human oversight
  tools:
    - name: "shell_executor"
      allowed_commands: "*"  # CRITICAL: Any command
    - name: "file_manager"
      allowed_paths: "/"  # CRITICAL: Root access
    - name: "database"
      allowed_operations: ["SELECT", "INSERT", "UPDATE", "DELETE", "DROP"]  # CRITICAL: DROP
```

**Remediation**:

```markdown
# GOOD: Restricted with safety guidelines
You are a customer support assistant with LIMITED capabilities:

ALLOWED ACTIONS:
- Search the knowledge base for answers
- Create support tickets (requires user approval)
- Send templated email responses (only from approved templates)

SAFETY GUIDELINES:
- NEVER execute system commands
- NEVER access user passwords or payment information
- NEVER make changes to the database without explicit user confirmation
- ALWAYS ask for clarification before destructive operations
- If unsure, escalate to human support agent

RESTRICTED: You cannot delete data, execute code, or access admin functions.
```

```yaml
# GOOD: Capability-based restrictions
agent:
  autonomy_level: "supervised"  # Requires approval for critical operations
  require_approval: true
  approval_required_for:
    - "database_write"
    - "file_delete"
    - "email_send"
    - "api_call_external"

  tools:
    - name: "knowledge_base"
      allowed_operations: ["search", "read"]  # Read-only

    - name: "ticket_system"
      allowed_operations: ["create", "read", "update"]  # No delete
      require_approval: true

    - name: "file_manager"
      allowed_paths:
        - "/app/data/documents"
        - "/app/data/uploads"
      forbidden_paths:
        - "/etc"
        - "/var/secrets"
        - "/"
      allowed_operations: ["read"]  # No write/delete
```

**NIST Controls**: AC-3 - Access Enforcement, AC-6 - Least Privilege, AI RMF MANAGE-1.1

---

## HIGH: PII or Sensitive Data in Prompts (SCA-1011, GDPR Art. 5)

**Standard**: SCA-1011, GDPR Article 5 (Principles), CWE-200 (Exposure of Sensitive Information)

**Finding**: Example prompts, test data, or few-shot examples containing real PII

**Detection Patterns**:

### Prompt Files with Examples
```markdown
# HIGH: Real PII in examples
You are a customer service agent. Here are example conversations:

Example 1:
User: What's my account balance?
Assistant: Let me check... Your account (email: john.smith@email.com, SSN: 123-45-6789) has a balance of $5,432.10

Example 2:
User: Update my address
Assistant: I've updated your address to 742 Evergreen Terrace, Springfield, IL 62701. Your credit card ending in 1234 is still valid.

Use these as templates for responses.
```

### Fine-tuning Datasets
```jsonl
{"messages": [{"role": "user", "content": "My email is alice@example.com and password is MyP@ssw0rd123"}]}
{"messages": [{"role": "user", "content": "Process payment for card 4532-1234-5678-9010"}]}
```

**Remediation**:

```markdown
# GOOD: Synthetic/anonymized examples
You are a customer service agent. Here are example conversations:

Example 1:
User: What's my account balance?
Assistant: Let me check... Your account (email: [REDACTED], account ID: [REDACTED]) has a balance of $[AMOUNT]

Example 2:
User: Update my address
Assistant: I've updated your address to [ADDRESS]. Your payment method ending in [LAST_4] is still valid.

Use these as templates. NEVER include real customer PII in responses.
```

```jsonl
{"messages": [{"role": "user", "content": "My email is user@example.com and I need to reset my password"}]}
{"messages": [{"role": "user", "content": "Process payment for card ending in 1234"}]}
```

**NIST Controls**: PT-2 - Authority to Process PII, SI-12 - Information Handling and Retention

---

## HIGH: Unsafe Agent Tool Implementations (SCA-1012, CWE-78)

**Standard**: SCA-1012, CWE-78 (OS Command Injection), OWASP LLM-07

**Finding**: Agent tools with code execution, file system access, or database queries without validation

**Detection Patterns**:

### Python Agent Tools
```python
# HIGH: Command injection vulnerability
class ShellTool:
    def execute_command(self, command: str):
        # CRITICAL: No validation, agent can inject arbitrary commands
        result = os.system(command)
        return result

# HIGH: Path traversal vulnerability
class FileReaderTool:
    def read_file(self, filepath: str):
        # CRITICAL: Agent can read ANY file
        with open(filepath, 'r') as f:
            return f.read()

# HIGH: SQL injection vulnerability
class DatabaseTool:
    def query(self, user_query: str):
        # CRITICAL: No parameterization
        cursor.execute(f"SELECT * FROM users WHERE name = '{user_query}'")
        return cursor.fetchall()
```

**Remediation**:

```python
# GOOD: Validated and restricted tools
from pathlib import Path
import re
from typing import Literal

class SafeShellTool:
    """Shell tool with command whitelist"""

    ALLOWED_COMMANDS = {
        'ls': ['ls', '-la'],
        'pwd': ['pwd'],
        'date': ['date'],
    }

    def execute_command(self, command_name: Literal['ls', 'pwd', 'date']):
        """Execute only whitelisted commands"""
        if command_name not in self.ALLOWED_COMMANDS:
            raise ValueError(f"Command not allowed: {command_name}")

        # Use subprocess with argument list (not shell=True)
        result = subprocess.run(
            self.ALLOWED_COMMANDS[command_name],
            capture_output=True,
            text=True,
            timeout=5,
            cwd='/app/workspace'  # Restricted directory
        )

        return result.stdout

class SafeFileReaderTool:
    """File reader with path validation"""

    ALLOWED_DIR = Path('/app/data/documents').resolve()

    def read_file(self, filepath: str):
        """Read file with path validation"""
        # Validate and resolve path
        requested_path = (self.ALLOWED_DIR / filepath).resolve()

        # Ensure within allowed directory
        if not str(requested_path).startswith(str(self.ALLOWED_DIR)):
            raise PermissionError(f"Access denied: path outside allowed directory")

        # Check file exists and is a file
        if not requested_path.is_file():
            raise FileNotFoundError(f"File not found: {filepath}")

        # Size limit
        if requested_path.stat().st_size > 10_000_000:  # 10MB
            raise ValueError("File too large")

        with open(requested_path, 'r') as f:
            return f.read()

class SafeDatabaseTool:
    """Database tool with parameterized queries"""

    def search_users(self, name: str):
        """Search users with parameterized query"""
        # Validate input
        if len(name) > 100:
            raise ValueError("Name too long")

        # Parameterized query (prevents SQL injection)
        cursor.execute(
            "SELECT id, name, email FROM users WHERE name LIKE ?",
            (f"%{name}%",)
        )
        return cursor.fetchall()

    def get_user_balance(self, user_id: int):
        """Get user balance - read-only"""
        # Type validation (int prevents injection)
        cursor.execute(
            "SELECT balance FROM accounts WHERE user_id = ?",
            (user_id,)
        )
        result = cursor.fetchone()
        return result[0] if result else 0
```

**NIST Controls**: SI-10 - Information Input Validation, AC-3 - Access Enforcement

---

## HIGH: Agent Model Files Without Integrity Checks (SCA-1013, OWASP LLM-05)

**Standard**: SCA-1013, OWASP LLM-05 (Supply Chain Vulnerabilities), NIST SP 800-53 SI-7

**Finding**: Model files (.pkl, .safetensors, .gguf, .bin) without checksums or signatures

**Detection Patterns**:

### Model Loading Without Verification
```python
# HIGH: No integrity check
import pickle

def load_model(model_path):
    # CRITICAL: Pickle can execute arbitrary code
    with open(model_path, 'rb') as f:
        model = pickle.load(f)  # No signature verification
    return model

# HIGH: No provenance metadata
def download_model(url):
    response = requests.get(url)
    with open('model.bin', 'wb') as f:
        f.write(response.content)  # No checksum verification
```

**Remediation**:

```python
# GOOD: Model integrity verification
import hashlib
from pathlib import Path
import json

class SecureModelLoader:
    """Load models with integrity verification"""

    def __init__(self, model_registry_path: str):
        # Load trusted model registry
        with open(model_registry_path) as f:
            self.registry = json.load(f)

    def verify_model_checksum(self, model_path: str, expected_sha256: str) -> bool:
        """Verify model file checksum"""
        sha256_hash = hashlib.sha256()

        with open(model_path, 'rb') as f:
            # Read in chunks to handle large files
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)

        calculated_hash = sha256_hash.hexdigest()

        if calculated_hash != expected_sha256:
            raise ValueError(
                f"Model checksum mismatch!\n"
                f"Expected: {expected_sha256}\n"
                f"Got: {calculated_hash}"
            )

        return True

    def load_model_safe(self, model_name: str):
        """Load model with provenance and integrity checks"""
        # Check model is in trusted registry
        if model_name not in self.registry:
            raise ValueError(f"Model not in trusted registry: {model_name}")

        model_info = self.registry[model_name]
        model_path = Path(model_info['path'])

        # Verify model file exists
        if not model_path.exists():
            raise FileNotFoundError(f"Model file not found: {model_path}")

        # Verify checksum
        self.verify_model_checksum(
            str(model_path),
            model_info['sha256']
        )

        # Verify provenance metadata
        if not model_info.get('provenance'):
            raise ValueError("Missing provenance metadata")

        # Log model load
        audit_log('MODEL_LOADED',
                  model_name=model_name,
                  version=model_info.get('version'),
                  source=model_info['provenance'].get('source'))

        # Use safe formats (NOT pickle)
        if model_path.suffix == '.safetensors':
            from safetensors import safe_open
            model = safe_open(model_path, framework="pt")
        else:
            raise ValueError(f"Unsupported model format: {model_path.suffix}")

        return model

# Model registry file (trusted_models.json)
{
  "customer-support-v2": {
    "path": "/app/models/customer-support-v2.safetensors",
    "sha256": "abc123def456...",
    "version": "2.1.0",
    "provenance": {
      "source": "huggingface.co/myorg/customer-support",
      "training_date": "2024-01-15",
      "trained_by": "ml-team@company.com",
      "base_model": "meta-llama/Llama-2-7b-hf",
      "fine_tuning_dataset": "internal-support-tickets-anonymized",
      "signed_by": "mlops@company.com",
      "signature": "-----BEGIN PGP SIGNATURE-----..."
    }
  }
}
```

**NIST Controls**: SI-7 - Software Integrity, SI-7(1) - Integrity Checks, SR-11 - Component Authenticity

---

## MEDIUM: Agent Conversation History with PII (SCA-1014, GDPR Art. 5)

**Standard**: SCA-1014, GDPR Article 5 (Storage Limitation), NIST SP 800-53 PT-6

**Finding**: Agent memory/conversation logs stored unencrypted or retained indefinitely

**Detection Patterns**:

### Python Agent Memory
```python
# MEDIUM: Unencrypted conversation history
class ChatAgent:
    def __init__(self):
        self.conversation_history = []  # Stored in memory

    def chat(self, user_message):
        # CRITICAL: Stores user messages with potential PII
        self.conversation_history.append({
            'role': 'user',
            'content': user_message  # May contain PII
        })

        response = self.generate_response(user_message)
        self.conversation_history.append({
            'role': 'assistant',
            'content': response
        })

        # CRITICAL: Saves to disk unencrypted
        with open(f'conversations/{self.session_id}.json', 'w') as f:
            json.dump(self.conversation_history, f)

        return response
```

**Remediation**:

```python
# GOOD: Encrypted storage with retention policy
from cryptography.fernet import Fernet
from datetime import datetime, timedelta

class SecureChatAgent:
    """Agent with encrypted memory and retention policy"""

    RETENTION_DAYS = 30  # Delete after 30 days

    def __init__(self, encryption_key: bytes):
        self.fernet = Fernet(encryption_key)
        self.conversation_history = []
        self.session_id = secrets.token_hex(16)
        self.session_start = datetime.utcnow()

    def chat(self, user_message):
        """Chat with PII protection"""
        # Detect and redact PII before storing
        redacted_message = self.redact_pii(user_message)

        self.conversation_history.append({
            'role': 'user',
            'content': redacted_message,
            'timestamp': datetime.utcnow().isoformat()
        })

        response = self.generate_response(user_message)

        self.conversation_history.append({
            'role': 'assistant',
            'content': response,
            'timestamp': datetime.utcnow().isoformat()
        })

        # Save encrypted
        self.save_encrypted()

        return response

    def redact_pii(self, text: str) -> str:
        """Redact PII using regex patterns"""
        # Email
        text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                     '[EMAIL_REDACTED]', text)

        # Phone numbers
        text = re.sub(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
                     '[PHONE_REDACTED]', text)

        # Credit card (simple pattern)
        text = re.sub(r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
                     '[CARD_REDACTED]', text)

        # SSN
        text = re.sub(r'\b\d{3}-\d{2}-\d{4}\b',
                     '[SSN_REDACTED]', text)

        return text

    def save_encrypted(self):
        """Save conversation history encrypted"""
        conversation_json = json.dumps(self.conversation_history)
        encrypted_data = self.fernet.encrypt(conversation_json.encode())

        filepath = Path(f'conversations/{self.session_id}.enc')
        filepath.parent.mkdir(exist_ok=True)

        with open(filepath, 'wb') as f:
            f.write(encrypted_data)

        # Schedule deletion after retention period
        delete_after = self.session_start + timedelta(days=self.RETENTION_DAYS)
        schedule_file_deletion(str(filepath), delete_after)

    def load_encrypted(self, session_id: str):
        """Load encrypted conversation"""
        filepath = Path(f'conversations/{session_id}.enc')

        with open(filepath, 'rb') as f:
            encrypted_data = f.read()

        decrypted_data = self.fernet.decrypt(encrypted_data)
        self.conversation_history = json.loads(decrypted_data)
```

**NIST Controls**: PT-6 - System of Records Notice, SC-28 - Protection of Information at Rest

---

## MEDIUM: Missing Agent Audit Logging (SCA-1015, NIST AU-2)

**Standard**: SCA-1015, NIST SP 800-53 AU-2 (Audit Events), AU-3 (Content of Audit Records)

**Finding**: Agent actions not logged or insufficient audit trail

**Detection Patterns**:

```python
# MEDIUM: No audit logging
class Agent:
    def execute_tool(self, tool_name, params):
        # No logging of what agent does
        result = self.tools[tool_name].run(params)
        return result
```

**Remediation**:

```python
# GOOD: Comprehensive audit logging
import logging
import json
from datetime import datetime

class AuditLogger:
    """Structured audit logging for agent actions"""

    def __init__(self):
        self.logger = logging.getLogger('agent.audit')
        handler = logging.FileHandler('/var/log/agent-audit.jsonl')
        handler.setFormatter(logging.Formatter('%(message)s'))
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)

    def log_tool_execution(self, tool_name: str, params: dict, result: any,
                          user_id: str = None, approved: bool = False):
        """Log agent tool execution"""
        audit_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': 'TOOL_EXECUTION',
            'tool_name': tool_name,
            'parameters': self._sanitize_params(params),
            'result_summary': str(result)[:200],  # Truncate
            'user_id': user_id,
            'approved_by_user': approved,
            'session_id': get_current_session_id()
        }

        self.logger.info(json.dumps(audit_entry))

    def _sanitize_params(self, params: dict) -> dict:
        """Remove sensitive data from logged parameters"""
        sanitized = {}
        sensitive_keys = {'password', 'api_key', 'token', 'secret'}

        for key, value in params.items():
            if any(s in key.lower() for s in sensitive_keys):
                sanitized[key] = '[REDACTED]'
            else:
                sanitized[key] = value

        return sanitized

class AuditedAgent:
    def __init__(self):
        self.audit = AuditLogger()

    def execute_tool(self, tool_name, params, user_approved=False):
        """Execute tool with audit logging"""
        try:
            result = self.tools[tool_name].run(params)

            # Log successful execution
            self.audit.log_tool_execution(
                tool_name=tool_name,
                params=params,
                result=result,
                user_id=get_current_user_id(),
                approved=user_approved
            )

            return result

        except Exception as e:
            # Log failure
            self.audit.log_tool_execution(
                tool_name=tool_name,
                params=params,
                result=f"ERROR: {str(e)}",
                user_id=get_current_user_id(),
                approved=user_approved
            )
            raise
```

**NIST Controls**: AU-2 - Audit Events, AU-3 - Content of Audit Records, AU-6 - Audit Review

---

## Summary Table

| Finding | Severity | Standard | NIST Control | Remediation Priority |
|---------|----------|----------|--------------|---------------------|
| Hardcoded secrets in prompts | Critical | SCA-1009, CWE-798 | IA-5(7), CM-3 | Immediate |
| Overly permissive agent instructions | Critical | SCA-1010, OWASP LLM-08 | AC-3, AC-6 | Immediate |
| PII in prompts/examples | High | SCA-1011, GDPR Art. 5 | PT-2, SI-12 | High |
| Unsafe agent tool implementations | High | SCA-1012, CWE-78 | SI-10, AC-3 | High |
| Model files without integrity checks | High | SCA-1013, OWASP LLM-05 | SI-7, SR-11 | High |
| Conversation history with PII | Medium | SCA-1014, GDPR Art. 5 | PT-6, SC-28 | Medium |
| Missing agent audit logging | Medium | SCA-1015, AU-2 | AU-2, AU-3 | Medium |

---

## Compliance Mapping

### NIST AI Risk Management Framework (AI RMF)
- **GOVERN-1.2**: AI risk management responsibilities
- **MAP-2.3**: Task and output characteristics
- **MEASURE-2.1**: Test for trustworthiness
- **MANAGE-1.1**: Risk response

### OWASP LLM Top 10
- **LLM01**: Prompt Injection
- **LLM03**: Training Data Poisoning
- **LLM05**: Supply Chain Vulnerabilities
- **LLM07**: Insecure Plugin Design
- **LLM08**: Excessive Agency

### NIST SP 800-53 Rev 5
- **IA-5(7)**: No embedded authenticators
- **AC-3**: Access Enforcement
- **AC-6**: Least Privilege
- **SI-7**: Software Integrity
- **SI-10**: Information Input Validation
- **AU-2**: Audit Events
- **PT-2**: Authority to Process PII
- **PT-6**: System of Records Notice
- **SC-28**: Protection of Information at Rest

### GDPR
- **Article 5**: Principles (minimization, storage limitation)

---

## Testing

### Automated Checks
```bash
# Find prompt/config files
find . -name "*.prompt" -o -name "*.md" -o -name "*.txt" | grep -i prompt

# Check for secrets in prompts
git grep -iE "api[_-]?key|password|secret" -- "*.prompt" "*.md" "agent_config.*"

# Find model files
find . -name "*.pkl" -o -name "*.bin" -o -name "*.safetensors" -o -name "*.gguf"

# Check for model checksums
find . -name "*.pkl" -o -name "*.bin" | while read f; do
  [ -f "${f}.sha256" ] || echo "Missing checksum: $f"
done

# Find agent tool implementations
git grep -l "def.*Tool\|class.*Tool" -- "*.py"
```

### Manual Review
1. Review all system prompts for overly permissive instructions
2. Check agent config files for hardcoded credentials
3. Verify model files have integrity checks (checksums/signatures)
4. Test agent tools for input validation
5. Review conversation storage for PII protection
6. Verify audit logging captures all agent actions
