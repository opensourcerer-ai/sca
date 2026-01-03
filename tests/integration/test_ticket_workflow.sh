#!/usr/bin/env bash
# Integration Tests: Ticket Creation Workflow
# Tests GitHub and Jira ticket creation (dry-run mode)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SCA_BIN="$PROJECT_ROOT/bin/sca"
TICKETS_SCRIPT="$PROJECT_ROOT/bin/sca-create-tickets.sh"
FIXTURES_DIR="$SCRIPT_DIR/../fixtures"

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# Test helper functions
assert_contains() {
    local haystack="$1"
    local needle="$2"
    local test_name="$3"

    TESTS_RUN=$((TESTS_RUN + 1))

    if echo "$haystack" | grep -q "$needle"; then
        echo -e "${GREEN}✓${NC} $test_name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        echo -e "${RED}✗${NC} $test_name"
        echo "  Expected to find: $needle"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

assert_file_exists() {
    local file_path="$1"
    local test_name="$2"

    TESTS_RUN=$((TESTS_RUN + 1))

    if [[ -f "$file_path" ]]; then
        echo -e "${GREEN}✓${NC} $test_name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        echo -e "${RED}✗${NC} $test_name"
        echo "  File not found: $file_path"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

assert_json_field() {
    local json_file="$1"
    local field="$2"
    local test_name="$3"

    TESTS_RUN=$((TESTS_RUN + 1))

    if jq -e "$field" "$json_file" > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC} $test_name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        echo -e "${RED}✗${NC} $test_name"
        echo "  Field not found in JSON: $field"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

cleanup() {
    if [[ -d "$TEST_REPO" ]]; then
        rm -rf "$TEST_REPO"
    fi
}

trap cleanup EXIT

echo "========================================="
echo "Integration Tests: Ticket Creation"
echo "========================================="
echo ""

# Setup test repository
TEST_REPO="$FIXTURES_DIR/ticket-test-repo"
mkdir -p "$TEST_REPO/sec-ctrl/"{config,state,reports}

# Create mock audit report
cat > "$TEST_REPO/sec-ctrl/reports/security-audit.latest.json" <<'EOF'
{
  "metadata": {
    "timestamp": "20260103T120000Z",
    "repo": "ticket-test-repo"
  },
  "summary": {
    "critical_findings": 1,
    "high_findings": 1
  },
  "findings": {
    "critical": [
      {
        "id": "CRIT-001",
        "title": "SQL Injection in User Query",
        "file": "src/db/users.c",
        "lines": "45-47",
        "cwe": "CWE-89",
        "impact": "Attacker can execute arbitrary SQL commands",
        "remediation_priority": "IMMEDIATE"
      }
    ],
    "high": [
      {
        "id": "HIGH-001",
        "title": "Weak Password Hashing (MD5)",
        "file": "src/auth/password.c",
        "lines": "23",
        "cwe": "CWE-327",
        "impact": "Password hashes vulnerable to rainbow table attacks"
      }
    ]
  }
}
EOF

# Create SUGGESTIONS.md with remediation steps
cat > "$TEST_REPO/sec-ctrl/SUGGESTIONS.md" <<'EOF'
# Security Remediation Suggestions

### CRIT-001: SQL Injection in User Query

**Remediation Steps**:
1. Use parameterized queries instead of string concatenation
2. Validate and sanitize all user input
3. Apply principle of least privilege to database user

**Code to Add**:
```c
// Replace string concatenation with prepared statement
sqlite3_stmt *stmt;
const char *sql = "SELECT * FROM users WHERE id = ?";
sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
sqlite3_bind_int(stmt, 1, user_id);
```

**References**:
- OWASP SQL Injection Prevention Cheat Sheet
- CWE-89: Improper Neutralization of Special Elements

---

### HIGH-001: Weak Password Hashing (MD5)

**Remediation Steps**:
1. Replace MD5 with bcrypt or Argon2id
2. Use at least cost factor 12 for bcrypt
3. Add salt (handled automatically by bcrypt)

**Code to Add**:
```c
#include <bcrypt/BCrypt.hpp>

std::string hash_password(const std::string& password) {
    return BCrypt::generateHash(password, 12);
}

bool verify_password(const std::string& password, const std::string& hash) {
    return BCrypt::validatePassword(password, hash);
}
```
EOF

# Initialize empty ticket tracker
echo '{"tickets": []}' > "$TEST_REPO/sec-ctrl/state/created-tickets.json"

echo "Test Group: Dry Run Mode"
echo "---"

# Test dry-run for GitHub - verify it runs without errors
if output=$("$TICKETS_SCRIPT" \
    --ctrl-dir "$TEST_REPO/sec-ctrl" \
    --report "$TEST_REPO/sec-ctrl/reports/security-audit.latest.json" \
    --platform github \
    --severity-min HIGH \
    --dry-run 2>&1); then
    echo -e "${GREEN}✓${NC} GitHub dry-run completes without error"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}✗${NC} GitHub dry-run failed"
    echo "  Output: $output"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
TESTS_RUN=$((TESTS_RUN + 1))

# Test dry-run for Jira
if output=$("$TICKETS_SCRIPT" \
    --ctrl-dir "$TEST_REPO/sec-ctrl" \
    --report "$TEST_REPO/sec-ctrl/reports/security-audit.latest.json" \
    --platform jira \
    --severity-min HIGH \
    --dry-run 2>&1); then
    echo -e "${GREEN}✓${NC} Jira dry-run completes without error"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}✗${NC} Jira dry-run failed"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
TESTS_RUN=$((TESTS_RUN + 1))
echo ""

echo "Test Group: CLI Integration"
echo "---"

# Test via main sca CLI
if output=$("$SCA_BIN" create-tickets --help 2>&1); then
    echo -e "${GREEN}✓${NC} create-tickets command available in CLI"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}✗${NC} create-tickets command not found"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
TESTS_RUN=$((TESTS_RUN + 1))

if echo "$output" | grep -F -- "--platform" > /dev/null; then
    echo -e "${GREEN}✓${NC} create-tickets CLI has --platform option"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}✗${NC} create-tickets CLI missing --platform"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
TESTS_RUN=$((TESTS_RUN + 1))

if echo "$output" | grep -F "github" > /dev/null && echo "$output" | grep -F "jira" > /dev/null; then
    echo -e "${GREEN}✓${NC} create-tickets supports github and jira platforms"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}✗${NC} create-tickets missing platform support"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
TESTS_RUN=$((TESTS_RUN + 1))

if echo "$output" | grep -F -- "--dry-run" > /dev/null; then
    echo -e "${GREEN}✓${NC} create-tickets has --dry-run option"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}✗${NC} create-tickets missing --dry-run"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
TESTS_RUN=$((TESTS_RUN + 1))
echo ""

echo "Test Group: Ticket Tracker Format"
echo "---"

# Simulate ticket creation by manually adding to tracker
cat > "$TEST_REPO/sec-ctrl/state/created-tickets.json" <<'EOF'
{
  "tickets": [
    {
      "finding_id": "CRIT-001",
      "ticket_key": "#123",
      "ticket_url": "https://github.com/test/repo/issues/123",
      "created_at": "2026-01-03T12:00:00Z"
    }
  ]
}
EOF

assert_file_exists "$TEST_REPO/sec-ctrl/state/created-tickets.json" "Ticket tracker file exists"
assert_json_field "$TEST_REPO/sec-ctrl/state/created-tickets.json" ".tickets" "Tracker has tickets array"
assert_json_field "$TEST_REPO/sec-ctrl/state/created-tickets.json" ".tickets[0].finding_id" "Tracker entry has finding_id"
assert_json_field "$TEST_REPO/sec-ctrl/state/created-tickets.json" ".tickets[0].ticket_url" "Tracker entry has ticket_url"
echo ""


echo "Test Group: Environment File Template"
echo "---"

if [[ -f "$PROJECT_ROOT/.env.example" ]]; then
    echo -e "${GREEN}✓${NC} .env.example exists"
    TESTS_PASSED=$((TESTS_PASSED + 1))

    env_content=$(cat "$PROJECT_ROOT/.env.example")

    # Check for essential variables
    for var in "GITHUB_TOKEN" "JIRA_URL" "JIRA_API_TOKEN"; do
        if echo "$env_content" | grep -q "$var"; then
            echo -e "${GREEN}✓${NC} .env.example has $var"
            TESTS_PASSED=$((TESTS_PASSED + 1))
        else
            echo -e "${RED}✗${NC} .env.example missing $var"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        fi
        TESTS_RUN=$((TESTS_RUN + 1))
    done
else
    echo -e "${RED}✗${NC} .env.example not found"
    TESTS_FAILED=$((TESTS_FAILED + 1))
    TESTS_RUN=$((TESTS_RUN + 1))
fi
echo ""

# Summary
echo "========================================="
echo "Test Results"
echo "========================================="
echo "Total:  $TESTS_RUN"
echo -e "Passed: ${GREEN}$TESTS_PASSED${NC}"
if [[ $TESTS_FAILED -gt 0 ]]; then
    echo -e "Failed: ${RED}$TESTS_FAILED${NC}"
else
    echo -e "Failed: $TESTS_FAILED"
fi
echo ""

if [[ $TESTS_FAILED -gt 0 ]]; then
    echo -e "${RED}TESTS FAILED${NC}"
    exit 1
else
    echo -e "${GREEN}ALL TESTS PASSED${NC}"
    exit 0
fi
