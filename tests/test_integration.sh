#!/usr/bin/env bash
set -euo pipefail

# Integration test: end-to-end bootstrap + audit
# Note: Requires CLAUDE_CODE_BIN or skips LLM invocation

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$SCRIPT_DIR/../bin"
FIXTURE_DIR="$SCRIPT_DIR/fixtures/integration-test-repo"

echo "=== Integration test ==="

# Create mock repo
rm -rf "$FIXTURE_DIR"
mkdir -p "$FIXTURE_DIR"/src
cat > "$FIXTURE_DIR/src/example.py" <<'EOF'
import os

# Hardcoded API key (intentional vulnerability for testing)
API_KEY = "sk-1234567890abcdef"

def get_user_data(user_id):
    # SQL injection vulnerability
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query
EOF

cd "$FIXTURE_DIR"
git init >/dev/null
git add -A >/dev/null
git commit -m "Initial commit" >/dev/null

# Test: Bootstrap
if ! "$BIN_DIR/sca" bootstrap --repo "$FIXTURE_DIR"; then
  echo "FAIL: bootstrap failed"
  exit 1
fi
echo "PASS: bootstrap created sec-ctrl/"

# Test: sec-ctrl/ structure exists
if [[ ! -d "$FIXTURE_DIR/sec-ctrl/config" ]]; then
  echo "FAIL: sec-ctrl/config not created"
  exit 1
fi
echo "PASS: sec-ctrl/ structure created"

# Test: Scope excludes sec-ctrl
SCOPE=$("$BIN_DIR/sca" scope --repo "$FIXTURE_DIR")
if echo "$SCOPE" | grep -q "sec-ctrl/"; then
  echo "FAIL: sec-ctrl in scope"
  exit 1
fi
echo "PASS: sec-ctrl excluded from scope"

# Test: Audit (skip if no model runner configured)
if [[ -z "${CLAUDE_CODE_BIN:-}" ]] && ! command -v claude >/dev/null 2>&1; then
  echo "SKIP: Audit test (no model runner configured)"
else
  echo "Running audit (this may take time)..."
  if "$BIN_DIR/sca" audit --repo "$FIXTURE_DIR" --verbose; then
    echo "PASS: Audit completed"
  else
    EXIT_CODE=$?
    if [[ "$EXIT_CODE" -eq 2 ]]; then
      echo "PASS: Audit found critical/high findings (expected for test repo)"
    else
      echo "FAIL: Audit failed with unexpected exit code: $EXIT_CODE"
      exit 1
    fi
  fi

  # Check report exists
  if [[ ! -f "$FIXTURE_DIR/sec-ctrl/reports/security-audit.latest.md" ]]; then
    echo "FAIL: Report not generated"
    exit 1
  fi
  echo "PASS: Report generated"
fi

# Cleanup
cd "$SCRIPT_DIR"
rm -rf "$FIXTURE_DIR"

echo "=== Integration test passed ==="
