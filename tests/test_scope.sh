#!/usr/bin/env bash
set -euo pipefail

# Unit tests for scope generation and exclusion logic

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$SCRIPT_DIR/../bin"
FIXTURE_DIR="$SCRIPT_DIR/fixtures/mock-repo"

echo "=== Testing scope generation ==="

# Create mock repo
rm -rf "$FIXTURE_DIR"
mkdir -p "$FIXTURE_DIR"/{src,sec-ctrl/config,tools/sec-audit-agent}
touch "$FIXTURE_DIR"/src/main.py
touch "$FIXTURE_DIR"/sec-ctrl/config/ignore.paths
touch "$FIXTURE_DIR"/tools/sec-audit-agent/agent.sh

cd "$FIXTURE_DIR"
git init >/dev/null 2>&1 || true
git add -A >/dev/null 2>&1 || true

# Test: sec-ctrl should be excluded
SCOPE=$("$BIN_DIR/repo-scope.sh" --repo "$FIXTURE_DIR")

if echo "$SCOPE" | grep -q "sec-ctrl/"; then
  echo "FAIL: sec-ctrl/ should be excluded from scope"
  echo "Scope output:"
  echo "$SCOPE"
  exit 1
fi
echo "PASS: sec-ctrl/ excluded from scope"

# Test: src/main.py should be included
if ! echo "$SCOPE" | grep -q "src/main.py"; then
  echo "FAIL: src/main.py should be in scope"
  exit 1
fi
echo "PASS: src/main.py included in scope"

# Cleanup
cd "$SCRIPT_DIR"
rm -rf "$FIXTURE_DIR"

echo "=== All scope tests passed ==="
