#!/usr/bin/env bash
set -euo pipefail

# Unit tests for CLI argument parsing

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$SCRIPT_DIR/../bin"

echo "=== Testing CLI argument parsing ==="

# Test: --help shows usage
if ! "$BIN_DIR/sca" --help | grep -q "Available commands"; then
  echo "FAIL: --help does not show commands"
  exit 1
fi
echo "PASS: --help shows usage"

# Test: Invalid command exits non-zero
"$BIN_DIR/sca" invalid-command >/dev/null 2>&1 && {
  echo "FAIL: Invalid command should exit non-zero"
  exit 1
} || {
  # Command failed as expected
  echo "PASS: Invalid command exits with error"
}

# Test: audit --help shows audit-specific options
if ! "$BIN_DIR/sca" audit --help | grep -q "enable-deps"; then
  echo "FAIL: audit --help missing --enable-deps"
  exit 1
fi
echo "PASS: audit --help shows options"

echo "=== All CLI tests passed ==="
