#!/usr/bin/env bash
# Unit Tests: CLI Argument Parsing
# Tests the sca Python CLI wrapper for correct argument handling

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SCA_BIN="$PROJECT_ROOT/bin/sca"

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test helper functions
assert_equals() {
    local expected="$1"
    local actual="$2"
    local test_name="$3"

    TESTS_RUN=$((TESTS_RUN + 1))

    if [[ "$expected" == "$actual" ]]; then
        echo -e "${GREEN}✓${NC} $test_name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        echo -e "${RED}✗${NC} $test_name"
        echo "  Expected: $expected"
        echo "  Got:      $actual"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

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
        echo "  In: $haystack"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

assert_exit_code() {
    local expected_code="$1"
    local actual_code="$2"
    local test_name="$3"

    TESTS_RUN=$((TESTS_RUN + 1))

    if [[ $expected_code -eq $actual_code ]]; then
        echo -e "${GREEN}✓${NC} $test_name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        echo -e "${RED}✗${NC} $test_name"
        echo "  Expected exit code: $expected_code"
        echo "  Got:                $actual_code"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

echo "========================================="
echo "Unit Tests: CLI Argument Parsing"
echo "========================================="
echo ""

# Test: No arguments shows help
echo "Test Group: Help Output"
echo "---"
output=$("$SCA_BIN" 2>&1 || true)
assert_contains "$output" "Security Control Agent" "sca with no args shows help"
assert_contains "$output" "audit" "Help includes 'audit' command"
assert_contains "$output" "suppress" "Help includes 'suppress' command"
assert_contains "$output" "create-tickets" "Help includes 'create-tickets' command"
echo ""

# Test: Audit command with filtering
echo "Test Group: Audit Command Filtering"
echo "---"

# Test exclude-standards
output=$("$SCA_BIN" audit --help 2>&1 || true)
assert_contains "$output" "--exclude-standards" "Audit help shows --exclude-standards"
assert_contains "$output" "--include-standards" "Audit help shows --include-standards"
assert_contains "$output" "--severity-min" "Audit help shows --severity-min"
assert_contains "$output" "--interactive" "Audit help shows --interactive"
echo ""

# Test: Suppress command
echo "Test Group: Suppress Command"
echo "---"
output=$("$SCA_BIN" suppress --help 2>&1 || true)
assert_contains "$output" "--report" "Suppress help shows --report"
assert_contains "$output" "--batch" "Suppress help shows --batch"
assert_contains "$output" "--auto-commit" "Suppress help shows --auto-commit"
assert_contains "$output" "--non-interactive" "Suppress help shows --non-interactive"
echo ""

# Test: Create-tickets command
echo "Test Group: Create-Tickets Command"
echo "---"
output=$("$SCA_BIN" create-tickets --help 2>&1 || true)
assert_contains "$output" "--platform" "create-tickets help shows --platform"
assert_contains "$output" "github" "create-tickets help mentions github"
assert_contains "$output" "jira" "create-tickets help mentions jira"
assert_contains "$output" "--dry-run" "create-tickets help shows --dry-run"
assert_contains "$output" "--severity-min" "create-tickets help shows --severity-min"
assert_contains "$output" "--create-all" "create-tickets help shows --create-all"
echo ""

# Test: Invalid command
echo "Test Group: Error Handling"
echo "---"
"$SCA_BIN" invalid-command 2>/dev/null && exit_code=$? || exit_code=$?
assert_exit_code 3 $exit_code "Invalid command exits with code 3"
echo ""

# Test: Version file exists
echo "Test Group: Version Information"
echo "---"
if [[ -f "$PROJECT_ROOT/VERSION" ]]; then
    version=$(cat "$PROJECT_ROOT/VERSION")
    assert_contains "$version" "0.8.8" "VERSION file contains 0.8.8"
else
    echo -e "${RED}✗${NC} VERSION file not found"
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
