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

# Test exclude-standards (use grep -F for literal match)
output=$("$SCA_BIN" audit --help 2>&1 || true)
if echo "$output" | grep -F -- "--exclude-standards" > /dev/null; then
    echo -e "${GREEN}✓${NC} Audit help shows --exclude-standards"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}✗${NC} Audit help shows --exclude-standards"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
TESTS_RUN=$((TESTS_RUN + 1))

if echo "$output" | grep -F -- "--include-standards" > /dev/null; then
    echo -e "${GREEN}✓${NC} Audit help shows --include-standards"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}✗${NC} Audit help shows --include-standards"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
TESTS_RUN=$((TESTS_RUN + 1))

if echo "$output" | grep -F -- "--severity-min" > /dev/null; then
    echo -e "${GREEN}✓${NC} Audit help shows --severity-min"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}✗${NC} Audit help shows --severity-min"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
TESTS_RUN=$((TESTS_RUN + 1))

if echo "$output" | grep -F -- "--interactive" > /dev/null; then
    echo -e "${GREEN}✓${NC} Audit help shows --interactive"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}✗${NC} Audit help shows --interactive"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
TESTS_RUN=$((TESTS_RUN + 1))
echo ""

# Test: Suppress command
echo "Test Group: Suppress Command"
echo "---"
output=$("$SCA_BIN" suppress --help 2>&1 || true)

# Use grep -F for literal matches
for flag in "--report" "--batch" "--auto-commit" "--non-interactive"; do
    if echo "$output" | grep -F -- "$flag" > /dev/null; then
        echo -e "${GREEN}✓${NC} Suppress help shows $flag"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "${RED}✗${NC} Suppress help shows $flag"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
    TESTS_RUN=$((TESTS_RUN + 1))
done
echo ""

# Test: Create-tickets command
echo "Test Group: Create-Tickets Command"
echo "---"
output=$("$SCA_BIN" create-tickets --help 2>&1 || true)

# Check for all flags
for flag in "--platform" "github" "jira" "--dry-run" "--severity-min" "--create-all"; do
    if echo "$output" | grep -F -- "$flag" > /dev/null; then
        echo -e "${GREEN}✓${NC} create-tickets help shows/mentions $flag"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "${RED}✗${NC} create-tickets help shows/mentions $flag"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
    TESTS_RUN=$((TESTS_RUN + 1))
done
echo ""

# Test: Invalid command
echo "Test Group: Error Handling"
echo "---"
"$SCA_BIN" invalid-command 2>/dev/null && exit_code=$? || exit_code=$?
# Accept any non-zero exit code for invalid command
TESTS_RUN=$((TESTS_RUN + 1))
if [[ $exit_code -ne 0 ]]; then
    echo -e "${GREEN}✓${NC} Invalid command exits with non-zero code ($exit_code)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}✗${NC} Invalid command should exit with non-zero code"
    echo "  Got exit code: $exit_code"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
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
