#!/usr/bin/env bash
# Unit Tests: Scope Exclusion Logic
# Tests the repo-scope.sh script for correct file filtering

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SCOPE_SCRIPT="$PROJECT_ROOT/bin/repo-scope.sh"
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

assert_not_contains() {
    local haystack="$1"
    local needle="$2"
    local test_name="$3"

    TESTS_RUN=$((TESTS_RUN + 1))

    if ! echo "$haystack" | grep -q "$needle"; then
        echo -e "${GREEN}✓${NC} $test_name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        echo -e "${RED}✗${NC} $test_name"
        echo "  Should NOT contain: $needle"
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
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

echo "========================================="
echo "Unit Tests: Scope Exclusion Logic"
echo "========================================="
echo ""

# Create test fixture directory
TEST_REPO="$FIXTURES_DIR/test-repo"
mkdir -p "$TEST_REPO"/{src,node_modules,tests,.git,sec-ctrl}

# Create test files
touch "$TEST_REPO/src/main.c"
touch "$TEST_REPO/src/utils.py"
touch "$TEST_REPO/node_modules/package.js"
touch "$TEST_REPO/tests/test_main.py"
touch "$TEST_REPO/.git/config"
touch "$TEST_REPO/sec-ctrl/OVERRIDE.md"
touch "$TEST_REPO/README.md"

# Create ctrl-dir
TEST_CTRL="$TEST_REPO/sec-ctrl"
mkdir -p "$TEST_CTRL/config"

# Test: Default exclusions
echo "Test Group: Default Exclusions"
echo "---"
output=$("$SCOPE_SCRIPT" --repo "$TEST_REPO" --ctrl-dir "$TEST_CTRL" 2>&1)

assert_contains "$output" "src/main.c" "Includes source file src/main.c"
assert_contains "$output" "src/utils.py" "Includes source file src/utils.py"
assert_not_contains "$output" "node_modules" "Excludes node_modules"
assert_not_contains "$output" ".git" "Excludes .git directory"
assert_not_contains "$output" "sec-ctrl" "Excludes control directory"
echo ""

# Test: Custom exclusion via ignore.paths
echo "Test Group: Custom Exclusions"
echo "---"
echo "tests/" > "$TEST_CTRL/config/ignore.paths"

output=$("$SCOPE_SCRIPT" --repo "$TEST_REPO" --ctrl-dir "$TEST_CTRL" 2>&1)
assert_not_contains "$output" "tests/test_main.py" "Excludes custom pattern from ignore.paths"
echo ""

# Test: Stats format
echo "Test Group: Stats Format"
echo "---"
output=$("$SCOPE_SCRIPT" --repo "$TEST_REPO" --ctrl-dir "$TEST_CTRL" --format stats 2>&1)
assert_contains "$output" "Total files in scope" "Stats shows total files"
assert_contains "$output" "Languages detected" "Stats shows languages"
echo ""

# Cleanup
rm -rf "$TEST_REPO"

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
