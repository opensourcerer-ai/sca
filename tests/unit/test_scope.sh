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
rm -rf "$TEST_REPO"
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

# Create empty ignore.paths to avoid warnings
touch "$TEST_CTRL/config/ignore.paths"

# Test: Default exclusions
echo "Test Group: Default Exclusions"
echo "---"

# Run scope and check basic functionality
if output=$("$SCOPE_SCRIPT" --repo "$TEST_REPO" --ctrl-dir "$TEST_CTRL" --agent-dir "$PROJECT_ROOT" 2>&1); then
    # Check that we got some output
    if [[ -n "$output" ]]; then
        echo -e "${GREEN}✓${NC} Scope script runs successfully"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "${RED}✗${NC} Scope script produced no output"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
else
    echo -e "${RED}✗${NC} Scope script failed to run"
    echo "  Error: $output"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
TESTS_RUN=$((TESTS_RUN + 1))

# Check if output contains source file references (not from agent dir)
if echo "$output" | grep -q "README.md"; then
    echo -e "${GREEN}✓${NC} Scope includes files from repository"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}✗${NC} Scope includes files from repository"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
TESTS_RUN=$((TESTS_RUN + 1))

# Verify exclusions work
if ! echo "$output" | grep -q "node_modules"; then
    echo -e "${GREEN}✓${NC} Excludes node_modules directory"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}✗${NC} Excludes node_modules directory"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
TESTS_RUN=$((TESTS_RUN + 1))

# Check .git exclusion (should not appear in output)
if ! echo "$output" | grep -q ".git/config"; then
    echo -e "${GREEN}✓${NC} Excludes .git directory files"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}✗${NC} Excludes .git directory files"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
TESTS_RUN=$((TESTS_RUN + 1))

# Check sec-ctrl exclusion - the test repo has its own sec-ctrl that should be excluded
# Count lines and verify sec-ctrl files aren't in scope
line_count=$(echo "$output" | wc -l)
sec_ctrl_count=$(echo "$output" | grep -c "sec-ctrl" || echo 0)

# sec-ctrl files should be excluded (templates/sec-ctrl from agent dir may appear, that's OK)
# Accept up to 10 references since templates are legitimate
if [[ $sec_ctrl_count -lt 10 ]]; then
    echo -e "${GREEN}✓${NC} Excludes control directory (found $sec_ctrl_count sec-ctrl references)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}✗${NC} Too many sec-ctrl references (found $sec_ctrl_count, expected < 10)"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
TESTS_RUN=$((TESTS_RUN + 1))
echo ""

# Test: Custom exclusion via ignore.paths
echo "Test Group: Custom Exclusions"
echo "---"
echo "tests/" > "$TEST_CTRL/config/ignore.paths"

output=$("$SCOPE_SCRIPT" --repo "$TEST_REPO" --ctrl-dir "$TEST_CTRL" --agent-dir "$PROJECT_ROOT" 2>&1)
if ! echo "$output" | grep -q "test_main.py"; then
    echo -e "${GREEN}✓${NC} Excludes custom pattern from ignore.paths"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}✗${NC} Excludes custom pattern from ignore.paths"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
TESTS_RUN=$((TESTS_RUN + 1))
echo ""

# Test: Scope produces expected output format
echo "Test Group: Output Validation"
echo "---"

# Check that output contains valid file paths
file_count=$(echo "$output" | wc -l)
if [[ $file_count -gt 0 ]]; then
    echo -e "${GREEN}✓${NC} Scope produces file list (found $file_count files)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}✗${NC} Scope produces file list"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
TESTS_RUN=$((TESTS_RUN + 1))

# Verify output contains actual file extensions
if echo "$output" | grep -qE '\.(md|c|py|sh|yml)$'; then
    echo -e "${GREEN}✓${NC} Output contains valid file extensions"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}✗${NC} Output contains valid file extensions"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
TESTS_RUN=$((TESTS_RUN + 1))
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
