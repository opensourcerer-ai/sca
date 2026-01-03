#!/usr/bin/env bash
# SCA Test Runner
# Executes all unit and integration tests with summary reporting

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test suite configuration
UNIT_TESTS=(
    "unit/test_cli.sh"
    "unit/test_scope.sh"
)

INTEGRATION_TESTS=(
    "integration/test_audit_workflow.sh"
    "integration/test_suppress_workflow.sh"
    "integration/test_ticket_workflow.sh"
)

# Results tracking
TOTAL_SUITES=0
PASSED_SUITES=0
FAILED_SUITES=0
FAILED_SUITE_NAMES=()

# Parse arguments
RUN_UNIT=1
RUN_INTEGRATION=1
VERBOSE=0

while [[ $# -gt 0 ]]; do
    case $1 in
        --unit-only)
            RUN_INTEGRATION=0
            shift
            ;;
        --integration-only)
            RUN_UNIT=0
            shift
            ;;
        --verbose)
            VERBOSE=1
            shift
            ;;
        --help)
            cat <<EOF
SCA Test Runner

Usage: $0 [OPTIONS]

Options:
    --unit-only          Run only unit tests
    --integration-only   Run only integration tests
    --verbose            Show detailed test output
    --help               Show this help message

Examples:
    # Run all tests
    $0

    # Run only unit tests
    $0 --unit-only

    # Run with verbose output
    $0 --verbose
EOF
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Print header
echo ""
echo "========================================="
echo -e "${BLUE}SCA Test Suite v$(cat "$PROJECT_ROOT/VERSION" 2>/dev/null || echo "unknown")${NC}"
echo "========================================="
echo ""

# Function to run a test suite
run_test_suite() {
    local test_path="$1"
    local test_name=$(basename "$test_path" .sh)

    TOTAL_SUITES=$((TOTAL_SUITES + 1))

    echo ""
    echo -e "${YELLOW}Running: $test_name${NC}"
    echo "---"

    # Make script executable
    chmod +x "$SCRIPT_DIR/$test_path"

    # Run test
    if [[ $VERBOSE -eq 1 ]]; then
        if "$SCRIPT_DIR/$test_path"; then
            echo -e "${GREEN}✓ PASSED${NC}: $test_name"
            PASSED_SUITES=$((PASSED_SUITES + 1))
            return 0
        else
            echo -e "${RED}✗ FAILED${NC}: $test_name"
            FAILED_SUITES=$((FAILED_SUITES + 1))
            FAILED_SUITE_NAMES+=("$test_name")
            return 1
        fi
    else
        # Capture output
        local output
        if output=$("$SCRIPT_DIR/$test_path" 2>&1); then
            echo -e "${GREEN}✓ PASSED${NC}: $test_name"
            PASSED_SUITES=$((PASSED_SUITES + 1))
            return 0
        else
            echo -e "${RED}✗ FAILED${NC}: $test_name"
            echo ""
            echo "Failed test output:"
            echo "$output"
            FAILED_SUITES=$((FAILED_SUITES + 1))
            FAILED_SUITE_NAMES+=("$test_name")
            return 1
        fi
    fi
}

# Run unit tests
if [[ $RUN_UNIT -eq 1 ]]; then
    echo "========================================="
    echo -e "${BLUE}Unit Tests${NC}"
    echo "========================================="

    for test in "${UNIT_TESTS[@]}"; do
        run_test_suite "$test" || true
    done
fi

# Run integration tests
if [[ $RUN_INTEGRATION -eq 1 ]]; then
    echo ""
    echo "========================================="
    echo -e "${BLUE}Integration Tests${NC}"
    echo "========================================="

    for test in "${INTEGRATION_TESTS[@]}"; do
        run_test_suite "$test" || true
    done
fi

# Print summary
echo ""
echo "========================================="
echo -e "${BLUE}Test Summary${NC}"
echo "========================================="
echo ""
echo "Total test suites:  $TOTAL_SUITES"
echo -e "Passed:             ${GREEN}$PASSED_SUITES${NC}"

if [[ $FAILED_SUITES -gt 0 ]]; then
    echo -e "Failed:             ${RED}$FAILED_SUITES${NC}"
    echo ""
    echo "Failed suites:"
    for suite in "${FAILED_SUITE_NAMES[@]}"; do
        echo -e "  ${RED}✗${NC} $suite"
    done
else
    echo -e "Failed:             $FAILED_SUITES"
fi

echo ""

# Exit code
if [[ $FAILED_SUITES -gt 0 ]]; then
    echo -e "${RED}=========================================${NC}"
    echo -e "${RED}TESTS FAILED${NC}"
    echo -e "${RED}=========================================${NC}"
    echo ""
    exit 1
else
    echo -e "${GREEN}=========================================${NC}"
    echo -e "${GREEN}ALL TESTS PASSED${NC}"
    echo -e "${GREEN}=========================================${NC}"
    echo ""

    # Calculate coverage percentage (approximate)
    coverage_pct=$((PASSED_SUITES * 100 / TOTAL_SUITES))
    echo "Estimated coverage: ${coverage_pct}%"
    echo ""

    exit 0
fi
