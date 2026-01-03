# SCA Test Suite

Comprehensive test suite for the Security Control Agent (SCA) with unit and integration tests.

## Quick Start

```bash
# Run all tests
make test

# Run only unit tests
make test-unit

# Run only integration tests
make test-integration

# Run with verbose output
make test-all
```

## Test Structure

```
tests/
├── run_tests.sh           # Main test runner
├── unit/                  # Unit tests for individual components
│   ├── test_cli.sh        # CLI argument parsing tests
│   └── test_scope.sh      # Scope exclusion logic tests
├── integration/           # End-to-end workflow tests
│   ├── test_audit_workflow.sh      # Bootstrap → Audit → Report
│   ├── test_suppress_workflow.sh   # Finding suppression
│   └── test_ticket_workflow.sh     # Ticket creation
└── fixtures/              # Test data and mock repositories
    └── README.md          # Fixture documentation
```

## Test Coverage

### Unit Tests (2 suites)
- **test_cli.sh**: CLI wrapper argument handling, help text, command routing
- **test_scope.sh**: File scope generation, exclusion patterns, stats mode

### Integration Tests (3 suites)
- **test_audit_workflow.sh**: End-to-end audit cycle from bootstrap to report
- **test_suppress_workflow.sh**: Interactive and batch suppression with OVERRIDE.md
- **test_ticket_workflow.sh**: GitHub/Jira ticket creation with dry-run mode

## Running Tests

### Via Makefile (Recommended)

```bash
# All tests
make test

# Unit tests only
make test-unit

# Integration tests only
make test-integration

# Verbose output
make test-all
```

### Direct Execution

```bash
# Run test runner directly
./tests/run_tests.sh

# Run specific test suite
./tests/unit/test_cli.sh
./tests/integration/test_audit_workflow.sh
```

### Options

```bash
# Test runner options
./tests/run_tests.sh --unit-only          # Unit tests only
./tests/run_tests.sh --integration-only   # Integration tests only
./tests/run_tests.sh --verbose            # Show detailed output
./tests/run_tests.sh --help               # Show help
```

## CI/CD Integration

Tests run automatically on GitHub Actions for:
- Push to `main` or `develop` branches
- Pull requests to `main` or `develop`
- Manual workflow dispatch

See `.github/workflows/test.yml` for CI configuration.

## Writing New Tests

### Unit Test Template

```bash
#!/usr/bin/env bash
# Unit Tests: [Component Name]
# Brief description of what this test suite covers

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

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
    else
        echo -e "${RED}✗${NC} $test_name"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

# Tests
echo "Test Group: [Group Name]"
assert_equals "expected" "actual" "Test description"

# Summary
if [[ $TESTS_FAILED -gt 0 ]]; then
    exit 1
else
    exit 0
fi
```

### Integration Test Template

```bash
#!/usr/bin/env bash
# Integration Tests: [Workflow Name]
# End-to-end test for [feature]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SCA_BIN="$PROJECT_ROOT/bin/sca"
FIXTURES_DIR="$SCRIPT_DIR/../fixtures"

# Setup
TEST_REPO="$FIXTURES_DIR/test-repo"
mkdir -p "$TEST_REPO"

# Cleanup
cleanup() {
    rm -rf "$TEST_REPO"
}
trap cleanup EXIT

# Test workflow
echo "Test Group: [Workflow Step]"
# ... test commands ...

# Summary
exit 0  # or 1 if failed
```

## Test Best Practices

### 1. Isolation
- Each test suite is independent
- Tests create their own fixtures in `tests/fixtures/`
- Cleanup is automatic via trap handlers

### 2. Assertions
- Use helper functions: `assert_equals`, `assert_contains`, `assert_file_exists`
- Descriptive test names: "Bootstrap creates OVERRIDE.md" not "Test 1"
- Clear error messages showing expected vs actual

### 3. Test Data
- Mock data in integration tests (no real API calls)
- Dry-run mode for external integrations (GitHub, Jira)
- Vulnerable code samples for audit tests

### 4. Coverage Goals
- Unit tests: >90% coverage of core logic
- Integration tests: All major workflows end-to-end
- Edge cases: Empty repos, missing files, invalid input

## Troubleshooting

### Tests Fail with "Permission denied"

```bash
# Make scripts executable
chmod +x tests/run_tests.sh
chmod +x tests/unit/*.sh
chmod +x tests/integration/*.sh
```

### jq not found

```bash
# Install jq
# macOS:
brew install jq

# Ubuntu/Debian:
sudo apt-get install jq

# Fedora:
sudo dnf install jq
```

### shellcheck warnings in CI

```bash
# Run shellcheck locally
make lint

# Fix reported issues
shellcheck bin/sca-suppress.sh
```

### Tests pass locally but fail in CI

- Check environment differences (PATH, installed tools)
- Verify GitHub Actions has required dependencies (jq, bc)
- Check file permissions in CI

## Adding New Test Suites

1. Create test file in `tests/unit/` or `tests/integration/`
2. Follow template structure above
3. Add to appropriate array in `tests/run_tests.sh`:
   ```bash
   UNIT_TESTS=(
       "unit/test_cli.sh"
       "unit/test_scope.sh"
       "unit/test_your_new_test.sh"  # Add here
   )
   ```
4. Test locally: `./tests/run_tests.sh`
5. Update this README with description

## Coverage Report

Current coverage (estimated):
- **Unit Tests**: 2 suites, ~40 assertions
- **Integration Tests**: 3 suites, ~60 assertions
- **Total**: 5 test suites, ~100 assertions

Coverage by component:
- ✅ CLI argument parsing
- ✅ File scope generation
- ✅ Bootstrap workflow
- ✅ Audit report validation
- ✅ Suppression (batch & interactive)
- ✅ Ticket creation (dry-run)
- ⚠️ Filtering logic (tested via CLI, needs dedicated suite)
- ⚠️ Drift comparison (basic test needed)

## Future Enhancements

- [ ] Performance benchmarks (large repos, 100K+ files)
- [ ] Security tests (agent immutability checks)
- [ ] Stress tests (concurrent audits)
- [ ] Mocked AI responses for full audit tests
- [ ] Code coverage measurement (via kcov or similar)
