# Test Fixtures

This directory contains test data and mock repositories for integration tests.

## Generated Fixtures

The following test repositories are created dynamically during test execution:
- `integration-test-repo/` - End-to-end audit workflow testing
- `suppress-test-repo/` - Suppression workflow testing
- `ticket-test-repo/` - Ticket creation workflow testing

These are automatically cleaned up after tests complete.

## Adding New Fixtures

To add permanent test fixtures:

1. Create a subdirectory with a descriptive name
2. Add sample vulnerable code or configuration
3. Document the purpose in this README
4. Reference from integration tests

## Example Vulnerable Code Patterns

For creating test cases, use these patterns:

### Critical Findings
- Hardcoded credentials (CWE-798)
- SQL injection (CWE-89)
- Command injection (CWE-78)

### High Findings
- Weak crypto (MD5, SHA-1) (CWE-327)
- Buffer overflows (strcpy) (CWE-120)
- Missing authentication (CWE-306)

### Medium Findings
- Missing rate limiting (CWE-307)
- Information disclosure (CWE-200)
- Session management issues (CWE-384)
