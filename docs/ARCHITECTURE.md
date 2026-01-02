# SCA Architecture Documentation

## Overview

**Security Control Agent (SCA)** is a read-only, invariant-driven security auditing tool designed for safety-critical environments. It analyzes codebases for security vulnerabilities without modifying the subject repository.

### Core Principles

1. **Immutability**: Subject repository is never modified
2. **Separation**: All writes go to dedicated control directory
3. **Invariant-Driven**: Uses predefined security patterns, not heuristics
4. **Evidence-Based**: Every finding cites file path + code context
5. **CI/CD Ready**: Deterministic exit codes for automated pipelines

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         User / CI Pipeline                       │
└────────────────────┬────────────────────────────────────────────┘
                     │
                     ▼
              ┌──────────────┐
              │   bin/sca    │  (Python CLI - arg parsing, dispatch)
              └──────┬───────┘
                     │
        ┌────────────┼────────────┐
        │            │            │
        ▼            ▼            ▼
┌───────────┐ ┌──────────┐ ┌──────────┐
│ audit     │ │  scope   │ │   diff   │ ...
│ (shell)   │ │ (shell)  │ │ (shell)  │
└─────┬─────┘ └────┬─────┘ └────┬─────┘
      │            │            │
      │            └────────────┴─── Uses lib/sca_common.sh
      │                              (path resolution, logging)
      ▼
┌─────────────────────────────────────────────────────────────┐
│              bin/sec-audit.sh (Orchestrator)                │
│                                                             │
│  1. Resolve paths (repo, ctrl-dir, agent-dir)              │
│  2. Validate agent immutability                            │
│  3. Generate file scope                                    │
│  4. Load invariants from agent-dir                         │
│  5. Call LLM API with code + invariants                    │
│  6. Parse response → Markdown & JSON reports               │
│  7. Apply OVERRIDE.md rules                                │
│  8. Generate SUGGESTIONS.md                                │
│  9. Determine exit code (0/2/3/4/5)                        │
└─────────────────────────────────────────────────────────────┘
      │                            │
      ├── Reads ─────────────────►│
      │   ┌────────────────────┐  │
      │   │ Subject Repository │  │
      │   │  (READ-ONLY)       │  │
      │   └────────────────────┘  │
      │                            │
      ├── Reads ─────────────────►│
      │   ┌────────────────────┐  │
      │   │   Agent Directory  │  │
      │   │  /opt/sca          │  │
      │   │  (IMMUTABLE)       │  │
      │   │  - invariants/     │  │
      │   │  - templates/      │  │
      │   │  - bin/            │  │
      │   └────────────────────┘  │
      │                            │
      └── Writes ────────────────►│
          ┌────────────────────┐  │
          │ Control Directory  │  │
          │  sec-ctrl/         │  │
          │  (WRITE)           │  │
          │  - config/         │  │
          │  - reports/        │  │
          │  - state/          │  │
          │  - OVERRIDE.md     │  │
          │  - SUGGESTIONS.md  │  │
          └────────────────────┘  │
                                  ▼
                            ┌──────────────┐
                            │   LLM API    │
                            │ (Claude/GPT) │
                            └──────────────┘
```

---

## Component Details

### 1. CLI Layer (`bin/sca`)

**Technology**: Python 3.7+ with argparse

**Responsibilities**:
- Parse command-line arguments
- Merge environment variables with CLI options
- Dispatch to appropriate shell script
- Provide unified --help documentation

**Key Functions**:
```python
def merge_env_and_args(args, env_var, arg_value):
    """CLI args take precedence over env vars"""
    if arg_value:
        return arg_value
    return os.environ.get(env_var, "")
```

**Exit Codes**:
- Inherits exit code from dispatched shell script
- No logic - pure dispatch layer

---

### 2. Core Library (`lib/sca_common.sh`)

**Technology**: POSIX-compatible shell (bash 4.0+)

**Responsibilities**:
- Portable path resolution (Linux + macOS)
- Repository root detection (git-aware)
- Control directory resolution (absolute/relative)
- Agent directory auto-detection
- Structured logging (INFO, WARN, ERROR, DEBUG)

**Key Functions**:

#### `realpath_portable()`
```bash
# Portable realpath (handles Linux + macOS)
realpath_portable() {
  local path="$1"
  if command -v realpath >/dev/null 2>&1; then
    realpath "$path"
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c "import os,sys; print(os.path.realpath(sys.argv[1]))" "$path"
  else
    echo "$(cd "$(dirname "$path")" && pwd -P)/$(basename "$path")"
  fi
}
```

#### `resolve_ctrl_dir()`
```bash
# Resolve control directory (absolute canonical path)
resolve_ctrl_dir() {
  local repo_root="$1"
  local ctrl_arg="$2"

  if [[ -n "$ctrl_arg" ]]; then
    # CLI arg provided
    [[ "$ctrl_arg" = /* ]] && realpath_portable "$ctrl_arg" || realpath_portable "$repo_root/$ctrl_arg"
  elif [[ -n "${SEC_CTRL_DIR:-}" ]]; then
    # Environment variable
    [[ "${SEC_CTRL_DIR}" = /* ]] && realpath_portable "${SEC_CTRL_DIR}" || realpath_portable "$repo_root/${SEC_CTRL_DIR}"
  else
    # Default
    realpath_portable "$repo_root/sec-ctrl"
  fi
}
```

#### Logging
```bash
# Log functions with level-aware output
log_info()  { [[ "${SCA_LOG_LEVEL:-1}" -ge 1 ]] && echo "[INFO] $*" >&2; return 0; }
log_warn()  { echo "[WARN] $*" >&2; return 0; }
log_error() { echo "[ERROR] $*" >&2; return 0; }
log_debug() { [[ "${SCA_LOG_LEVEL:-1}" -ge 2 ]] && echo "[DEBUG] $*" >&2; return 0; }
```

**Critical Design**: All log functions return 0 to prevent `set -e` failures.

---

### 3. Scope Generator (`bin/repo-scope.sh`)

**Responsibilities**:
- Determine which files will be analyzed
- Apply exclusion rules
- Generate sorted file list

**Algorithm**:
```
1. Get base file list:
   - If git repo: `git ls-files` (tracked files only)
   - Else: `find . -type f` (all files)

2. Build exclusion list:
   - Always: DEFAULT_EXCLUDES (node_modules/, .git/, dist/, etc.)
   - Always: Control directory path
   - Always: Agent directory path (if inside repo)
   - Optional: Custom patterns from sec-ctrl/config/ignore.paths

3. Filter files:
   - For each exclusion pattern:
     - Convert glob (*) to regex (.*)
     - grep -vE to remove matching files

4. Output:
   - One file path per line
   - Relative to repository root
   - Sorted by modification time (newest first)
```

**Exclusion Pattern Matching**:
```bash
for ex in "${EXCLUDES[@]}"; do
  pattern="${ex//\*/.*}"  # Convert glob to regex
  pattern="^${pattern}"    # Anchor to start
  FILTERED="$(echo "$FILTERED" | grep -vE "$pattern" || true)"
done
```

---

### 4. Audit Orchestrator (`bin/sec-audit.sh`)

**Responsibilities**:
- Validate environment (agent immutability, paths)
- Load invariants from agent directory
- Construct LLM prompt with code + invariants
- Call LLM API
- Parse response to structured format
- Apply override rules
- Generate suggestions
- Determine exit code

**Workflow**:

```bash
# 1. Setup & Validation
trap cleanup EXIT  # Ensure cleanup on any exit
validate_agent_immutable "$AGENT_DIR"  # Exit 4 if writable/dirty

# 2. Generate Scope
FILES=$("$BIN_DIR/repo-scope.sh" --repo "$REPO" --ctrl-dir "$CTRL_DIR")
SCOPE_HASH=$(echo "$FILES" | sha256sum | awk '{print $1}')

# 3. Incremental Mode Check
if [[ "$INCREMENTAL" = "true" ]] && [[ -f "$CTRL_DIR/state/scope-hash.txt" ]]; then
  PREV_HASH=$(cat "$CTRL_DIR/state/scope-hash.txt")
  if [[ "$SCOPE_HASH" = "$PREV_HASH" ]]; then
    echo "No changes since last audit, skipping"
    exit 0
  fi
fi

# 4. Load Invariants
INVARIANTS=$(find "$AGENT_DIR/invariants" -name "*.md" | xargs cat)

# 5. Load Override Rules
OVERRIDES=""
if [[ -f "$CTRL_DIR/OVERRIDE.md" ]]; then
  OVERRIDES=$(cat "$CTRL_DIR/OVERRIDE.md")
fi

# 6. Construct LLM Prompt
PROMPT="
You are a security auditor. Analyze the following codebase for security issues.

## Invariants (security patterns to detect):
$INVARIANTS

## Override Rules (findings to suppress):
$OVERRIDES

IMPORTANT: Do NOT report any findings that match patterns in Override Rules.

## Code to analyze:
$(for file in $FILES; do
  echo "--- $file ---"
  cat "$REPO/$file"
done)

Generate a detailed security audit report in Markdown format.
"

# 7. Call LLM API
RESPONSE=$(call_llm_api "$PROMPT")

# 8. Save Reports
echo "$RESPONSE" > "$CTRL_DIR/reports/security-audit.latest.md"
convert_to_json "$RESPONSE" > "$CTRL_DIR/reports/security-audit.latest.json"

# 9. Generate Suggestions
"$BIN_DIR/generate-suggestions.sh" \
  --report "$CTRL_DIR/reports/security-audit.latest.md" \
  --overrides "$CTRL_DIR/OVERRIDE.md" \
  > "$CTRL_DIR/SUGGESTIONS.md"

# 10. Determine Exit Code
CRITICAL_HIGH_COUNT=$("$BIN_DIR/report-parser.sh" "$CTRL_DIR/reports/security-audit.latest.md")
if [[ "$CRITICAL_HIGH_COUNT" -gt 0 ]]; then
  exit 2  # Findings exist
else
  exit 0  # Clean
fi
```

**Immutability Checks**:
```bash
validate_agent_immutable() {
  local agent_dir="$1"

  # Check writable
  if [[ -w "$agent_dir" ]]; then
    log_error "Agent directory is writable (must be read-only)"
    exit 4
  fi

  # Check git-dirty (if git repo)
  if git -C "$agent_dir" status --porcelain 2>/dev/null | grep -q .; then
    log_error "Agent directory has uncommitted changes"
    exit 4
  fi
}
```

---

### 5. Report Parser (`bin/report-parser.sh`)

**Responsibilities**:
- Extract Critical/High finding counts from Markdown report
- Determine exit code (0 if clean, 2 if findings)

**Algorithm**:
```bash
# Parse Markdown headings
in_confirmed=false
in_critical=false
in_high=false

while IFS= read -r line; do
  case "$line" in
    "## Findings (Confirmed)")
      in_confirmed=true
      ;;
    "### Critical")
      [[ "$in_confirmed" = true ]] && in_critical=true
      ;;
    "### High")
      [[ "$in_confirmed" = true ]] && in_high=true
      ;;
    "### Medium"|"### Low"|"## "*|"# "*)
      in_critical=false
      in_high=false
      ;;
  esac

  if [[ "$in_critical" = true ]] || [[ "$in_high" = true ]]; then
    if [[ "$line" =~ ^\*\*Evidence\*\* ]]; then
      ((count++))
    fi
  fi
done < "$report_file"

[[ "$count" -gt 0 ]] && exit 2 || exit 0
```

---

### 6. Suggestions Generator (`bin/generate-suggestions.sh`)

**Responsibilities**:
- Extract remediation suggestions from report
- Exclude findings matching OVERRIDE.md patterns
- Generate actionable SUGGESTIONS.md

**Algorithm**:
```bash
# Read override patterns
OVERRIDE_PATTERNS=()
while IFS= read -r line; do
  [[ "$line" =~ ^# ]] && continue  # Skip comments
  [[ -z "$line" ]] && continue     # Skip blank lines
  OVERRIDE_PATTERNS+=("$line")
done < "$OVERRIDES_FILE"

# Parse report, extract findings
while IFS= read -r line; do
  if [[ "$line" =~ ^\*\*Evidence\*\*:.*\`(.+)\` ]]; then
    evidence="${BASH_REMATCH[1]}"

    # Check if overridden
    skip=false
    for pattern in "${OVERRIDE_PATTERNS[@]}"; do
      if [[ "$evidence" =~ $pattern ]]; then
        skip=true
        break
      fi
    done

    [[ "$skip" = false ]] && echo "$line"  # Include in suggestions
  fi
done < "$REPORT_FILE"
```

---

### 7. Diff Analyzer (`bin/sec-diff.sh`)

**Responsibilities**:
- Compare current report with previous
- Show security drift (findings added/removed)
- Track changes over time

**Algorithm**:
```bash
# Find most recent previous report
CURRENT="$CTRL_DIR/reports/security-audit.latest.md"
PREVIOUS=$(ls -t "$CTRL_DIR/reports/security-audit."*.md | grep -v latest | head -1)

# Extract finding counts by severity
extract_counts() {
  local report="$1"
  grep "^### Critical" -A 100 "$report" | grep -c "^\*\*Evidence\*\*" || echo 0
  grep "^### High" -A 100 "$report" | grep -c "^\*\*Evidence\*\*" || echo 0
  # ... similar for Medium, Low
}

# Compare
CURR_CRITICAL=$(extract_counts "$CURRENT" | head -1)
PREV_CRITICAL=$(extract_counts "$PREVIOUS" | head -1)
DELTA_CRITICAL=$((CURR_CRITICAL - PREV_CRITICAL))

# Output
echo "Findings:"
echo "  Critical: $PREV_CRITICAL → $CURR_CRITICAL (Δ $DELTA_CRITICAL)"
```

---

## Security Model

### Threat Model

**In Scope**:
- Tampering with invariants (mitigated by agent immutability)
- Tampering with reports (mitigated by timestamped archives)
- Bypassing findings via OVERRIDE.md abuse (mitigated by git audit trail)
- Information disclosure via reports (mitigated by .gitignore guidance)

**Out of Scope**:
- LLM API compromise (trust boundary)
- Host OS compromise (assumes trusted execution environment)
- Supply chain attacks on agent installation (assumes verified downloads)

### Security Boundaries

```
┌─────────────────────────────────────────────────────────┐
│                   Untrusted Zone                        │
│  ┌────────────────────────────────────────┐            │
│  │      Subject Repository (READ)          │            │
│  │  - May contain malicious code           │            │
│  │  - Analyzed but not executed            │            │
│  │  - Never modified                       │            │
│  └────────────────────────────────────────┘            │
└─────────────────────────────────────────────────────────┘
                        │ Read-only
                        ▼
┌─────────────────────────────────────────────────────────┐
│                   Trusted Zone                          │
│  ┌────────────────────────────────────────┐            │
│  │   Agent Directory (READ-ONLY, VERIFIED) │            │
│  │  - Immutability enforced (exit 4)       │            │
│  │  - Contains security invariants         │            │
│  │  - Version-controlled                   │            │
│  └────────────────────────────────────────┘            │
│  ┌────────────────────────────────────────┐            │
│  │   Control Directory (WRITE)             │            │
│  │  - All audit artifacts                  │            │
│  │  - May contain sensitive snippets       │            │
│  │  - Excluded from git (reports/)         │            │
│  └────────────────────────────────────────┘            │
└─────────────────────────────────────────────────────────┘
                        │ HTTPS/TLS
                        ▼
┌─────────────────────────────────────────────────────────┐
│              External Trust Boundary                    │
│  ┌────────────────────────────────────────┐            │
│  │         LLM API (Claude/GPT)            │            │
│  │  - Receives code + invariants           │            │
│  │  - Returns security findings            │            │
│  │  - Assumed trustworthy                  │            │
│  └────────────────────────────────────────┘            │
└─────────────────────────────────────────────────────────┘
```

### Access Control

| Component | Read | Write | Execute |
|-----------|------|-------|---------|
| Subject Repo | SCA | ❌ | ❌ |
| Agent Dir | SCA | ❌ | ✓ (bin/) |
| Control Dir | SCA | SCA | ❌ |
| LLM API | ❌ | ❌ | N/A (external) |

---

## Data Flow

### Audit Flow

```
1. User: sca audit
   ↓
2. CLI parses args → dispatches to sec-audit.sh
   ↓
3. Load config:
   - REPO_ROOT = resolve_repo_root()
   - CTRL_DIR = resolve_ctrl_dir()
   - AGENT_DIR = resolve_agent_dir()
   ↓
4. Validate agent immutability:
   - Check writable: test -w $AGENT_DIR
   - Check git-dirty: git status --porcelain
   → Exit 4 if failed
   ↓
5. Generate scope:
   - repo-scope.sh → FILE_LIST
   - Exclude: ctrl-dir, agent-dir, .git/, node_modules/
   ↓
6. Load invariants:
   - cat $AGENT_DIR/invariants/**/*.md → INVARIANTS
   ↓
7. Load overrides:
   - cat $CTRL_DIR/OVERRIDE.md → OVERRIDES
   ↓
8. Construct prompt:
   - Invariants + Overrides + Code → LLM_PROMPT
   ↓
9. Call LLM API:
   - POST https://api.anthropic.com/v1/messages
   - Body: { model: "claude", messages: [...] }
   → LLM_RESPONSE
   ↓
10. Parse response:
    - Extract findings by severity
    - Format as Markdown → security-audit.latest.md
    - Format as JSON → security-audit.latest.json
    ↓
11. Generate suggestions:
    - Extract remediations from report
    - Exclude overridden findings
    → SUGGESTIONS.md
    ↓
12. Determine exit code:
    - Count Critical/High findings
    - Exit 2 if > 0, else Exit 0
    ↓
13. User sees:
    - Reports in sec-ctrl/reports/
    - Suggestions in sec-ctrl/SUGGESTIONS.md
    - Exit code (0/2/3/4/5)
```

---

## File System Layout

```
/opt/sca/                       # Agent installation (read-only)
├── bin/
│   ├── sca                     # Python CLI dispatcher
│   ├── sec-audit.sh            # Main audit orchestrator
│   ├── repo-scope.sh           # Scope generator
│   ├── report-parser.sh        # Exit code determiner
│   ├── generate-suggestions.sh # Suggestion generator
│   ├── sec-diff.sh             # Drift analyzer
│   ├── sec-bootstrap.sh        # Control dir initializer
│   └── deps-scan.sh            # Dependency scanner
├── lib/
│   └── sca_common.sh           # Shared library functions
├── invariants/
│   ├── global.md               # Cross-language invariants
│   ├── crypto/                 # Cryptography invariants
│   │   ├── secrets.md
│   │   ├── WEAK_ALGORITHMS.md
│   │   └── FPE.md
│   ├── data-protection/        # Data protection invariants
│   │   ├── logging.md
│   │   └── database.md
│   ├── languages/              # Language-specific invariants
│   │   ├── c-cpp.md
│   │   ├── go.md
│   │   ├── java.md
│   │   ├── python.md
│   │   └── ...
│   ├── llm/                    # LLM security invariants
│   │   └── global.md
│   └── documentation/          # Documentation invariants
│       └── completeness.md
├── templates/sec-ctrl/         # Bootstrap templates
│   ├── README.md
│   ├── OVERRIDE.md
│   └── config/ignore.paths
├── docs/                       # Documentation
│   ├── USAGE.md
│   ├── OVERRIDE_GUIDE.md
│   ├── ARCHITECTURE.md         # This file
│   └── man/                    # Man pages
│       ├── sca.1
│       ├── sca-audit.1
│       ├── sca-scope.1
│       ├── sca-diff.1
│       └── sca-bootstrap.1
├── tests/                      # Test suite
│   ├── test_cli.sh
│   ├── test_scope.sh
│   └── test_integration.sh
├── Makefile                    # Build/install targets
├── INSTALL.md                  # Installation guide
├── CHANGELOG_V1.md             # Change log
└── README.md                   # Project overview

/path/to/subject/repo/          # Subject repository (read-only)
├── sec-ctrl/                   # Control directory (write)
│   ├── README.md
│   ├── OVERRIDE.md             # User-maintained
│   ├── SUGGESTIONS.md          # Auto-generated
│   ├── config/
│   │   └── ignore.paths        # Custom exclusions
│   ├── reports/
│   │   ├── security-audit.latest.md
│   │   ├── security-audit.latest.json
│   │   ├── security-audit.20240115_120000.md  # Archived
│   │   └── deps/               # Dependency scans
│   ├── state/
│   │   ├── last-run.txt
│   │   ├── repo-fingerprint.txt
│   │   └── scope-hash.txt
│   └── cache/
│       └── last-scope.txt
├── src/                        # Application code (analyzed)
│   └── ...
└── ... (rest of codebase)
```

---

## Extension Points

### 1. Custom Invariants

Add project-specific security checks:

```bash
# sec-ctrl/invariants/local-overrides.md

# Invariant: Require security headers

All HTTP responses MUST include security headers:
- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff
- Content-Security-Policy: ...

Severity: High
```

Agent loads custom invariants during audit:
```bash
INVARIANTS=$(cat "$AGENT_DIR/invariants/**/*.md" "$CTRL_DIR/invariants/**/*.md" 2>/dev/null)
```

### 2. Custom Dependency Scanners

Add new scanners to `bin/deps-scan.sh`:

```bash
# Add Gradle dependency check
if [[ -f "build.gradle" ]]; then
  log_info "Running Gradle dependency-check"
  ./gradlew dependencyCheckAnalyze > "$DEPS_DIR/gradle-$(date +%Y%m%d_%H%M%S).txt"
fi
```

### 3. Custom Report Formats

Add new output formats:

```bash
# Add SARIF output
if [[ "$FORMAT" = "sarif" ]]; then
  convert_to_sarif "$MARKDOWN_REPORT" > "$CTRL_DIR/reports/security-audit.latest.sarif"
fi
```

### 4. Integration Hooks

Add pre/post audit hooks:

```bash
# Pre-audit hook
if [[ -x "$CTRL_DIR/hooks/pre-audit.sh" ]]; then
  "$CTRL_DIR/hooks/pre-audit.sh"
fi

# Run audit
...

# Post-audit hook
if [[ -x "$CTRL_DIR/hooks/post-audit.sh" ]]; then
  "$CTRL_DIR/hooks/post-audit.sh" "$EXIT_CODE" "$REPORT_FILE"
fi
```

---

## Performance Considerations

### Scope Optimization

- Use `git ls-files` (fast) instead of `find` when possible
- Cache scope between runs (incremental mode)
- Exclude large binary/generated files early

### LLM API Optimization

- Incremental mode skips unchanged repositories (no API call)
- Batch related files in single prompt (reduces round-trips)
- Use cheaper models for low-risk code (if multi-tier pricing)

### Report Generation

- Stream output to files (don't buffer in memory)
- Use efficient JSON parsing (jq, not grep)
- Compress archived reports (gzip)

---

## Error Handling

### Exit Code Strategy

```
0: Success (no critical/high findings)
   → CI: Continue

2: Findings exist
   → CI: Fail, block merge

3: Incomplete (config error)
   → CI: Warn, allow merge with manual review

4: Security violation (agent tampered)
   → CI: Fail immediately, alert security team

5: Internal error (bug)
   → CI: Warn, retry, alert on-call
```

### Error Recovery

- Cleanup trap ensures temp files removed
- Atomic writes (write to .tmp, mv to final)
- Backup before overwrite (--force mode)
- Detailed error messages with remediation

---

## Testing Strategy

### Unit Tests
- `tests/test_cli.sh`: CLI argument parsing
- `tests/test_scope.sh`: Scope exclusion logic
- Individual function tests in isolation

### Integration Tests
- `tests/test_integration.sh`: End-to-end audit workflow
- Mock LLM responses for deterministic results
- Verify all hard constraints

### Security Tests
- Agent immutability enforcement
- Path traversal prevention (ctrl-dir/agent-dir exclusions)
- Override pattern injection (ensure no code execution)

### Regression Tests
- Archive known-good reports
- Compare new audit results with baseline
- Flag unexpected changes

---

## Deployment Models

### Model 1: System-Wide Install (Recommended)

```bash
sudo make install PREFIX=/opt/sca
sudo chown -R root:root /opt/sca
sudo chmod -R a-w /opt/sca
export PATH="/opt/sca/bin:$PATH"
```

**Pros**: Immutability enforced by OS permissions
**Cons**: Requires sudo for install

### Model 2: User Install

```bash
make install-user  # Installs to ~/.local/sca
export PATH="$HOME/.local/sca/bin:$PATH"
```

**Pros**: No sudo required
**Cons**: User can modify agent directory (exit 4 risk)

### Model 3: Container

```dockerfile
FROM ubuntu:22.04
COPY sca/ /opt/sca
RUN chmod -R a-w /opt/sca
USER nobody
ENTRYPOINT ["/opt/sca/bin/sca"]
```

**Pros**: Guaranteed immutability, reproducible
**Cons**: Requires Docker, overhead

---

## Future Enhancements

### Planned (v2.0)
- SARIF output format (IDE integration)
- Web UI for report viewing
- Real-time monitoring mode (watch files)
- Multi-repository batch audits

### Under Consideration
- Custom invariant DSL (beyond Markdown)
- Machine learning for false positive reduction
- Automatic fix application (with approval)
- Integration with SIEM/SOAR platforms

---

## Compliance Mapping

| Requirement | Implementation |
|-------------|----------------|
| **PCI-DSS 6.5** (Secure development) | Invariants detect OWASP Top 10 |
| **PCI-DSS 11.3** (Penetration testing) | Regular audits simulate security review |
| **HIPAA § 164.308(a)(8)** (Evaluation) | Audit reports document security posture |
| **SOC 2 CC6.1** (Logical access) | Authorization invariants |
| **GDPR Art. 25** (Security by design) | Invariant-driven development |
| **NIST SP 800-53** (SA-11) | Developer security testing |

---

## Support & Contributing

- **Documentation**: `/opt/sca/docs/`
- **Issues**: https://github.com/your-org/sca/issues
- **Security**: security@example.com (for vulnerabilities)
- **Discussions**: https://github.com/your-org/sca/discussions

---

## Authors

Built for safety-critical environments requiring strict compliance.

## License

[Your License]

---

**Document Version**: 1.0
**Last Updated**: 2026-01-02
**Status**: Production
