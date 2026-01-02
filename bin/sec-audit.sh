#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/sca_common.sh
source "$SCRIPT_DIR/../lib/sca_common.sh"

# Trap EXIT to ensure cleanup
cleanup() {
  [[ -n "${SCOPE_LIST:-}" ]] && rm -f "$SCOPE_LIST"
  [[ -n "${INV_BUNDLE:-}" ]] && rm -f "$INV_BUNDLE"
  [[ -n "${PROMPT_FILE:-}" ]] && rm -f "$PROMPT_FILE"
}
trap cleanup EXIT

usage() {
  cat <<EOF
Usage: sec-audit.sh [OPTIONS]

Options:
  --repo <path>              Repository root (default: current git root)
  --ctrl-dir <path>          Control directory (default: <repo>/sec-ctrl)
  --agent-dir <path>         SCA agent location
  --readonly-agent           Enforce agent immutability (default: on)
  --no-readonly-agent        Disable agent immutability check
  --format md|json|both      Output format (default: both)
  --enable-deps              Run dependency scanners
  --incremental              Skip if repo unchanged
  --verbose                  Show detailed progress
  -h, --help                 Show this help
EOF
}

# Defaults
REPO="."
CTRL_DIR=""
AGENT_DIR=""
READONLY_AGENT=1
FORMAT="both"
ENABLE_DEPS=0
INCREMENTAL=0
VERBOSE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo) REPO="$2"; shift 2;;
    --ctrl-dir) CTRL_DIR="$2"; shift 2;;
    --agent-dir) AGENT_DIR="$2"; shift 2;;
    --readonly-agent) READONLY_AGENT=1; shift;;
    --no-readonly-agent) READONLY_AGENT=0; shift;;
    --format) FORMAT="$2"; shift 2;;
    --enable-deps) ENABLE_DEPS=1; shift;;
    --incremental) INCREMENTAL=1; shift;;
    --verbose) VERBOSE=1; export SCA_LOG_LEVEL=2; shift;;
    -h|--help) usage; exit 0;;
    *) log_error "Unknown arg: $1"; usage; exit 3;;
  esac
done

# Resolve paths
REPO_ROOT="$(resolve_repo_root "$REPO")"
CTRL_DIR="$(resolve_ctrl_dir "$REPO_ROOT" "$CTRL_DIR")"
AGENT_DIR="$(resolve_agent_dir "$REPO_ROOT" "$AGENT_DIR")"

if [[ -z "$AGENT_DIR" ]]; then
  log_error "Could not resolve agent dir. Provide --agent-dir or set SEC_AUDIT_AGENT_HOME."
  exit 3
fi

log_info "Repo root: $REPO_ROOT"
log_info "Control dir: $CTRL_DIR"
log_info "Agent dir: $AGENT_DIR"

# Enforce read-only agent
if [[ "$READONLY_AGENT" -eq 1 ]]; then
  # Check if writable by current user
  if [[ -w "$AGENT_DIR" ]]; then
    log_error "Agent dir is writable: $AGENT_DIR"
    log_error "Fix: install agent read-only (e.g. root-owned /opt/sca) or chmod -R a-w."
    exit 4
  fi

  # Check if git repo is dirty
  if [[ -d "$AGENT_DIR/.git" ]]; then
    if git -C "$AGENT_DIR" status --porcelain | grep -q .; then
      log_error "Agent checkout is dirty: $AGENT_DIR"
      log_error "Fix: reset/clean agent checkout. Agent must be immutable during audits."
      exit 4
    fi
  fi
fi

# Create control directory structure
mkdir -p "$CTRL_DIR"/{state,reports,cache,config,invariants/languages}

# Ensure default ignore file exists
if [[ ! -f "$CTRL_DIR/config/ignore.paths" ]]; then
  log_info "Creating default ignore.paths"
  cat > "$CTRL_DIR/config/ignore.paths" <<'EOF'
sec-ctrl/
tools/sec-audit-agent/
.git/
node_modules/
dist/
build/
target/
vendor/
.venv/
__pycache__/
EOF
fi

# Generate scope
log_info "Generating scope..."
SCOPE_LIST="$(mktemp)"
"$SCRIPT_DIR/repo-scope.sh" --repo "$REPO_ROOT" --ctrl-dir "$CTRL_DIR" --agent-dir "$AGENT_DIR" > "$SCOPE_LIST"

SCOPE_SIZE=$(wc -l < "$SCOPE_LIST")
log_info "Scope: $SCOPE_SIZE files"

# Check incremental mode
if [[ "$INCREMENTAL" -eq 1 ]]; then
  SCOPE_HASH="$(sha256sum "$SCOPE_LIST" | awk '{print $1}')"
  if [[ -f "$CTRL_DIR/state/scope-hash.txt" ]]; then
    PREV_HASH="$(cat "$CTRL_DIR/state/scope-hash.txt")"
    if [[ "$SCOPE_HASH" == "$PREV_HASH" ]]; then
      log_info "Scope unchanged, skipping (--incremental mode)"
      exit 0
    fi
  fi
  echo "$SCOPE_HASH" > "$CTRL_DIR/state/scope-hash.txt"
fi

# Language detection
log_info "Detecting languages..."
LANGS=()
if grep -qE '\.(c|h|cc|cpp|hpp|cxx)$' "$SCOPE_LIST"; then LANGS+=("c-cpp"); fi
if grep -qE '\.go$' "$SCOPE_LIST"; then LANGS+=("go"); fi
if grep -qE '\.(java|kt|scala)$' "$SCOPE_LIST"; then LANGS+=("java"); fi
if grep -qE '\.(js|ts|tsx|jsx|mjs)$' "$SCOPE_LIST"; then LANGS+=("javascript-typescript"); fi
if grep -qE '\.py$' "$SCOPE_LIST"; then LANGS+=("python"); fi
if grep -qE '\.rs$' "$SCOPE_LIST"; then LANGS+=("rust"); fi

log_info "Languages: ${LANGS[*]:-none}"

# Build invariant bundle
INV_BUNDLE="$(mktemp)"
cat "$AGENT_DIR/invariants/global.md" > "$INV_BUNDLE"

# Add crypto/key material invariants if they exist
if [[ -f "$AGENT_DIR/invariants/crypto/secrets.md" ]]; then
  echo -e "\n\n# Cryptography & Key Material Invariants\n" >> "$INV_BUNDLE"
  cat "$AGENT_DIR/invariants/crypto/secrets.md" >> "$INV_BUNDLE"
fi

# Add LLM invariants if they exist
if [[ -f "$AGENT_DIR/invariants/llm/global.md" ]]; then
  echo -e "\n\n# LLM/Agent Security Invariants\n" >> "$INV_BUNDLE"
  cat "$AGENT_DIR/invariants/llm/global.md" >> "$INV_BUNDLE"
fi

# Add language-specific invariants
for L in "${LANGS[@]}"; do
  if [[ -f "$AGENT_DIR/invariants/languages/$L.md" ]]; then
    echo -e "\n\n# Language invariants: $L\n" >> "$INV_BUNDLE"
    cat "$AGENT_DIR/invariants/languages/$L.md" >> "$INV_BUNDLE"
  fi
done

# Run dependency scan if enabled
if [[ "$ENABLE_DEPS" -eq 1 ]]; then
  log_info "Running dependency scanners..."
  "$SCRIPT_DIR/deps-scan.sh" --repo "$REPO_ROOT" --ctrl-dir "$CTRL_DIR" || log_warn "Dependency scan had warnings"
fi

# Prepare output files
TS="$(date -u +"%Y%m%dT%H%M%SZ")"
OUT_MD="$CTRL_DIR/reports/security-audit.$TS.md"
OUT_JSON="$CTRL_DIR/reports/security-audit.$TS.json"
OUT_LATEST_MD="$CTRL_DIR/reports/security-audit.latest.md"
OUT_LATEST_JSON="$CTRL_DIR/reports/security-audit.latest.json"

CLAUDE_BIN="${CLAUDE_CODE_BIN:-claude}"

# Build prompt
PROMPT_FILE="$(mktemp)"
cat > "$PROMPT_FILE" <<EOF
You are a security audit agent. Follow the runbook and output strictly in the report template.

## Runbook
$(cat "$AGENT_DIR/prompts/RUNBOOK.md")

## Report Template
$(cat "$AGENT_DIR/prompts/REPORT_TEMPLATE.md")

## System Guidance
$(cat "$AGENT_DIR/prompts/SYSTEM.md")

## Invariants
$(cat "$INV_BUNDLE")

## Repo scope
Repo root: $REPO_ROOT
Control dir: $CTRL_DIR
Exclude: sec-ctrl/ and agent directory
Languages detected: ${LANGS[*]:-none}

## File list (analyze these; do not analyze excluded paths)
$(cat "$SCOPE_LIST")

## Override Rules (findings to suppress)
The user has specified these findings should be SUPPRESSED and NOT reported:
$(if [[ -f "$CTRL_DIR/OVERRIDE.md" ]]; then cat "$CTRL_DIR/OVERRIDE.md"; else echo "No overrides defined."; fi)

IMPORTANT: Do NOT report any findings that match the patterns or descriptions in OVERRIDE.md above. These have been explicitly accepted by the security team.

## Instructions
- Cite file paths for every finding (include line numbers if possible).
- Separate confirmed vs suspicious/needs-review.
- Include OWASP-style issues, dependency/CVE risk spots, secrets, crypto misuse, authn/authz, injection, deserialization, path traversal, SSRF, XSS, CSRF, logging/PII.
- If you cannot confirm, say what evidence is missing.
- EXCLUDE any findings mentioned in the Override Rules section above.
- For each confirmed finding, provide a concrete remediation suggestion.
- End with a prioritized fix plan (top 10).
EOF

# Invoke model (capture both stdout and stderr)
log_info "Invoking model runner: $CLAUDE_BIN"
if ! "$CLAUDE_BIN" code < "$PROMPT_FILE" > "$OUT_MD" 2>&1; then
  log_error "Model runner failed"
  exit 5
fi

# Copy to latest
cp -f "$OUT_MD" "$OUT_LATEST_MD"

# Generate JSON if requested (basic conversion for v1)
if [[ "$FORMAT" == "json" ]] || [[ "$FORMAT" == "both" ]]; then
  log_info "Generating JSON report..."
  # Simple JSON wrapper (v1: wrap markdown in JSON structure)
  cat > "$OUT_JSON" <<EOF
{
  "metadata": {
    "timestamp": "$TS",
    "repo": "$REPO_ROOT",
    "ctrl_dir": "$CTRL_DIR"
  },
  "markdown_report": $(jq -Rs . < "$OUT_MD")
}
EOF
  cp -f "$OUT_JSON" "$OUT_LATEST_JSON"
fi

# Write state
log_info "Writing state..."
printf "%s\n" "$TS" > "$CTRL_DIR/state/last-run.txt"
sha="$( (cd "$REPO_ROOT" && git rev-parse HEAD 2>/dev/null) || echo "nogit" )"
printf "%s\n" "$sha" > "$CTRL_DIR/state/repo-fingerprint.txt"
cp -f "$SCOPE_LIST" "$CTRL_DIR/state/last-scope.txt"

# Generate SUGGESTIONS.md from report
log_info "Generating SUGGESTIONS.md..."
"$SCRIPT_DIR/generate-suggestions.sh" --report "$OUT_MD" --output "$CTRL_DIR/SUGGESTIONS.md" --overrides "$CTRL_DIR/OVERRIDE.md" || log_warn "Failed to generate suggestions"

# Parse report for exit code
log_info "Parsing report for findings..."
"$SCRIPT_DIR/report-parser.sh" "$OUT_MD"
PARSE_EXIT=$?

log_info "Wrote: $OUT_MD"
log_info "Latest: $OUT_LATEST_MD"
log_info "Suggestions: $CTRL_DIR/SUGGESTIONS.md"

exit $PARSE_EXIT
