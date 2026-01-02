#!/usr/bin/env bash
set -euo pipefail

# Generate SUGGESTIONS.md from security report
# Extracts remediation suggestions and excludes overridden findings

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/sca_common.sh
source "$SCRIPT_DIR/../lib/sca_common.sh"

usage() {
  cat <<EOF
Usage: generate-suggestions.sh --report <path> --output <path> [--overrides <path>]

Extracts remediation suggestions from security report and generates SUGGESTIONS.md

Options:
  --report <path>      Input report markdown file
  --output <path>      Output SUGGESTIONS.md path
  --overrides <path>   Optional OVERRIDE.md path (findings to exclude)
  -h, --help           Show this help
EOF
}

REPORT_FILE=""
OUTPUT_FILE=""
OVERRIDES_FILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --report) REPORT_FILE="$2"; shift 2;;
    --output) OUTPUT_FILE="$2"; shift 2;;
    --overrides) OVERRIDES_FILE="$2"; shift 2;;
    -h|--help) usage; exit 0;;
    *) log_error "Unknown arg: $1"; usage; exit 3;;
  esac
done

[[ -z "$REPORT_FILE" ]] && { log_error "--report required"; exit 3; }
[[ -z "$OUTPUT_FILE" ]] && { log_error "--output required"; exit 3; }
[[ ! -f "$REPORT_FILE" ]] && { log_error "Report file not found: $REPORT_FILE"; exit 3; }

# Read override patterns if provided
OVERRIDE_PATTERNS=()
if [[ -n "$OVERRIDES_FILE" ]] && [[ -f "$OVERRIDES_FILE" ]]; then
  log_info "Loading override patterns from $OVERRIDES_FILE"
  # Extract file paths and issue descriptions from OVERRIDE.md
  while IFS= read -r line; do
    # Skip comments and empty lines
    [[ -z "$line" ]] && continue
    [[ "$line" =~ ^# ]] && continue
    # Extract patterns (file paths, issue keywords)
    OVERRIDE_PATTERNS+=("$line")
  done < "$OVERRIDES_FILE"
fi

# Generate SUGGESTIONS.md
cat > "$OUTPUT_FILE" <<'HEADER'
# Security Audit Remediation Suggestions

This file contains actionable remediation suggestions for security findings.

**Auto-generated** from the latest security audit report.
**Excludes**: Issues listed in OVERRIDE.md (accepted risks).

---

HEADER

# Extract findings and remediations from report
IN_CONFIRMED=0
IN_NEEDS_REVIEW=0
CURRENT_SEVERITY=""
CURRENT_FINDING=""
FINDING_COUNTER=0

while IFS= read -r line; do
  # Detect sections
  if [[ "$line" =~ ^##[[:space:]]*Findings[[:space:]]*\(Confirmed\) ]]; then
    IN_CONFIRMED=1
    IN_NEEDS_REVIEW=0
    echo "## Confirmed Findings (Prioritized)" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
    continue
  fi

  if [[ "$line" =~ ^##[[:space:]]*Findings[[:space:]]*\(Needs\ Review\) ]]; then
    IN_CONFIRMED=0
    IN_NEEDS_REVIEW=1
    echo "" >> "$OUTPUT_FILE"
    echo "## Findings Requiring Review" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
    continue
  fi

  # Stop at next major section
  if [[ "$line" =~ ^##[[:space:]]*[^#] ]] && [[ ! "$line" =~ Findings ]]; then
    break
  fi

  # Track severity
  if [[ "$line" =~ ^###[[:space:]]*(Critical|High|Medium|Low) ]]; then
    CURRENT_SEVERITY="${BASH_REMATCH[1]}"
  fi

  # Copy findings to suggestions
  if [[ "$IN_CONFIRMED" -eq 1 ]] || [[ "$IN_NEEDS_REVIEW" -eq 1 ]]; then
    # Check if this line should be excluded (matches override pattern)
    SHOULD_SKIP=0
    for pattern in "${OVERRIDE_PATTERNS[@]}"; do
      if [[ "$line" =~ $pattern ]]; then
        SHOULD_SKIP=1
        log_debug "Skipping overridden finding: $line"
        break
      fi
    done

    if [[ "$SHOULD_SKIP" -eq 0 ]]; then
      echo "$line" >> "$OUTPUT_FILE"
    fi
  fi
done < "$REPORT_FILE"

# Add footer
cat >> "$OUTPUT_FILE" <<'FOOTER'

---

## How to Use This File

1. **Prioritize**: Start with Critical and High severity findings
2. **Assign**: Distribute fixes across team members
3. **Track**: Move completed items to a "Fixed" section or delete
4. **Verify**: Re-run `sca audit` after fixes to confirm resolution
5. **Override**: If a finding is accepted risk, add to OVERRIDE.md

## Override Process

To suppress a finding:
1. Add entry to `OVERRIDE.md` with justification
2. Include file path or unique identifier
3. Example:
```
# Accepted: API key in test fixture (not production)
tests/fixtures/api_test_key.txt

# Accepted: HTTP localhost connection in development
src/config/dev.py:15 - http://localhost:8000
```

FOOTER

log_info "Generated $OUTPUT_FILE with remediation suggestions"
exit 0
