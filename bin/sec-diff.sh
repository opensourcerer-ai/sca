#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/sca_common.sh
source "$SCRIPT_DIR/../lib/sca_common.sh"

usage() {
  cat <<EOF
Usage: sec-diff.sh [OPTIONS]

Options:
  --repo <path>              Repository root
  --ctrl-dir <path>          Control directory
  --format summary|detailed  Output format (default: summary)
  -h, --help                 Show this help
EOF
}

REPO="."
CTRL_DIR=""
FORMAT="summary"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo) REPO="$2"; shift 2;;
    --ctrl-dir) CTRL_DIR="$2"; shift 2;;
    --format) FORMAT="$2"; shift 2;;
    -h|--help) usage; exit 0;;
    *) log_error "Unknown arg: $1"; usage; exit 3;;
  esac
done

REPO_ROOT="$(resolve_repo_root "$REPO")"
CTRL_DIR="$(resolve_ctrl_dir "$REPO_ROOT" "$CTRL_DIR")"

LATEST="$CTRL_DIR/reports/security-audit.latest.md"

if [[ ! -f "$LATEST" ]]; then
  log_error "No latest report found. Run 'sca audit' first."
  exit 3
fi

# Find previous report (second-most recent .md file)
PREV="$(find "$CTRL_DIR/reports" -name 'security-audit.*.md' -type f | sort -r | sed -n '2p')"

if [[ -z "$PREV" ]] || [[ ! -f "$PREV" ]]; then
  log_error "No previous report found for comparison."
  exit 3
fi

log_info "Comparing:"
log_info "  Previous: $(basename "$PREV")"
log_info "  Latest:   security-audit.latest.md"

# Extract metadata
PREV_SHA="$(grep -E '^- Commit/Revision:' "$PREV" | sed 's/.*: //' || echo "unknown")"
CURR_SHA="$(grep -E '^- Commit/Revision:' "$LATEST" | sed 's/.*: //' || echo "unknown")"

# Count findings (simple heuristic: count bullets under Confirmed sections)
count_findings() {
  local file="$1"
  local severity="$2"
  grep -A 50 "^## Findings (Confirmed)" "$file" | grep -A 20 "^### $severity" | grep -cE '^- ' || echo "0"
}

PREV_CRIT=$(count_findings "$PREV" "Critical")
CURR_CRIT=$(count_findings "$LATEST" "Critical")
PREV_HIGH=$(count_findings "$PREV" "High")
CURR_HIGH=$(count_findings "$LATEST" "High")

DELTA_CRIT=$((CURR_CRIT - PREV_CRIT))
DELTA_HIGH=$((CURR_HIGH - PREV_HIGH))

# Output
cat <<EOF

Drift Summary
=============
Commit: $PREV_SHA → $CURR_SHA

Findings:
  Critical: $PREV_CRIT → $CURR_CRIT (Δ $DELTA_CRIT)
  High:     $PREV_HIGH → $CURR_HIGH (Δ $DELTA_HIGH)

EOF

if [[ "$FORMAT" == "detailed" ]]; then
  echo "Detailed diff:"
  diff -u "$PREV" "$LATEST" || true
fi

exit 0
