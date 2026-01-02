#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/sca_common.sh
source "$SCRIPT_DIR/../lib/sca_common.sh"

usage() {
  echo "Usage: repo-scope.sh [--repo <path>] [--ctrl-dir <path>] [--agent-dir <path>]"
}

REPO="."
CTRL_DIR=""
AGENT_DIR=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo) REPO="$2"; shift 2;;
    --ctrl-dir) CTRL_DIR="$2"; shift 2;;
    --agent-dir) AGENT_DIR="$2"; shift 2;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown arg: $1"; usage; exit 3;;
  esac
done

# Resolve paths using shared library
REPO_ROOT="$(resolve_repo_root "$REPO")"
CTRL_DIR="$(resolve_ctrl_dir "$REPO_ROOT" "$CTRL_DIR")"
AGENT_DIR="$(resolve_agent_dir "$REPO_ROOT" "$AGENT_DIR")"

log_debug "Repo root: $REPO_ROOT"
log_debug "Ctrl dir: $CTRL_DIR"
log_debug "Agent dir: $AGENT_DIR"

# Build ignore file path (FIXED: handle absolute CTRL_DIR correctly)
IGNORE_FILE="$CTRL_DIR/config/ignore.paths"

# Default excludes (always exclude ctrl-dir and agent-dir by path)
# Convert to relative paths for matching
CTRL_DIR_REL="${CTRL_DIR#$REPO_ROOT/}"
AGENT_DIR_REL="${AGENT_DIR#$REPO_ROOT/}"

DEFAULT_EXCLUDES=(
  "$CTRL_DIR_REL"
  "sec-ctrl/"
  "tools/sec-audit-agent/"
  ".git/"
  "node_modules/"
  "dist/"
  "build/"
  "target/"
  "vendor/"
  ".venv/"
  "__pycache__/"
)

# If agent-dir is outside repo, don't add to relative excludes
if ! is_subpath "$AGENT_DIR" "$REPO_ROOT"; then
  log_debug "Agent dir is external to repo, not adding to scope exclusions"
fi

cd "$REPO_ROOT"

# Get file list
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  FILES="$(git ls-files)"
else
  FILES="$(find . -type f | sed 's|^\./||')"
fi

# Build exclusion list (always start with defaults)
EXCLUDES=("${DEFAULT_EXCLUDES[@]}")

# Add custom patterns from ignore file
if [[ -f "$IGNORE_FILE" ]]; then
  log_debug "Loading additional ignore patterns from $IGNORE_FILE"
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    [[ "$line" =~ ^# ]] && continue
    EXCLUDES+=("$line")
  done < "$IGNORE_FILE"
else
  log_debug "No ignore file found, using defaults only"
fi

# Filter files
FILTERED="$FILES"
for ex in "${EXCLUDES[@]}"; do
  # Escape special chars for grep, handle glob patterns
  pattern="${ex//\*/.*}"
  pattern="^${pattern}"
  FILTERED="$(echo "$FILTERED" | grep -vE "$pattern" || true)"
done

printf "%s\n" "$FILTERED"
