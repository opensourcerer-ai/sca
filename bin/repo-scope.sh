#!/usr/bin/env bash
set -euo pipefail

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
    *) echo "Unknown arg: $1"; usage; exit 2;;
  esac
done

# Resolve repo root
if git -C "$REPO" rev-parse --show-toplevel >/dev/null 2>&1; then
  REPO_ROOT="$(git -C "$REPO" rev-parse --show-toplevel)"
else
  REPO_ROOT="$(cd "$REPO" && pwd)"
fi

# Resolve ctrl dir
if [[ -z "$CTRL_DIR" ]]; then
  if [[ -n "${SEC_CTRL_DIR:-}" ]]; then
    CTRL_DIR="${SEC_CTRL_DIR}"
  else
    CTRL_DIR="$REPO_ROOT/sec-ctrl"
  fi
fi

# Resolve agent dir (best-effort)
if [[ -z "$AGENT_DIR" ]]; then
  if [[ -n "${SEC_AUDIT_AGENT_HOME:-}" ]]; then
    AGENT_DIR="${SEC_AUDIT_AGENT_HOME}"
  elif [[ -d "/opt/sca" ]]; then
    AGENT_DIR="/opt/sca"
  elif [[ -d "$REPO_ROOT/tools/sec-audit-agent" ]]; then
    AGENT_DIR="$REPO_ROOT/tools/sec-audit-agent"
  else
    AGENT_DIR=""
  fi
fi

IGNORE_FILE="$REPO_ROOT/$CTRL_DIR/config/ignore.paths"
# If ignore file doesn't exist yet, fall back to built-in defaults
DEFAULT_EXCLUDES=("$CTRL_DIR/" "sec-ctrl/" "tools/sec-audit-agent/" ".git/" "node_modules/" "dist/" "build/" "target/" "vendor/" ".venv/" "__pycache__/")

cd "$REPO_ROOT"

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  FILES="$(git ls-files)"
else
  FILES="$(find . -type f | sed 's|^\./||')"
fi

EXCLUDES=()
if [[ -f "$IGNORE_FILE" ]]; then
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    [[ "$line" =~ ^# ]] && continue
    EXCLUDES+=("$line")
  done < "$IGNORE_FILE"
else
  EXCLUDES+=("${DEFAULT_EXCLUDES[@]}")
fi

for ex in "${EXCLUDES[@]}"; do
  FILES="$(printf "%s\n" "$FILES" | grep -vE "^${ex//\*/.*}")" || true
done

printf "%s\n" "$FILES"
