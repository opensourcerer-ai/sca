#!/usr/bin/env bash
# Shared functions for SCA scripts

# Portable realpath (handles Linux + macOS)
realpath_portable() {
  local path="$1"
  if command -v realpath >/dev/null 2>&1; then
    realpath "$path"
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c "import os,sys; print(os.path.realpath(sys.argv[1]))" "$path"
  elif command -v python >/dev/null 2>&1; then
    python -c "import os,sys; print(os.path.realpath(sys.argv[1]))" "$path"
  else
    # Fallback: resolve relative to pwd
    echo "$(cd "$(dirname "$path")" && pwd -P)/$(basename "$path")"
  fi
}

# Resolve repository root
resolve_repo_root() {
  local repo_arg="$1"
  if git -C "$repo_arg" rev-parse --show-toplevel >/dev/null 2>&1; then
    git -C "$repo_arg" rev-parse --show-toplevel
  else
    realpath_portable "$repo_arg"
  fi
}

# Resolve control directory (absolute canonical path)
resolve_ctrl_dir() {
  local repo_root="$1"
  local ctrl_arg="$2"

  if [[ -n "$ctrl_arg" ]]; then
    if [[ "$ctrl_arg" = /* ]]; then
      realpath_portable "$ctrl_arg"
    else
      realpath_portable "$repo_root/$ctrl_arg"
    fi
  elif [[ -n "${SEC_CTRL_DIR:-}" ]]; then
    if [[ "${SEC_CTRL_DIR}" = /* ]]; then
      realpath_portable "${SEC_CTRL_DIR}"
    else
      realpath_portable "$repo_root/${SEC_CTRL_DIR}"
    fi
  else
    realpath_portable "$repo_root/sec-ctrl"
  fi
}

# Resolve agent directory
resolve_agent_dir() {
  local repo_root="$1"
  local agent_arg="$2"

  if [[ -n "$agent_arg" ]]; then
    realpath_portable "$agent_arg"
  elif [[ -n "${SEC_AUDIT_AGENT_HOME:-}" ]]; then
    realpath_portable "${SEC_AUDIT_AGENT_HOME}"
  elif [[ -d "/opt/sca" ]]; then
    echo "/opt/sca"
  elif [[ -d "$repo_root/tools/sec-audit-agent" ]]; then
    realpath_portable "$repo_root/tools/sec-audit-agent"
  else
    echo ""
  fi
}

# Check if path is subpath of another
is_subpath() {
  local child="$1"
  local parent="$2"

  # Normalize both paths
  child="$(realpath_portable "$child" 2>/dev/null || echo "$child")"
  parent="$(realpath_portable "$parent" 2>/dev/null || echo "$parent")"

  case "$child" in
    "$parent"/*|"$parent") return 0 ;;
    *) return 1 ;;
  esac
}

# Log to stderr with level
log_info() {
  local level="${SCA_LOG_LEVEL:-1}"
  [[ "$level" -ge 1 ]] && echo "[INFO] $*" >&2
  return 0
}

log_warn() {
  echo "[WARN] $*" >&2
  return 0
}

log_error() {
  echo "[ERROR] $*" >&2
  return 0
}

log_debug() {
  local level="${SCA_LOG_LEVEL:-1}"
  [[ "$level" -ge 2 ]] && echo "[DEBUG] $*" >&2
  return 0
}
