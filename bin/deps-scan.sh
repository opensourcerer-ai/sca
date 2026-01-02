#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/sca_common.sh
source "$SCRIPT_DIR/../lib/sca_common.sh"

usage() {
  echo "Usage: deps-scan.sh --repo <path> --ctrl-dir <path>"
}

REPO_ROOT=""
CTRL_DIR=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo) REPO_ROOT="$2"; shift 2;;
    --ctrl-dir) CTRL_DIR="$2"; shift 2;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown arg: $1"; usage; exit 3;;
  esac
done

[[ -z "$REPO_ROOT" ]] && { echo "[ERROR] --repo required" >&2; exit 3; }
[[ -z "$CTRL_DIR" ]] && { echo "[ERROR] --ctrl-dir required" >&2; exit 3; }

TS="$(date -u +"%Y%m%dT%H%M%SZ")"
DEPS_DIR="$CTRL_DIR/reports/deps"
mkdir -p "$DEPS_DIR"

cd "$REPO_ROOT"

# JavaScript/TypeScript (npm)
if [[ -f "package.json" ]] || [[ -f "package-lock.json" ]]; then
  log_info "Running npm audit..."
  if command -v npm >/dev/null 2>&1; then
    npm audit --json > "$DEPS_DIR/npm-audit.$TS.json" 2>/dev/null || log_warn "npm audit failed (non-zero exit)"
  else
    log_warn "npm not found, skipping npm audit"
  fi
fi

# Python (pip-audit)
if [[ -f "requirements.txt" ]] || [[ -f "Pipfile" ]] || [[ -f "pyproject.toml" ]]; then
  log_info "Running pip-audit..."
  if command -v pip-audit >/dev/null 2>&1; then
    pip-audit --format json --output "$DEPS_DIR/pip-audit.$TS.json" 2>/dev/null || log_warn "pip-audit failed"
  else
    log_warn "pip-audit not found, skipping"
  fi
fi

# Rust (cargo audit)
if [[ -f "Cargo.toml" ]]; then
  log_info "Running cargo audit..."
  if command -v cargo-audit >/dev/null 2>&1; then
    cargo audit --json > "$DEPS_DIR/cargo-audit.$TS.json" 2>/dev/null || log_warn "cargo audit failed"
  else
    log_warn "cargo-audit not found, skipping"
  fi
fi

# Go (nancy, govulncheck)
if [[ -f "go.mod" ]]; then
  log_info "Running govulncheck..."
  if command -v govulncheck >/dev/null 2>&1; then
    govulncheck -json ./... > "$DEPS_DIR/govulncheck.$TS.json" 2>/dev/null || log_warn "govulncheck failed"
  else
    log_warn "govulncheck not found, skipping"
  fi
fi

log_info "Dependency scan complete. Outputs in $DEPS_DIR"
exit 0
