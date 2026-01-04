#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/sca_common.sh
source "$SCRIPT_DIR/../lib/sca_common.sh"

usage() {
  cat <<EOF
Usage: sca-diagnose.sh [OPTIONS]

Diagnose SCA installation and dependencies.

Options:
  --repo <path>              Repository root (default: current dir)
  --ctrl-dir <path>          Control directory (default: <repo>/sec-ctrl)
  --agent-dir <path>         SCA agent location
  --verbose                  Show detailed output
  -h, --help                 Show this help

Examples:
  sca-diagnose.sh
  sca-diagnose.sh --verbose
  sca-diagnose.sh --repo /path/to/repo
EOF
}

# Defaults
REPO="."
CTRL_DIR=""
AGENT_DIR=""
VERBOSE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo) REPO="$2"; shift 2;;
    --ctrl-dir) CTRL_DIR="$2"; shift 2;;
    --agent-dir) AGENT_DIR="$2"; shift 2;;
    --verbose) VERBOSE=1; shift;;
    -h|--help) usage; exit 0;;
    *) echo "[ERROR] Unknown arg: $1"; usage; exit 3;;
  esac
done

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

check_mark="${GREEN}✓${NC}"
cross_mark="${RED}✗${NC}"
warn_mark="${YELLOW}⚠${NC}"

echo ""
echo "SCA Diagnostics"
echo "==============="
echo ""

# Track overall status
ISSUES_FOUND=0
WARNINGS_FOUND=0

# Helper functions
check_command() {
  local cmd="$1"
  local required="${2:-yes}"
  local version_flag="${3:---version}"

  if command -v "$cmd" &>/dev/null; then
    local version
    version=$("$cmd" $version_flag 2>&1 | head -n1 || echo "unknown")
    echo -e "${check_mark} $cmd installed: $version"
    return 0
  else
    if [[ "$required" == "yes" ]]; then
      echo -e "${cross_mark} $cmd not found (REQUIRED)"
      ((ISSUES_FOUND++))
      return 1
    else
      echo -e "${warn_mark} $cmd not found (optional)"
      ((WARNINGS_FOUND++))
      return 0
    fi
  fi
}

check_version() {
  local name="$1"
  local current="$2"
  local required="$3"

  if [[ "$current" == "unknown" ]]; then
    echo -e "${warn_mark} $name version unknown"
    ((WARNINGS_FOUND++))
    return 0
  fi

  # Simple version comparison (works for X.Y format)
  if [[ "$(printf '%s\n' "$required" "$current" | sort -V | head -n1)" == "$required" ]]; then
    echo -e "${check_mark} $name $current (required: $required+)"
    return 0
  else
    echo -e "${cross_mark} $name $current (required: $required+)"
    ((ISSUES_FOUND++))
    return 1
  fi
}

# Core Dependencies
echo "Core Dependencies:"
echo "------------------"

# Python
if command -v python3 &>/dev/null; then
  PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
  check_version "Python" "$PYTHON_VERSION" "3.7"
else
  echo -e "${cross_mark} Python 3 not found (REQUIRED)"
  echo "  Install: https://www.python.org/downloads/"
  ((ISSUES_FOUND++))
fi

# Bash
if [[ -n "${BASH_VERSION:-}" ]]; then
  BASH_MAJOR=$(echo "$BASH_VERSION" | cut -d. -f1)
  if [[ "$BASH_MAJOR" -ge 4 ]]; then
    echo -e "${check_mark} Bash $BASH_VERSION (required: 4.0+)"
  else
    echo -e "${cross_mark} Bash $BASH_VERSION (required: 4.0+)"
    ((ISSUES_FOUND++))
  fi
else
  echo -e "${cross_mark} Bash version unknown"
  ((ISSUES_FOUND++))
fi

# jq
check_command "jq" "yes" "--version"

# git
check_command "git" "yes" "--version"

echo ""

# Claude Code CLI
echo "Claude Code Integration:"
echo "------------------------"

CLAUDE_BIN="${CLAUDE_CODE_BIN:-claude}"
if command -v "$CLAUDE_BIN" &>/dev/null; then
  CLAUDE_VERSION=$("$CLAUDE_BIN" --version 2>&1 | head -n1 || echo "unknown")
  echo -e "${check_mark} Claude Code CLI installed: $CLAUDE_VERSION"
  echo "  Binary: $(command -v "$CLAUDE_BIN")"
else
  echo -e "${cross_mark} Claude Code CLI not found (REQUIRED)"
  echo "  Command: $CLAUDE_BIN"
  echo "  Install: https://claude.com/claude-code"
  echo "  Or set: export CLAUDE_CODE_BIN=/path/to/claude"
  ((ISSUES_FOUND++))
fi

# Anthropic API Key (optional check - Claude Code will prompt if needed)
if [[ -n "${ANTHROPIC_API_KEY:-}" ]]; then
  KEY_LENGTH=${#ANTHROPIC_API_KEY}
  MASKED_KEY="${ANTHROPIC_API_KEY:0:8}...${ANTHROPIC_API_KEY: -4}"
  echo -e "${check_mark} ANTHROPIC_API_KEY set ($KEY_LENGTH chars)"
  echo "  Value: $MASKED_KEY"
else
  echo -e "${warn_mark} ANTHROPIC_API_KEY not set (optional)"
  echo "  Claude Code will prompt for API key when running sca audit"
  echo "  Or set: export ANTHROPIC_API_KEY=your-api-key"
  echo "  Get key: https://console.anthropic.com/settings/keys"
  ((WARNINGS_FOUND++))
fi

echo ""

# SCA Agent Directory
echo "SCA Installation:"
echo "-----------------"

# Resolve agent directory
AGENT_DIR="$(resolve_agent_dir "${REPO:-.}" "$AGENT_DIR" 2>/dev/null || echo "")"

if [[ -z "$AGENT_DIR" ]]; then
  # Try to detect from script location
  AGENT_DIR="$SCRIPT_DIR/.."
fi

if [[ -d "$AGENT_DIR" ]]; then
  echo -e "${check_mark} Agent directory: $AGENT_DIR"

  # Check if writable (should NOT be writable)
  if [[ -w "$AGENT_DIR" ]]; then
    echo -e "${warn_mark} Agent directory is WRITABLE (should be read-only)"
    echo "  Fix: sudo chmod -R a-w $AGENT_DIR"
    ((WARNINGS_FOUND++))
  else
    echo -e "${check_mark} Agent directory is read-only"
  fi

  # Check if git repo and dirty
  if [[ -d "$AGENT_DIR/.git" ]]; then
    pushd "$AGENT_DIR" >/dev/null
    if git diff-index --quiet HEAD -- 2>/dev/null; then
      echo -e "${check_mark} Agent git status: clean"
    else
      echo -e "${warn_mark} Agent git status: uncommitted changes"
      ((WARNINGS_FOUND++))
    fi
    popd >/dev/null
  fi

  # Check for required files
  REQUIRED_FILES=(
    "bin/sca"
    "bin/sec-audit.sh"
    "bin/repo-scope.sh"
    "lib/sca_common.sh"
    "invariants/global.md"
    "prompts/RUNBOOK.md"
  )

  MISSING_FILES=0
  for file in "${REQUIRED_FILES[@]}"; do
    if [[ ! -f "$AGENT_DIR/$file" ]]; then
      echo -e "${cross_mark} Missing: $file"
      ((MISSING_FILES++))
    fi
  done

  if [[ $MISSING_FILES -eq 0 ]]; then
    echo -e "${check_mark} All required files present"
  else
    echo -e "${cross_mark} Missing $MISSING_FILES required files"
    ((ISSUES_FOUND++))
  fi

  # Check VERSION file
  if [[ -f "$AGENT_DIR/VERSION" ]]; then
    VERSION=$(cat "$AGENT_DIR/VERSION")
    echo -e "${check_mark} SCA version: $VERSION"
  else
    echo -e "${warn_mark} VERSION file not found"
    ((WARNINGS_FOUND++))
  fi

else
  echo -e "${cross_mark} Agent directory not found: $AGENT_DIR"
  echo "  Set: export SEC_AUDIT_AGENT_HOME=/opt/sca"
  echo "  Or provide: --agent-dir /path/to/sca"
  ((ISSUES_FOUND++))
fi

echo ""

# Repository and Control Directory (if specified)
if [[ "$REPO" != "." ]]; then
  echo "Repository Configuration:"
  echo "-------------------------"

  REPO_ROOT="$(resolve_repo_root "$REPO" 2>/dev/null || echo "")"

  if [[ -n "$REPO_ROOT" && -d "$REPO_ROOT" ]]; then
    echo -e "${check_mark} Repository root: $REPO_ROOT"

    # Check if git repo
    if [[ -d "$REPO_ROOT/.git" ]]; then
      echo -e "${check_mark} Git repository"
      pushd "$REPO_ROOT" >/dev/null
      CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
      CURRENT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
      echo "  Branch: $CURRENT_BRANCH"
      echo "  Commit: $CURRENT_COMMIT"
      popd >/dev/null
    else
      echo -e "${warn_mark} Not a git repository"
      ((WARNINGS_FOUND++))
    fi

  else
    echo -e "${cross_mark} Repository not found: $REPO"
    ((ISSUES_FOUND++))
  fi

  # Control directory
  CTRL_DIR="$(resolve_ctrl_dir "$REPO_ROOT" "$CTRL_DIR" 2>/dev/null || echo "$REPO_ROOT/sec-ctrl")"

  if [[ -d "$CTRL_DIR" ]]; then
    echo -e "${check_mark} Control directory: $CTRL_DIR"

    # Check if writable
    if [[ -w "$CTRL_DIR" ]]; then
      echo -e "${check_mark} Control directory is writable"
    else
      echo -e "${cross_mark} Control directory is NOT writable"
      ((ISSUES_FOUND++))
    fi

    # Check for OVERRIDE.md
    if [[ -f "$CTRL_DIR/OVERRIDE.md" ]]; then
      OVERRIDE_LINES=$(wc -l < "$CTRL_DIR/OVERRIDE.md")
      echo "  OVERRIDE.md: $OVERRIDE_LINES lines"
    fi

    # Check for reports
    if [[ -d "$CTRL_DIR/reports" ]]; then
      REPORT_COUNT=$(find "$CTRL_DIR/reports" -name "security-audit.*.md" -type f 2>/dev/null | wc -l)
      echo "  Reports: $REPORT_COUNT audit(s) found"
    fi

  else
    echo -e "${warn_mark} Control directory not found: $CTRL_DIR"
    echo "  Run: sca bootstrap --repo $REPO_ROOT"
    ((WARNINGS_FOUND++))
  fi

  echo ""
fi

# Optional Integrations
echo "Optional Integrations:"
echo "----------------------"

# GitHub CLI
if command -v gh &>/dev/null; then
  GH_VERSION=$(gh --version 2>&1 | head -n1)
  echo -e "${check_mark} GitHub CLI installed: $GH_VERSION"

  # Check auth status
  if gh auth status &>/dev/null; then
    GH_USER=$(gh api user -q .login 2>/dev/null || echo "unknown")
    echo -e "${check_mark} Authenticated as: $GH_USER"
  else
    echo -e "${warn_mark} Not authenticated (run: gh auth login)"
    ((WARNINGS_FOUND++))
  fi
else
  echo -e "${warn_mark} GitHub CLI not found (optional)"
  echo "  For ticket creation: https://cli.github.com/"
fi

# Jira
if [[ -n "${JIRA_URL:-}" && -n "${JIRA_API_TOKEN:-}" ]]; then
  echo -e "${check_mark} Jira credentials configured"
  echo "  URL: $JIRA_URL"
  MASKED_TOKEN="${JIRA_API_TOKEN:0:4}...${JIRA_API_TOKEN: -4}"
  echo "  Token: $MASKED_TOKEN"
elif [[ -n "${JIRA_URL:-}" || -n "${JIRA_API_TOKEN:-}" ]]; then
  echo -e "${warn_mark} Jira partially configured"
  [[ -z "${JIRA_URL:-}" ]] && echo "  Missing: JIRA_URL"
  [[ -z "${JIRA_API_TOKEN:-}" ]] && echo "  Missing: JIRA_API_TOKEN"
  ((WARNINGS_FOUND++))
else
  echo -e "${warn_mark} Jira not configured (optional)"
fi

echo ""

# Dependency Scanners
echo "Dependency Scanners (Optional):"
echo "--------------------------------"
check_command "npm" "no" "--version"
check_command "pip-audit" "no" "--version"
check_command "cargo" "no" "--version"
check_command "govulncheck" "no" "-version"

echo ""

# Summary
echo "Summary:"
echo "--------"

if [[ $ISSUES_FOUND -eq 0 && $WARNINGS_FOUND -eq 0 ]]; then
  echo -e "${GREEN}✓ All checks passed! SCA is ready to use.${NC}"
  exit 0
elif [[ $ISSUES_FOUND -eq 0 ]]; then
  echo -e "${YELLOW}⚠ $WARNINGS_FOUND warning(s) found, but SCA should work.${NC}"
  exit 0
else
  echo -e "${RED}✗ $ISSUES_FOUND critical issue(s) found.${NC}"
  if [[ $WARNINGS_FOUND -gt 0 ]]; then
    echo -e "${YELLOW}⚠ $WARNINGS_FOUND warning(s) also found.${NC}"
  fi
  echo ""
  echo "Fix the critical issues above before running SCA."
  exit 1
fi
