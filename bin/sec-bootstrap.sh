#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/sca_common.sh
source "$SCRIPT_DIR/../lib/sca_common.sh"

usage() {
  cat <<EOF
Usage: sec-bootstrap.sh [OPTIONS]

Options:
  --repo <path>        Repository root
  --ctrl-dir <path>    Control directory to create
  --force              Overwrite existing ctrl-dir (危险)
  -h, --help           Show this help
EOF
}

REPO="."
CTRL_DIR=""
FORCE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo) REPO="$2"; shift 2;;
    --ctrl-dir) CTRL_DIR="$2"; shift 2;;
    --force) FORCE=1; shift;;
    -h|--help) usage; exit 0;;
    *) log_error "Unknown arg: $1"; usage; exit 3;;
  esac
done

REPO_ROOT="$(resolve_repo_root "$REPO")"
CTRL_DIR="$(resolve_ctrl_dir "$REPO_ROOT" "$CTRL_DIR")"
AGENT_DIR="$(resolve_agent_dir "$REPO_ROOT" "")"

if [[ -z "$AGENT_DIR" ]]; then
  log_error "Could not resolve agent dir. Set SEC_AUDIT_AGENT_HOME or install to /opt/sca."
  exit 3
fi

log_info "Creating control directory: $CTRL_DIR"

# Check if exists
if [[ -d "$CTRL_DIR" ]] && [[ -n "$(ls -A "$CTRL_DIR" 2>/dev/null)" ]]; then
  if [[ "$FORCE" -eq 0 ]]; then
    log_error "Control directory exists and is not empty: $CTRL_DIR"
    log_error "Use --force to overwrite (will backup existing)."
    exit 3
  else
    BACKUP="$CTRL_DIR.backup.$(date -u +%Y%m%dT%H%M%SZ)"
    log_warn "Backing up existing ctrl-dir to: $BACKUP"
    mv "$CTRL_DIR" "$BACKUP"
  fi
fi

# Create structure
mkdir -p "$CTRL_DIR"/{state,reports,cache,config,invariants}

# Copy templates
TEMPLATE_DIR="$AGENT_DIR/templates/sec-ctrl"
if [[ -d "$TEMPLATE_DIR" ]]; then
  cp -r "$TEMPLATE_DIR"/* "$CTRL_DIR"/
else
  log_warn "No templates found in $TEMPLATE_DIR, creating minimal structure"
fi

# Create default ignore.paths if not exists
if [[ ! -f "$CTRL_DIR/config/ignore.paths" ]]; then
  cat > "$CTRL_DIR/config/ignore.paths" <<'EOF'
# Default ignore patterns for SCA scope
# Edit as needed for your repository

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
*.min.js
*.bundle.js
EOF
fi

# Create README
cat > "$CTRL_DIR/README.md" <<'EOF'
# Security Control Directory

This directory contains SCA (Security Control Agent) artifacts for this repository.

## Structure
- `config/`: Ignore patterns and configuration
- `invariants/`: Local overrides (with justification)
- `state/`: Run metadata and drift tracking
- `reports/`: Audit reports (markdown + JSON)
- `cache/`: Optional caching for performance
- `OVERRIDE.md`: Accepted risks and suppressed findings
- `SUGGESTIONS.md`: Auto-generated remediation guidance (regenerated each audit)

## Usage
Run `sca audit` from repository root to generate reports.

## Override Process
To suppress a finding, add it to `OVERRIDE.md` with:
- File path or unique identifier
- Business/security justification
- Approver and date
- Review date

## Important
DO NOT commit secrets or sensitive data to this directory.
Reports may contain code snippets; review before sharing.
EOF

# Create OVERRIDE.md if template exists
if [[ -f "$TEMPLATE_DIR/OVERRIDE.md" ]]; then
  cp "$TEMPLATE_DIR/OVERRIDE.md" "$CTRL_DIR/OVERRIDE.md"
else
  log_warn "OVERRIDE.md template not found, creating minimal version"
  cat > "$CTRL_DIR/OVERRIDE.md" <<'EOF'
# Security Audit Override Rules

Add accepted findings here to suppress them in future reports.

Format:
```
# Override: Brief description
# File: path/to/file.ext
# Reason: Why this is acceptable
# Approved: Name, Date
# Review: Next review date
path/to/file.ext
```

## Active Overrides

<!-- Add your overrides below -->

EOF
fi

log_info "Bootstrap complete: $CTRL_DIR"
log_info "Created: OVERRIDE.md for managing accepted risks"
log_info "Next: Run 'sca audit' to perform first audit."

exit 0
