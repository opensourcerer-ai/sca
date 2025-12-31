    #!/usr/bin/env bash
    set -euo pipefail

    usage() {
      echo "Usage: sec-audit.sh [--repo <path>] [--ctrl-dir <path>] [--agent-dir <path>] [--readonly-agent|--no-readonly-agent]"
    }

    REPO="."
    CTRL_DIR=""
    AGENT_DIR=""
    READONLY_AGENT=1

    while [[ $# -gt 0 ]]; do
      case "$1" in
        --repo) REPO="$2"; shift 2;;
        --ctrl-dir) CTRL_DIR="$2"; shift 2;;
        --agent-dir) AGENT_DIR="$2"; shift 2;;
        --readonly-agent) READONLY_AGENT=1; shift;;
        --no-readonly-agent) READONLY_AGENT=0; shift;;
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
    else
      # allow relative path
      if [[ "$CTRL_DIR" != /* ]]; then
        CTRL_DIR="$REPO_ROOT/$CTRL_DIR"
      fi
    fi

    # Resolve agent dir
    if [[ -z "$AGENT_DIR" ]]; then
      if [[ -n "${SEC_AUDIT_AGENT_HOME:-}" ]]; then
        AGENT_DIR="${SEC_AUDIT_AGENT_HOME}"
      elif [[ -d "/opt/sca" ]]; then
        AGENT_DIR="/opt/sca"
      elif [[ -d "$REPO_ROOT/tools/sec-audit-agent" ]]; then
        AGENT_DIR="$REPO_ROOT/tools/sec-audit-agent"
      else
        echo "ERROR: Could not resolve agent dir. Provide --agent-dir or set SEC_AUDIT_AGENT_HOME."
        exit 3
      fi
    fi

    # Enforce read-only agent (writable or dirty => fail)
    if [[ "$READONLY_AGENT" -eq 1 ]]; then
      if [[ -w "$AGENT_DIR" ]]; then
        echo "ERROR: Agent dir is writable: $AGENT_DIR"
        echo "Fix: install agent read-only (e.g. root-owned /opt/sca) or chmod -R a-w."
        exit 4
      fi
      if [[ -d "$AGENT_DIR/.git" ]]; then
        if git -C "$AGENT_DIR" status --porcelain | grep -q .; then
          echo "ERROR: Agent checkout is dirty: $AGENT_DIR"
          echo "Fix: reset/clean agent checkout. Agent must be immutable during audits."
          exit 4
        fi
      fi
    fi

    mkdir -p "$CTRL_DIR"/{state,reports,cache,config,invariants/languages}

    # Ensure default ignore file exists (users can customize)
    if [[ ! -f "$CTRL_DIR/config/ignore.paths" ]]; then
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

    TS="$(date -u +"%Y%m%dT%H%M%SZ")"
    OUT_MD="$CTRL_DIR/reports/security-audit.$TS.md"
    OUT_LATEST="$CTRL_DIR/reports/security-audit.latest.md"

    SCOPE_LIST="$(mktemp)"
    "$AGENT_DIR/bin/repo-scope.sh" --repo "$REPO_ROOT" --ctrl-dir "$CTRL_DIR" --agent-dir "$AGENT_DIR" > "$SCOPE_LIST"

    # Language detection
    LANGS=()
    if grep -qE '\.c$|\.h$|\.cc$|\.cpp$|\.hpp$' "$SCOPE_LIST"; then LANGS+=("c-cpp"); fi
    if grep -qE '\.go$' "$SCOPE_LIST"; then LANGS+=("go"); fi
    if grep -qE '\.java$|\.kt$' "$SCOPE_LIST"; then LANGS+=("java"); fi
    if grep -qE '\.js$|\.ts$|\.tsx$|\.jsx$' "$SCOPE_LIST"; then LANGS+=("javascript-typescript"); fi
    if grep -qE '\.py$' "$SCOPE_LIST"; then LANGS+=("python"); fi
    if grep -qE '\.rs$' "$SCOPE_LIST"; then LANGS+=("rust"); fi

    INV_BUNDLE="$(mktemp)"
    cat "$AGENT_DIR/invariants/global.md" > "$INV_BUNDLE"
    for L in "${LANGS[@]}"; do
      echo -e "\n\n# Language invariants: $L\n" >> "$INV_BUNDLE"
      cat "$AGENT_DIR/invariants/languages/$L.md" >> "$INV_BUNDLE"
    done

    CLAUDE_BIN="${CLAUDE_CODE_BIN:-claude}"

    # Invoke Claude Code (adjust command if your CLI differs)
    "$CLAUDE_BIN" code <<EOF > "$OUT_MD"
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
Exclude: sec-ctrl/ and tools/sec-audit-agent/
Languages detected: ${LANGS[*]:-none}

## File list (analyze these; do not analyze excluded paths)
$(cat "$SCOPE_LIST")

## Instructions
- Cite file paths for every finding.
- Separate confirmed vs suspicious/needs-review.
- Include OWASP-style issues, dependency/CVE risk spots, secrets, crypto misuse, authn/authz, injection, deserialization, path traversal, SSRF, XSS, CSRF, logging/PII.
- If you cannot confirm, say what evidence is missing.
- End with a prioritized fix plan (top 10).
EOF

    cp -f "$OUT_MD" "$OUT_LATEST"

    # Write minimal state
    printf "%s\n" "$TS" > "$CTRL_DIR/state/last-run.txt"
    sha="$( (cd "$REPO_ROOT" && git rev-parse HEAD 2>/dev/null) || echo "nogit")"
    printf "%s\n" "$sha" > "$CTRL_DIR/state/repo-fingerprint.txt"
    cp -f "$SCOPE_LIST" "$CTRL_DIR/state/last-scope.txt"

    rm -f "$SCOPE_LIST" "$INV_BUNDLE"

    echo "Wrote: $OUT_MD"
    echo "Latest: $OUT_LATEST"
