#!/bin/bash
# Interactive finding suppression tool
# Allows users to review findings and add justified overrides

set -e

# Source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/sca_common.sh"

# Default paths
CTRL_DIR=""
REPORT_FILE=""
OVERRIDE_FILE=""
JUSTIFICATIONS_FILE="$SCRIPT_DIR/../config/justifications.conf"
BATCH_FILE=""

# Options
INTERACTIVE_MODE=1
AUTO_COMMIT=0

show_usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Interactive tool to suppress security findings with justified reasons.

Options:
  --ctrl-dir PATH         Control directory (default: auto-detect)
  --report PATH           Path to audit report JSON file
  --batch FILE            Batch suppress from file (format: ID|Category|Reason)
  --auto-commit           Auto-commit changes to OVERRIDE.md
  --non-interactive       Batch mode only, no interactive prompts
  -h, --help              Show this help

Examples:
  # Interactive suppression from latest audit
  $(basename "$0") --ctrl-dir ./sec-ctrl

  # Batch suppression from file
  $(basename "$0") --batch suppressions.txt --ctrl-dir ./sec-ctrl

EOF
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ctrl-dir)
            CTRL_DIR="$2"
            shift 2
            ;;
        --report)
            REPORT_FILE="$2"
            shift 2
            ;;
        --batch)
            BATCH_FILE="$2"
            INTERACTIVE_MODE=0
            shift 2
            ;;
        --auto-commit)
            AUTO_COMMIT=1
            shift
            ;;
        --non-interactive)
            INTERACTIVE_MODE=0
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Auto-detect control directory if not specified
if [[ -z "$CTRL_DIR" ]]; then
    if [[ -d "sec-ctrl" ]]; then
        CTRL_DIR="sec-ctrl"
    elif [[ -d "../sec-ctrl" ]]; then
        CTRL_DIR="../sec-ctrl"
    else
        log_error "Control directory not found. Use --ctrl-dir"
        exit 1
    fi
fi

CTRL_DIR="$(cd "$CTRL_DIR" && pwd)"
OVERRIDE_FILE="$CTRL_DIR/OVERRIDE.md"

# Find latest report if not specified
if [[ -z "$REPORT_FILE" ]]; then
    REPORT_FILE="$CTRL_DIR/reports/security-audit.latest.json"
fi

if [[ ! -f "$REPORT_FILE" ]]; then
    log_error "Report file not found: $REPORT_FILE"
    exit 1
fi

log_info "Suppression tool starting"
log_info "Control dir: $CTRL_DIR"
log_info "Report: $REPORT_FILE"

# Load justifications
declare -A JUSTIFICATIONS
declare -A JUSTIFICATION_NAMES
declare -A REVIEW_MONTHS

if [[ -f "$JUSTIFICATIONS_FILE" ]]; then
    while IFS='|' read -r id name desc months; do
        # Skip comments and empty lines
        [[ "$id" =~ ^#.*$ ]] && continue
        [[ -z "$id" ]] && continue

        JUSTIFICATIONS[$id]="$desc"
        JUSTIFICATION_NAMES[$id]="$name"
        REVIEW_MONTHS[$id]="$months"
    done < "$JUSTIFICATIONS_FILE"
else
    log_warn "Justifications file not found: $JUSTIFICATIONS_FILE"
    # Hardcode defaults
    JUSTIFICATIONS[1]="False Positive"
    JUSTIFICATION_NAMES[1]="False Positive"
    REVIEW_MONTHS[1]=12
fi

# Display justification menu
show_justification_menu() {
    echo ""
    echo "Select justification category:"
    for id in $(seq 1 10); do
        if [[ -n "${JUSTIFICATION_NAMES[$id]}" ]]; then
            printf "%2d. %s\n" "$id" "${JUSTIFICATION_NAMES[$id]}"
        fi
    done
    echo ""
}

# Add suppression to OVERRIDE.md
add_suppression() {
    local finding_id="$1"
    local finding_title="$2"
    local file_path="$3"
    local lines="$4"
    local category_id="$5"
    local custom_reason="$6"
    local approved_by="$7"

    local category_name="${JUSTIFICATION_NAMES[$category_id]}"
    local review_months="${REVIEW_MONTHS[$category_id]}"
    local date_now="$(date +%Y-%m-%d)"
    local review_date="$(date -d "+${review_months} months" +%Y-%m-%d 2>/dev/null || date -v+${review_months}m +%Y-%m-%d 2>/dev/null || echo "N/A")"

    # Build override entry
    cat >> "$OVERRIDE_FILE" <<EOF

# Override: $finding_title ($category_name)
# Category: $category_name
# Finding: $finding_id - $finding_title
# Reason: $custom_reason
# Approved-By: $approved_by
# Date: $date_now
# Review-Date: $review_date
EOF

    if [[ -n "$lines" ]]; then
        echo "${file_path}:${lines}" >> "$OVERRIDE_FILE"
    else
        echo "$file_path" >> "$OVERRIDE_FILE"
    fi

    log_info "Added suppression for $finding_id to OVERRIDE.md"
}

# Extract findings from JSON report
extract_findings() {
    if ! command -v jq &> /dev/null; then
        log_error "jq is required for parsing JSON reports"
        exit 1
    fi

    # Extract critical findings
    jq -r '.findings.critical[]? | "\(.id)|\(.title)|\(.file // "unknown")|\(.lines // "")|CRITICAL"' "$REPORT_FILE"
    jq -r '.findings.high[]? | "\(.id)|\(.title)|\(.file // .files[0] // "unknown")|\(.lines // "")|HIGH"' "$REPORT_FILE"
    jq -r '.findings.medium[]? | "\(.id)|\(.title)|\(.file // "unknown")|\(.lines // "")|MEDIUM"' "$REPORT_FILE"
}

# Interactive mode
interactive_suppression() {
    local findings_count=0
    local suppressed_count=0

    echo ""
    echo "========================================"
    echo "  Interactive Finding Suppression"
    echo "========================================"
    echo ""

    while IFS='|' read -r id title file lines severity; do
        findings_count=$((findings_count + 1))

        echo ""
        echo "─────────────────────────────────────────"
        echo "Finding #$findings_count"
        echo "─────────────────────────────────────────"
        echo "ID:       $id"
        echo "Title:    $title"
        echo "File:     $file"
        [[ -n "$lines" ]] && echo "Lines:    $lines"
        echo "Severity: $severity"
        echo ""

        while true; do
            read -p "Action: [s]uppress [k]eep [v]iew details [q]uit: " action

            case "$action" in
                s|S)
                    # Suppress
                    show_justification_menu
                    read -p "Select category [1-10]: " cat_id

                    if [[ ! "$cat_id" =~ ^[1-9]$|^10$ ]] || [[ -z "${JUSTIFICATION_NAMES[$cat_id]}" ]]; then
                        echo "Invalid category"
                        continue
                    fi

                    read -p "Additional reason/notes: " custom_reason
                    [[ -z "$custom_reason" ]] && custom_reason="${JUSTIFICATION_NAMES[$cat_id]}"

                    read -p "Approved by (name/team): " approved_by
                    [[ -z "$approved_by" ]] && approved_by="$(whoami)"

                    add_suppression "$id" "$title" "$file" "$lines" "$cat_id" "$custom_reason" "$approved_by"
                    suppressed_count=$((suppressed_count + 1))
                    echo "✓ Suppressed"
                    break
                    ;;
                k|K)
                    # Keep
                    echo "Keeping finding in report"
                    break
                    ;;
                v|V)
                    # View details
                    echo ""
                    echo "Finding details:"
                    jq ".findings.critical[]?, .findings.high[]?, .findings.medium[]? | select(.id == \"$id\")" "$REPORT_FILE" 2>/dev/null || echo "Details not available"
                    echo ""
                    ;;
                q|Q)
                    # Quit
                    echo "Exiting interactive mode"
                    echo ""
                    echo "Summary:"
                    echo "  Total findings reviewed: $findings_count"
                    echo "  Suppressed: $suppressed_count"
                    exit 0
                    ;;
                *)
                    echo "Invalid action. Use s/k/v/q"
                    ;;
            esac
        done
    done < <(extract_findings)

    echo ""
    echo "========================================"
    echo "Summary:"
    echo "  Total findings reviewed: $findings_count"
    echo "  Suppressed: $suppressed_count"
    echo "========================================"
    echo ""

    if [[ $AUTO_COMMIT -eq 1 ]] && [[ $suppressed_count -gt 0 ]]; then
        if [[ -d "$CTRL_DIR/.git" ]]; then
            log_info "Auto-committing changes"
            (cd "$CTRL_DIR" && git add OVERRIDE.md && git commit -m "chore: Suppress $suppressed_count findings via sca-suppress")
        fi
    fi
}

# Batch mode
batch_suppression() {
    if [[ ! -f "$BATCH_FILE" ]]; then
        log_error "Batch file not found: $BATCH_FILE"
        exit 1
    fi

    local count=0
    while IFS='|' read -r id category_id reason; do
        # Skip comments
        [[ "$id" =~ ^#.*$ ]] && continue
        [[ -z "$id" ]] && continue

        # Find finding in report
        local finding_json=$(jq ".findings.critical[]?, .findings.high[]?, .findings.medium[]? | select(.id == \"$id\")" "$REPORT_FILE")

        if [[ -z "$finding_json" ]]; then
            log_warn "Finding $id not found in report, skipping"
            continue
        fi

        local title=$(echo "$finding_json" | jq -r '.title')
        local file=$(echo "$finding_json" | jq -r '.file // .files[0] // "unknown"')
        local lines=$(echo "$finding_json" | jq -r '.lines // ""')

        add_suppression "$id" "$title" "$file" "$lines" "$category_id" "$reason" "batch-import"
        count=$((count + 1))
    done < "$BATCH_FILE"

    log_info "Batch suppression complete: $count findings suppressed"
}

# Main execution
if [[ $INTERACTIVE_MODE -eq 1 ]]; then
    interactive_suppression
elif [[ -n "$BATCH_FILE" ]]; then
    batch_suppression
else
    log_error "No mode specified. Use --batch or run interactively"
    exit 1
fi

log_info "Suppression tool complete"
