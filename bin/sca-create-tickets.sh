#!/bin/bash
# Create GitHub issues or Jira tickets from security audit findings
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/sca_common.sh"

# Defaults
CTRL_DIR=""
REPORT_FILE=""
PLATFORM="github"  # github or jira
ENV_FILE=".env"
SEVERITY_MIN="HIGH"  # Only create tickets for HIGH and above by default
DRY_RUN=0
SKIP_EXISTING=1

show_usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Create GitHub issues or Jira tickets from security audit findings.

Options:
  --ctrl-dir PATH         Control directory (default: auto-detect)
  --report PATH           Path to audit report JSON (default: latest)
  --platform TYPE         Platform: github or jira (default: github)
  --env-file PATH         Environment file with credentials (default: .env)
  --severity-min LEVEL    Minimum severity (CRITICAL, HIGH, MEDIUM, LOW) (default: HIGH)
  --dry-run               Show what would be created without creating
  --create-all            Create tickets even if they already exist
  -h, --help              Show this help

Environment Variables (or in .env file):
  GitHub:
    GITHUB_TOKEN          GitHub personal access token (or use 'gh' CLI auth)
    GITHUB_REPO           Repository (format: owner/repo)

  Jira:
    JIRA_URL              Jira instance URL (e.g., https://company.atlassian.net)
    JIRA_USER             Jira username/email
    JIRA_API_TOKEN        Jira API token
    JIRA_PROJECT          Jira project key (e.g., SEC, VULN)
    JIRA_ISSUE_TYPE       Issue type (default: Bug)

Examples:
  # Create GitHub issues (using gh CLI)
  $(basename "$0") --platform github

  # Create Jira tickets with custom env file
  $(basename "$0") --platform jira --env-file ~/.sca-jira.env

  # Dry run to see what would be created
  $(basename "$0") --dry-run

  # Create tickets for all severities
  $(basename "$0") --severity-min LOW
EOF
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ctrl-dir) CTRL_DIR="$2"; shift 2;;
        --report) REPORT_FILE="$2"; shift 2;;
        --platform) PLATFORM="$2"; shift 2;;
        --env-file) ENV_FILE="$2"; shift 2;;
        --severity-min) SEVERITY_MIN="$2"; shift 2;;
        --dry-run) DRY_RUN=1; shift;;
        --create-all) SKIP_EXISTING=0; shift;;
        -h|--help) show_usage; exit 0;;
        *) log_error "Unknown option: $1"; show_usage; exit 1;;
    esac
done

# Load environment file if it exists
if [[ -f "$ENV_FILE" ]]; then
    log_info "Loading environment from: $ENV_FILE"
    set -a
    source "$ENV_FILE"
    set +a
else
    log_warn "No .env file found at $ENV_FILE - using environment variables"
fi

# Auto-detect control directory
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

# Find latest report if not specified
if [[ -z "$REPORT_FILE" ]]; then
    REPORT_FILE="$CTRL_DIR/reports/security-audit.latest.json"
fi

if [[ ! -f "$REPORT_FILE" ]]; then
    log_error "Report file not found: $REPORT_FILE"
    exit 1
fi

# Ensure jq is available
if ! command -v jq &> /dev/null; then
    log_error "jq is required for parsing JSON reports"
    exit 1
fi

log_info "Platform: $PLATFORM"
log_info "Report: $REPORT_FILE"
log_info "Minimum severity: $SEVERITY_MIN"

# Ticket tracking file
TICKET_TRACKER="$CTRL_DIR/state/created-tickets.json"
mkdir -p "$CTRL_DIR/state"

if [[ ! -f "$TICKET_TRACKER" ]]; then
    echo '{"tickets": []}' > "$TICKET_TRACKER"
fi

# Check if finding already has a ticket
has_ticket() {
    local finding_id="$1"
    jq -e ".tickets[] | select(.finding_id == \"$finding_id\")" "$TICKET_TRACKER" &>/dev/null
}

# Record created ticket
record_ticket() {
    local finding_id="$1"
    local ticket_url="$2"
    local ticket_key="$3"

    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    # Add to tracker
    jq --arg fid "$finding_id" \
       --arg url "$ticket_url" \
       --arg key "$ticket_key" \
       --arg ts "$timestamp" \
       '.tickets += [{
           "finding_id": $fid,
           "ticket_key": $key,
           "ticket_url": $url,
           "created_at": $ts
       }]' "$TICKET_TRACKER" > "$TICKET_TRACKER.tmp"

    mv "$TICKET_TRACKER.tmp" "$TICKET_TRACKER"
}

# Create GitHub issue
create_github_issue() {
    local finding_id="$1"
    local title="$2"
    local body="$3"
    local severity="$4"
    local file_path="$5"

    # Check if gh CLI is available
    if ! command -v gh &> /dev/null; then
        log_error "GitHub CLI 'gh' is required for GitHub integration"
        log_error "Install: https://cli.github.com/"
        return 1
    fi

    # Check authentication
    if ! gh auth status &>/dev/null; then
        log_error "Not authenticated with GitHub. Run: gh auth login"
        return 1
    fi

    # Build labels
    local labels="security,sca-finding"
    case "$severity" in
        CRITICAL) labels="$labels,severity:critical,priority:p0";;
        HIGH) labels="$labels,severity:high,priority:p1";;
        MEDIUM) labels="$labels,severity:medium,priority:p2";;
        LOW) labels="$labels,severity:low,priority:p3";;
    esac

    if [[ $DRY_RUN -eq 1 ]]; then
        log_info "[DRY RUN] Would create GitHub issue:"
        log_info "  Title: $title"
        log_info "  Labels: $labels"
        log_info "  Finding: $finding_id"
        return 0
    fi

    # Create issue
    local issue_url
    issue_url=$(gh issue create \
        --title "$title" \
        --body "$body" \
        --label "$labels" \
        2>&1)

    if [[ $? -eq 0 ]]; then
        log_info "✓ Created GitHub issue: $issue_url"

        # Extract issue number from URL
        local issue_number=$(echo "$issue_url" | grep -oP '\d+$')
        record_ticket "$finding_id" "$issue_url" "#$issue_number"
        return 0
    else
        log_error "Failed to create GitHub issue: $issue_url"
        return 1
    fi
}

# Create Jira ticket
create_jira_ticket() {
    local finding_id="$1"
    local title="$2"
    local body="$3"
    local severity="$4"
    local file_path="$5"

    # Validate required Jira environment variables
    if [[ -z "$JIRA_URL" ]] || [[ -z "$JIRA_USER" ]] || [[ -z "$JIRA_API_TOKEN" ]] || [[ -z "$JIRA_PROJECT" ]]; then
        log_error "Missing required Jira environment variables:"
        log_error "  JIRA_URL, JIRA_USER, JIRA_API_TOKEN, JIRA_PROJECT"
        return 1
    fi

    local issue_type="${JIRA_ISSUE_TYPE:-Bug}"

    # Map severity to Jira priority
    local priority="Medium"
    case "$severity" in
        CRITICAL) priority="Highest";;
        HIGH) priority="High";;
        MEDIUM) priority="Medium";;
        LOW) priority="Low";;
    esac

    # Build Jira JSON payload
    local jira_payload=$(jq -n \
        --arg project "$JIRA_PROJECT" \
        --arg summary "$title" \
        --arg description "$body" \
        --arg issuetype "$issue_type" \
        --arg priority "$priority" \
        --arg findingid "$finding_id" \
        --arg filepath "$file_path" \
        '{
            "fields": {
                "project": {"key": $project},
                "summary": $summary,
                "description": $description,
                "issuetype": {"name": $issuetype},
                "priority": {"name": $priority},
                "labels": ["security", "sca-finding", ("severity-" + ($priority | ascii_downcase))],
                "customfield_10000": $findingid
            }
        }')

    if [[ $DRY_RUN -eq 1 ]]; then
        log_info "[DRY RUN] Would create Jira ticket:"
        log_info "  Title: $title"
        log_info "  Priority: $priority"
        log_info "  Project: $JIRA_PROJECT"
        log_info "  Finding: $finding_id"
        return 0
    fi

    # Create Jira ticket
    local response
    response=$(curl -s -w "\n%{http_code}" \
        -X POST \
        -H "Content-Type: application/json" \
        -u "$JIRA_USER:$JIRA_API_TOKEN" \
        -d "$jira_payload" \
        "$JIRA_URL/rest/api/2/issue")

    local http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | head -n-1)

    if [[ "$http_code" == "201" ]]; then
        local issue_key=$(echo "$body" | jq -r '.key')
        local issue_url="$JIRA_URL/browse/$issue_key"

        log_info "✓ Created Jira ticket: $issue_url"
        record_ticket "$finding_id" "$issue_url" "$issue_key"
        return 0
    else
        log_error "Failed to create Jira ticket (HTTP $http_code):"
        log_error "$body"
        return 1
    fi
}

# Extract remediation suggestion for a finding from SUGGESTIONS.md
extract_remediation_suggestion() {
    local finding_id="$1"
    local suggestions_file="$CTRL_DIR/SUGGESTIONS.md"

    if [[ ! -f "$suggestions_file" ]]; then
        echo "No remediation suggestions available"
        return
    fi

    # Extract the section for this finding ID
    # Pattern: ### FINDING-ID: Title ... up to next ### or ---
    awk -v id="$finding_id" '
        /^### / {
            if ($0 ~ "^### " id ":") {
                in_section=1
                print
                next
            } else if (in_section) {
                exit
            }
        }
        /^---$/ && in_section { exit }
        in_section { print }
    ' "$suggestions_file"
}

# Generate ticket body from finding
generate_ticket_body() {
    local finding_json="$1"
    local platform="$2"

    local finding_id=$(echo "$finding_json" | jq -r '.id')
    local title=$(echo "$finding_json" | jq -r '.title')
    local file=$(echo "$finding_json" | jq -r '.file // .files[0] // "unknown"')
    local lines=$(echo "$finding_json" | jq -r '.lines // ""')
    local cwe=$(echo "$finding_json" | jq -r '.cwe // ""')
    local impact=$(echo "$finding_json" | jq -r '.impact // ""')
    local remediation=$(echo "$finding_json" | jq -r '.remediation_priority // ""')

    local file_location="$file"
    if [[ -n "$lines" ]]; then
        file_location="$file:$lines"
    fi

    # Get remediation suggestion
    local suggestion=$(extract_remediation_suggestion "$finding_id")

    if [[ "$platform" == "github" ]]; then
        # GitHub Markdown format
        cat <<EOF
## Security Finding: $finding_id

**File**: \`$file_location\`
**CWE**: $cwe
**Remediation Priority**: $remediation

### Impact
$impact

### Location
\`\`\`
$file_location
\`\`\`

### Remediation Steps
$suggestion

### References
- [Security Audit Report](sec-ctrl/reports/security-audit.latest.md)
- [Full Remediation Guide](sec-ctrl/SUGGESTIONS.md)

---
*This issue was automatically created by SCA (Security Control Agent)*
*Finding ID: $finding_id*
EOF
    else
        # Jira format (convert markdown to Jira markup)
        local jira_suggestion=$(echo "$suggestion" | \
            sed 's/^### /h3. /g' | \
            sed 's/^## /h2. /g' | \
            sed 's/^# /h1. /g' | \
            sed 's/```/\{code\}/g' | \
            sed 's/\*\*\(.*\)\*\*/\*\1\*/g')

        cat <<EOF
h2. Security Finding: $finding_id

*File*: {{$file_location}}
*CWE*: $cwe
*Remediation Priority*: $remediation

h3. Impact
$impact

h3. Location
{code}
$file_location
{code}

h3. Remediation Steps
$jira_suggestion

h3. References
* [Security Audit Report|sec-ctrl/reports/security-audit.latest.md]
* [Full Remediation Guide|sec-ctrl/SUGGESTIONS.md]

----
_This ticket was automatically created by SCA (Security Control Agent)_
_Finding ID: $finding_id_
EOF
    fi
}

# Check if severity meets threshold
severity_meets_threshold() {
    local severity="$1"
    local threshold="$SEVERITY_MIN"

    # Severity hierarchy
    local -A severity_levels=([CRITICAL]=4 [HIGH]=3 [MEDIUM]=2 [LOW]=1)

    local finding_level=${severity_levels[$severity]:-0}
    local threshold_level=${severity_levels[$threshold]:-0}

    [[ $finding_level -ge $threshold_level ]]
}

# Main processing
log_info "Processing findings from report..."

total_findings=0
created_count=0
skipped_count=0
error_count=0

# Process critical findings
while IFS= read -r finding; do
    total_findings=$((total_findings + 1))

    finding_id=$(echo "$finding" | jq -r '.id')
    title=$(echo "$finding" | jq -r '.title')
    severity="CRITICAL"
    file=$(echo "$finding" | jq -r '.file // .files[0] // "unknown"')

    # Check severity threshold
    if ! severity_meets_threshold "$severity" "$SEVERITY_MIN"; then
        log_info "Skipping $finding_id (severity below threshold)"
        skipped_count=$((skipped_count + 1))
        continue
    fi

    # Check if already has ticket
    if [[ $SKIP_EXISTING -eq 1 ]] && has_ticket "$finding_id"; then
        existing_ticket=$(jq -r ".tickets[] | select(.finding_id == \"$finding_id\") | .ticket_url" "$TICKET_TRACKER")
        log_info "Skipping $finding_id (ticket exists: $existing_ticket)"
        skipped_count=$((skipped_count + 1))
        continue
    fi

    # Generate ticket content
    ticket_title="[CRITICAL] $title"
    ticket_body=$(generate_ticket_body "$finding" "$PLATFORM")

    # Create ticket based on platform
    if [[ "$PLATFORM" == "github" ]]; then
        if create_github_issue "$finding_id" "$ticket_title" "$ticket_body" "$severity" "$file"; then
            created_count=$((created_count + 1))
        else
            error_count=$((error_count + 1))
        fi
    elif [[ "$PLATFORM" == "jira" ]]; then
        if create_jira_ticket "$finding_id" "$ticket_title" "$ticket_body" "$severity" "$file"; then
            created_count=$((created_count + 1))
        else
            error_count=$((error_count + 1))
        fi
    else
        log_error "Unsupported platform: $PLATFORM"
        exit 1
    fi

done < <(jq -c '.findings.critical[]?' "$REPORT_FILE")

# Process high findings
while IFS= read -r finding; do
    total_findings=$((total_findings + 1))

    finding_id=$(echo "$finding" | jq -r '.id')
    title=$(echo "$finding" | jq -r '.title')
    severity="HIGH"
    file=$(echo "$finding" | jq -r '.file // .files[0] // "unknown"')

    if ! severity_meets_threshold "$severity" "$SEVERITY_MIN"; then
        skipped_count=$((skipped_count + 1))
        continue
    fi

    if [[ $SKIP_EXISTING -eq 1 ]] && has_ticket "$finding_id"; then
        existing_ticket=$(jq -r ".tickets[] | select(.finding_id == \"$finding_id\") | .ticket_url" "$TICKET_TRACKER")
        log_info "Skipping $finding_id (ticket exists: $existing_ticket)"
        skipped_count=$((skipped_count + 1))
        continue
    fi

    ticket_title="[HIGH] $title"
    ticket_body=$(generate_ticket_body "$finding" "$PLATFORM")

    if [[ "$PLATFORM" == "github" ]]; then
        if create_github_issue "$finding_id" "$ticket_title" "$ticket_body" "$severity" "$file"; then
            created_count=$((created_count + 1))
        else
            error_count=$((error_count + 1))
        fi
    elif [[ "$PLATFORM" == "jira" ]]; then
        if create_jira_ticket "$finding_id" "$ticket_title" "$ticket_body" "$severity" "$file"; then
            created_count=$((created_count + 1))
        else
            error_count=$((error_count + 1))
        fi
    fi

done < <(jq -c '.findings.high[]?' "$REPORT_FILE")

# Process medium findings
while IFS= read -r finding; do
    total_findings=$((total_findings + 1))

    finding_id=$(echo "$finding" | jq -r '.id')
    title=$(echo "$finding" | jq -r '.title')
    severity="MEDIUM"
    file=$(echo "$finding" | jq -r '.file // .files[0] // "unknown"')

    if ! severity_meets_threshold "$severity" "$SEVERITY_MIN"; then
        skipped_count=$((skipped_count + 1))
        continue
    fi

    if [[ $SKIP_EXISTING -eq 1 ]] && has_ticket "$finding_id"; then
        existing_ticket=$(jq -r ".tickets[] | select(.finding_id == \"$finding_id\") | .ticket_url" "$TICKET_TRACKER")
        log_info "Skipping $finding_id (ticket exists: $existing_ticket)"
        skipped_count=$((skipped_count + 1))
        continue
    fi

    ticket_title="[MEDIUM] $title"
    ticket_body=$(generate_ticket_body "$finding" "$PLATFORM")

    if [[ "$PLATFORM" == "github" ]]; then
        if create_github_issue "$finding_id" "$ticket_title" "$ticket_body" "$severity" "$file"; then
            created_count=$((created_count + 1))
        else
            error_count=$((error_count + 1))
        fi
    elif [[ "$PLATFORM" == "jira" ]]; then
        if create_jira_ticket "$finding_id" "$ticket_title" "$ticket_body" "$severity" "$file"; then
            created_count=$((created_count + 1))
        else
            error_count=$((error_count + 1))
        fi
    fi

done < <(jq -c '.findings.medium[]?' "$REPORT_FILE")

# Summary
echo ""
echo "=========================================="
echo "Ticket Creation Summary"
echo "=========================================="
echo "Total findings processed: $total_findings"
echo "Tickets created: $created_count"
echo "Skipped (existing/threshold): $skipped_count"
echo "Errors: $error_count"
echo "=========================================="

if [[ $DRY_RUN -eq 1 ]]; then
    echo ""
    echo "This was a DRY RUN - no tickets were actually created"
fi

log_info "Ticket tracker: $TICKET_TRACKER"
exit 0
