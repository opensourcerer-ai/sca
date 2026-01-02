#!/usr/bin/env bash
set -euo pipefail

# Parse markdown report and extract confirmed Critical/High finding counts
# Usage: report-parser.sh <report.md>
# Exit: 0 if no critical/high, 2 if found, 3 if parse error

REPORT_FILE="${1:-}"

if [[ -z "$REPORT_FILE" ]] || [[ ! -f "$REPORT_FILE" ]]; then
  echo "[ERROR] Report file not found: $REPORT_FILE" >&2
  exit 3
fi

# Extract confirmed findings section
IN_CONFIRMED=0
IN_CRITICAL=0
IN_HIGH=0
CRITICAL_COUNT=0
HIGH_COUNT=0

while IFS= read -r line; do
  # Detect section boundaries
  if [[ "$line" =~ ^##[[:space:]]*Findings[[:space:]]*\(Confirmed\) ]]; then
    IN_CONFIRMED=1
    continue
  fi

  if [[ "$line" =~ ^##[[:space:]]*Findings[[:space:]]*\(Needs\ Review\) ]]; then
    IN_CONFIRMED=0
    break
  fi

  if [[ "$IN_CONFIRMED" -eq 1 ]]; then
    if [[ "$line" =~ ^###[[:space:]]*Critical ]]; then
      IN_CRITICAL=1
      IN_HIGH=0
    elif [[ "$line" =~ ^###[[:space:]]*High ]]; then
      IN_HIGH=1
      IN_CRITICAL=0
    elif [[ "$line" =~ ^### ]]; then
      IN_CRITICAL=0
      IN_HIGH=0
    fi

    # Count non-empty lines that look like findings (start with -, *, or number)
    if [[ "$IN_CRITICAL" -eq 1 ]] && [[ "$line" =~ ^[[:space:]]*[-*0-9] ]]; then
      ((CRITICAL_COUNT++))
    fi

    if [[ "$IN_HIGH" -eq 1 ]] && [[ "$line" =~ ^[[:space:]]*[-*0-9] ]]; then
      ((HIGH_COUNT++))
    fi
  fi
done < "$REPORT_FILE"

echo "Critical: $CRITICAL_COUNT" >&2
echo "High: $HIGH_COUNT" >&2

TOTAL=$((CRITICAL_COUNT + HIGH_COUNT))
if [[ "$TOTAL" -gt 0 ]]; then
  exit 2
else
  exit 0
fi
