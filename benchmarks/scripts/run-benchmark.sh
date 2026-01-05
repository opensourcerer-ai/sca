#!/usr/bin/env bash
#
# SCA Performance Benchmark Runner
#
# Runs SCA audits on test repositories of varying sizes and measures:
# - Execution time
# - Memory usage
# - CPU usage
# - Output size
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCHMARK_ROOT="$SCRIPT_DIR/.."
PROJECT_ROOT="$BENCHMARK_ROOT/.."

# shellcheck source=lib/sca_common.sh
source "$PROJECT_ROOT/lib/sca_common.sh"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

usage() {
  cat <<EOF
Usage: run-benchmark.sh [OPTIONS]

Run SCA performance benchmarks on test repositories.

Options:
  --size SIZE              Repository size: small, medium, large, xlarge, all
  --runs N                 Number of runs per size (default: 3)
  --skip-generation        Skip test repo generation (use existing)
  --results-dir DIR        Results output directory (default: ./results)
  --verbose                Show detailed output
  -h, --help               Show this help

Examples:
  run-benchmark.sh --size small --runs 3
  run-benchmark.sh --size all --results-dir /tmp/benchmark-results
  run-benchmark.sh --size medium --skip-generation --verbose
EOF
}

# Defaults
SIZE="small"
RUNS=3
SKIP_GENERATION=0
RESULTS_DIR="$BENCHMARK_ROOT/results"
VERBOSE=0

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --size) SIZE="$2"; shift 2;;
    --runs) RUNS="$2"; shift 2;;
    --skip-generation) SKIP_GENERATION=1; shift;;
    --results-dir) RESULTS_DIR="$2"; shift 2;;
    --verbose) VERBOSE=1; shift;;
    -h|--help) usage; exit 0;;
    *) echo "[ERROR] Unknown arg: $1"; usage; exit 3;;
  esac
done

# Validate SIZE
VALID_SIZES=("small" "medium" "large" "xlarge" "all")
if [[ ! " ${VALID_SIZES[@]} " =~ " ${SIZE} " ]]; then
  echo -e "${RED}[ERROR] Invalid size: $SIZE${NC}"
  echo "Valid sizes: ${VALID_SIZES[*]}"
  exit 3
fi

# Create results directory
mkdir -p "$RESULTS_DIR"

# Size configurations
declare -A SIZE_FILES
SIZE_FILES[small]=1000
SIZE_FILES[medium]=10000
SIZE_FILES[large]=50000
SIZE_FILES[xlarge]=100000

log_info() {
  echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
  echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_error() {
  echo -e "${RED}[ERROR]${NC} $*"
}

log_warn() {
  echo -e "${YELLOW}[WARN]${NC} $*"
}

# Generate test repository
generate_test_repo() {
  local size="$1"
  local repo_dir="$BENCHMARK_ROOT/test-repos/$size"

  if [[ $SKIP_GENERATION -eq 1 && -d "$repo_dir" ]]; then
    log_info "Skipping generation for $size (already exists)"
    return 0
  fi

  log_info "Generating test repository: $size (${SIZE_FILES[$size]} files)"

  rm -rf "$repo_dir"

  python3 "$BENCHMARK_ROOT/generators/generate-test-repo.py" \
    --size "$size" \
    --output "$repo_dir"

  if [[ ! -d "$repo_dir" ]]; then
    log_error "Failed to generate test repository: $size"
    return 1
  fi

  log_success "Generated: $repo_dir"
}

# Run single benchmark
run_single_benchmark() {
  local size="$1"
  local run_number="$2"
  local repo_dir="$BENCHMARK_ROOT/test-repos/$size"
  local timestamp=$(date +%Y%m%d_%H%M%S)
  local result_file="$RESULTS_DIR/${size}_run${run_number}_${timestamp}.json"

  log_info "Running benchmark: $size (run $run_number/$RUNS)"

  # Ensure repo exists
  if [[ ! -d "$repo_dir" ]]; then
    log_error "Test repository not found: $repo_dir"
    return 1
  fi

  # Initialize sec-ctrl in test repo
  cd "$repo_dir"
  if [[ ! -d "sec-ctrl" ]]; then
    "$PROJECT_ROOT/bin/sec-bootstrap.sh" --repo "$repo_dir" >/dev/null 2>&1
  fi

  # Measure performance
  local start_time=$(date +%s)
  local start_mem=$(free -m | awk 'NR==2 {print $3}')

  # Run SCA audit with time and resource tracking
  local audit_output
  local audit_exit_code

  if [[ $VERBOSE -eq 1 ]]; then
    /usr/bin/time -v "$PROJECT_ROOT/bin/sec-audit.sh" \
      --repo "$repo_dir" \
      --format json \
      --readonly-agent \
      --incremental \
      2>&1 | tee /tmp/benchmark-audit-output.txt
    audit_exit_code=${PIPESTATUS[0]}
  else
    /usr/bin/time -v "$PROJECT_ROOT/bin/sec-audit.sh" \
      --repo "$repo_dir" \
      --format json \
      --readonly-agent \
      --incremental \
      >/tmp/benchmark-audit-output.txt 2>&1
    audit_exit_code=$?
  fi

  local end_time=$(date +%s)
  local end_mem=$(free -m | awk 'NR==2 {print $3}')

  local duration=$((end_time - start_time))
  local mem_delta=$((end_mem - start_mem))

  # Extract metrics from /usr/bin/time output
  local max_rss=$(grep "Maximum resident set size" /tmp/benchmark-audit-output.txt | awk '{print $6}')
  local cpu_percent=$(grep "Percent of CPU" /tmp/benchmark-audit-output.txt | awk '{print $7}' | tr -d '%')
  local wall_time=$(grep "Elapsed (wall clock)" /tmp/benchmark-audit-output.txt | awk '{print $8}')

  # Count files analyzed
  local files_analyzed=0
  if [[ -f "$repo_dir/sec-ctrl/state/scope-hash.txt" ]]; then
    files_analyzed=$(wc -l < "$repo_dir/sec-ctrl/state/scope-hash.txt" 2>/dev/null || echo 0)
  fi

  # Report size
  local report_size=0
  if [[ -f "$repo_dir/sec-ctrl/reports/security-audit.latest.md" ]]; then
    report_size=$(wc -c < "$repo_dir/sec-ctrl/reports/security-audit.latest.md")
  fi

  # Extract findings count from JSON report
  local findings_count=0
  if [[ -f "$repo_dir/sec-ctrl/reports/security-audit.latest.json" ]]; then
    findings_count=$(jq -r '.summary.total_findings // 0' "$repo_dir/sec-ctrl/reports/security-audit.latest.json" 2>/dev/null || echo 0)
  fi

  # Write results
  cat > "$result_file" <<EOF
{
  "benchmark": {
    "size": "$size",
    "target_files": ${SIZE_FILES[$size]},
    "run_number": $run_number,
    "timestamp": "$timestamp",
    "sca_version": "$(cat "$PROJECT_ROOT/VERSION" 2>/dev/null || echo "unknown")"
  },
  "repository": {
    "path": "$repo_dir",
    "files_analyzed": $files_analyzed
  },
  "performance": {
    "duration_seconds": $duration,
    "wall_clock_time": "$wall_time",
    "max_memory_kb": ${max_rss:-0},
    "memory_delta_mb": $mem_delta,
    "cpu_percent": "${cpu_percent:-0}"
  },
  "output": {
    "report_size_bytes": $report_size,
    "findings_count": $findings_count,
    "exit_code": $audit_exit_code
  }
}
EOF

  log_success "Benchmark complete: $size (run $run_number)"
  log_info "  Duration: ${duration}s | Memory: ${max_rss:-0} KB | Files: $files_analyzed | Findings: $findings_count"
  log_info "  Results: $result_file"

  cd "$BENCHMARK_ROOT"
}

# Aggregate results
aggregate_results() {
  local size="$1"

  log_info "Aggregating results for: $size"

  local result_files=("$RESULTS_DIR/${size}_run"*.json)

  if [[ ${#result_files[@]} -eq 0 ]]; then
    log_warn "No results found for $size"
    return
  fi

  # Calculate statistics
  local total_duration=0
  local total_memory=0
  local total_files=0
  local count=0

  for result_file in "${result_files[@]}"; do
    if [[ ! -f "$result_file" ]]; then
      continue
    fi

    local duration=$(jq -r '.performance.duration_seconds' "$result_file")
    local memory=$(jq -r '.performance.max_memory_kb' "$result_file")
    local files=$(jq -r '.repository.files_analyzed' "$result_file")

    total_duration=$((total_duration + duration))
    total_memory=$((total_memory + memory))
    total_files=$((total_files + files))
    count=$((count + 1))
  done

  if [[ $count -eq 0 ]]; then
    log_warn "No valid results for $size"
    return
  fi

  local avg_duration=$((total_duration / count))
  local avg_memory=$((total_memory / count))
  local avg_files=$((total_files / count))

  # Write aggregate
  local aggregate_file="$RESULTS_DIR/${size}_aggregate.json"
  cat > "$aggregate_file" <<EOF
{
  "size": "$size",
  "runs": $count,
  "target_files": ${SIZE_FILES[$size]},
  "averages": {
    "duration_seconds": $avg_duration,
    "max_memory_kb": $avg_memory,
    "files_analyzed": $avg_files
  },
  "results_files": [
    $(printf '"%s",' "${result_files[@]}" | sed 's/,$//')
  ]
}
EOF

  log_success "Aggregate results: $aggregate_file"
  log_info "  Average duration: ${avg_duration}s | Average memory: ${avg_memory} KB | Average files: $avg_files"
}

# Main benchmark workflow
main() {
  echo ""
  echo "SCA Performance Benchmark"
  echo "========================="
  echo "Size: $SIZE"
  echo "Runs per size: $RUNS"
  echo "Results directory: $RESULTS_DIR"
  echo ""

  # Determine sizes to benchmark
  local sizes_to_run=()
  if [[ "$SIZE" == "all" ]]; then
    sizes_to_run=("small" "medium" "large" "xlarge")
  else
    sizes_to_run=("$SIZE")
  fi

  # Run benchmarks
  for size in "${sizes_to_run[@]}"; do
    log_info "=== Benchmarking: $size ==="

    # Generate test repo
    if ! generate_test_repo "$size"; then
      log_error "Failed to generate test repository: $size"
      continue
    fi

    # Run multiple iterations
    for run in $(seq 1 "$RUNS"); do
      if ! run_single_benchmark "$size" "$run"; then
        log_error "Benchmark failed: $size (run $run)"
      fi

      # Sleep between runs
      if [[ $run -lt $RUNS ]]; then
        sleep 2
      fi
    done

    # Aggregate results
    aggregate_results "$size"

    echo ""
  done

  log_success "All benchmarks complete!"
  log_info "Results directory: $RESULTS_DIR"
}

main
