# SCA Performance Benchmarks

Performance benchmarking infrastructure for SCA security audits on repositories of varying sizes.

## Overview

This directory contains tools to:
- Generate test repositories (1K to 100K files)
- Run performance benchmarks
- Measure execution time, memory usage, CPU utilization
- Aggregate and analyze results

## Quick Start

### 1. Generate Test Repository

```bash
# Generate small test repo (1,000 files)
./generators/generate-test-repo.py --size small --output test-repos/small

# Generate medium test repo (10,000 files)
./generators/generate-test-repo.py --size medium --output test-repos/medium

# Generate large test repo (50,000 files)
./generators/generate-test-repo.py --size large --output test-repos/large

# Generate extra-large test repo (100,000 files)
./generators/generate-test-repo.py --size xlarge --output test-repos/xlarge
```

### 2. Run Benchmarks

```bash
# Benchmark small repository (3 runs)
./scripts/run-benchmark.sh --size small --runs 3

# Benchmark all sizes
./scripts/run-benchmark.sh --size all --runs 3

# Benchmark with custom results directory
./scripts/run-benchmark.sh --size medium --runs 5 --results-dir /tmp/benchmark-results

# Skip repo generation (use existing)
./scripts/run-benchmark.sh --size small --skip-generation
```

### 3. View Results

```bash
# View individual run results
cat results/small_run1_20260103_120000.json

# View aggregate results
cat results/small_aggregate.json

# Generate performance report
./scripts/generate-report.sh --results-dir results --output PERFORMANCE.md
```

## Directory Structure

```
benchmarks/
├── README.md                    # This file
├── generators/
│   └── generate-test-repo.py    # Test repository generator
├── scripts/
│   ├── run-benchmark.sh         # Benchmark runner
│   └── generate-report.sh       # Report generator
├── test-repos/                  # Generated test repositories
│   ├── small/                   # 1,000 files
│   ├── medium/                  # 10,000 files
│   ├── large/                   # 50,000 files
│   └── xlarge/                  # 100,000 files
└── results/                     # Benchmark results (JSON)
    ├── small_run1_*.json
    ├── small_aggregate.json
    ├── medium_run1_*.json
    └── ...
```

## Test Repository Characteristics

Generated test repositories include realistic code structures across multiple languages:

### Small (1,000 files)
- **Target size**: 1,000 files
- **Languages**: Python, Go, JavaScript, Java
- **Distribution**: ~250 files per language
- **Estimated size**: ~5 MB
- **Typical audit time**: 2-5 minutes

### Medium (10,000 files)
- **Target size**: 10,000 files
- **Languages**: Python, Go, JavaScript, Java
- **Distribution**: ~2,500 files per language
- **Estimated size**: ~50 MB
- **Typical audit time**: 10-30 minutes

### Large (50,000 files)
- **Target size**: 50,000 files
- **Languages**: Python, Go, JavaScript, Java
- **Distribution**: ~12,500 files per language
- **Estimated size**: ~250 MB
- **Typical audit time**: 30-90 minutes

### Extra-Large (100,000 files)
- **Target size**: 100,000 files
- **Languages**: Python, Go, JavaScript, Java
- **Distribution**: ~25,000 files per language
- **Estimated size**: ~500 MB
- **Typical audit time**: 1-2 hours

## Metrics Collected

Each benchmark run collects:

### Performance Metrics
- **Duration**: Total audit execution time (seconds)
- **Wall clock time**: Real-world time elapsed
- **Max memory**: Peak resident set size (KB)
- **Memory delta**: Change in system memory usage (MB)
- **CPU utilization**: Percentage of CPU used

### Repository Metrics
- **Files analyzed**: Actual number of files in audit scope
- **Report size**: Output report file size (bytes)
- **Findings count**: Number of security findings detected

### Metadata
- **SCA version**: Version of SCA used for benchmark
- **Timestamp**: When benchmark was run
- **Run number**: Iteration number (1-N)
- **Exit code**: Audit exit code (0=success, 2=findings, etc.)

## Result Format

Individual run results are stored as JSON:

```json
{
  "benchmark": {
    "size": "small",
    "target_files": 1000,
    "run_number": 1,
    "timestamp": "20260103_120000",
    "sca_version": "0.8.9"
  },
  "repository": {
    "path": "/path/to/test-repos/small",
    "files_analyzed": 987
  },
  "performance": {
    "duration_seconds": 180,
    "wall_clock_time": "3:00.45",
    "max_memory_kb": 524288,
    "memory_delta_mb": 450,
    "cpu_percent": "95"
  },
  "output": {
    "report_size_bytes": 102400,
    "findings_count": 15,
    "exit_code": 2
  }
}
```

Aggregate results provide statistics across multiple runs:

```json
{
  "size": "small",
  "runs": 3,
  "target_files": 1000,
  "averages": {
    "duration_seconds": 175,
    "max_memory_kb": 512000,
    "files_analyzed": 985
  },
  "results_files": [
    "results/small_run1_20260103_120000.json",
    "results/small_run2_20260103_120500.json",
    "results/small_run3_20260103_121000.json"
  ]
}
```

## Performance Targets

SCA aims to achieve the following performance targets:

| Size | Files | Duration Target | Memory Target | Status |
|------|-------|----------------|---------------|--------|
| Small | 1K | < 5 minutes | < 1 GB | 🎯 Target |
| Medium | 10K | < 30 minutes | < 2 GB | 🎯 Target |
| Large | 50K | < 2 hours | < 4 GB | 🎯 Target |
| XLarge | 100K | < 4 hours | < 8 GB | 🎯 Target |

## Interpreting Results

### Good Performance
- Duration within target range
- Memory usage scales linearly with repository size
- CPU utilization > 80% (efficient use of resources)
- Exit code 0 or 2 (successful audit)

### Performance Issues
- Duration exceeds target by > 50%
- Memory usage > 2x target
- CPU utilization < 50% (bottlenecked)
- Exit code 3, 4, or 5 (errors)

### Common Bottlenecks
1. **Slow Claude API responses** - Network latency or rate limiting
2. **Large prompt construction** - Too many files in scope
3. **Inefficient file I/O** - Reading many small files
4. **Memory pressure** - Large repositories causing swap

## Optimization Strategies

If benchmarks show poor performance:

### 1. Reduce Scope
```bash
# Add exclusions to sec-ctrl/config/ignore.paths
node_modules/
vendor/
.venv/
dist/
build/
generated/
```

### 2. Enable Incremental Mode
```bash
# Skip audit if repository unchanged
./bin/sca audit --incremental
```

### 3. Filter by Language
```bash
# Analyze only specific file types
# (Future feature - not yet implemented)
./bin/sca audit --languages python,go
```

### 4. Parallel Processing
```bash
# Split large repos into modules
# Audit each module separately
# (Future feature - not yet implemented)
```

## CI/CD Integration

Run benchmarks in CI to detect performance regressions:

```yaml
name: Performance Benchmarks

on:
  pull_request:
    paths:
      - 'bin/**'
      - 'invariants/**'
      - 'prompts/**'

jobs:
  benchmark:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install Claude Code
        run: curl -fsSL https://claude.com/download/cli/linux | bash

      - name: Run small benchmark
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          cd benchmarks
          ./scripts/run-benchmark.sh --size small --runs 3

      - name: Upload results
        uses: actions/upload-artifact@v3
        with:
          name: benchmark-results
          path: benchmarks/results/

      - name: Check performance regression
        run: |
          # Compare with baseline
          # Fail if duration > 20% slower
          ./benchmarks/scripts/check-regression.sh
```

## Troubleshooting

### "Test repository generation failed"
- Ensure Python 3.7+ is installed
- Check disk space (100K files need ~500 MB)
- Verify write permissions on test-repos/

### "Benchmark hangs or times out"
- Check Claude API connectivity
- Verify ANTHROPIC_API_KEY is set
- Monitor API rate limits
- Try smaller repository size first

### "Out of memory errors"
- Close other applications
- Increase system swap space
- Use smaller repository size
- Check for memory leaks in SCA

### "Inconsistent results across runs"
- Run more iterations (--runs 5 or --runs 10)
- Ensure system is idle during benchmarks
- Check for background processes consuming resources
- Disable power-saving features

## Contributing

To add new benchmark types:

1. **Create new generator** in `generators/`
2. **Add size configuration** to `run-benchmark.sh`
3. **Update targets** in this README
4. **Run validation** with 3+ runs
5. **Submit PR** with results

## References

- [GA Roadmap](../docs/GA_ROADMAP.md) - Week 4: Performance benchmarks
- [CLAUDE_CODE_GUIDE.md](../docs/CLAUDE_CODE_GUIDE.md) - Performance considerations
- [INSTALL.md](../INSTALL.md) - Installation requirements

---

**Generated for SCA v0.8.9**
