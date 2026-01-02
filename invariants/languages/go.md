# Go Security Invariants — Memory Leaks, Concurrency, Injections (v1)

## Error Handling
- **Check all errors**: Never ignore error returns (`_, err := foo(); // err not checked`)
- **Wrap errors with context**: Use `fmt.Errorf("context: %w", err)` for error chains
- **No panics in production**: Catch panics with `recover()` in goroutine handlers
- **Validate input before processing**: Check bounds, types, nil pointers

## Memory Leaks & Resource Management
- **Close resources in defer**: `defer file.Close()`, `defer conn.Close()`
- **Context cancellation**: Always pass `context.Context` to long-running operations
- **Goroutine leaks**: Ensure goroutines terminate (use channels/context for signaling)
  - Pattern: `go func() { for { ... } }()` without exit condition
- **Timers/Tickers**: MUST call `.Stop()` when done (prevents leak)
  - Pattern: `time.AfterFunc()`, `time.NewTicker()` without `.Stop()`
- **HTTP body leaks**: MUST read/close response bodies
  - Pattern: `resp, _ := http.Get(url)` without `defer resp.Body.Close()`

## Concurrency & Threading
- **Data races**: Use mutexes or channels for shared state
  - Run with `-race` flag in tests to detect
- **Mutex lock/unlock**: Always `defer mu.Unlock()` after `mu.Lock()`
- **Channel deadlocks**: Avoid sending/receiving on unbuffered channels without goroutine
- **WaitGroup misuse**: Call `.Add()` before goroutine starts, `.Done()` inside
- **Context propagation**: Pass context through function calls, check `ctx.Done()`

## Injection Vulnerabilities
- **SQL injection**: Use parameterized queries (`db.Query("SELECT * FROM users WHERE id = ?", userID)`)
  - NEVER: `db.Query("SELECT * FROM users WHERE id = " + userID)`
- **Command injection**: Use `exec.Command()` with separate args, NOT shell
  - NEVER: `exec.Command("sh", "-c", userInput)`
- **Path traversal**: Validate/sanitize file paths (`filepath.Clean()`, check prefix)

## Cryptography
- **Use `crypto/rand`**, NEVER `math/rand` for security
- **TLS config**: `InsecureSkipVerify: false` (default), use cert validation
- **Weak ciphers**: Set `MinVersion: tls.VersionTLS12` minimum

## GC Pressure & Performance
- **Large allocations in hot paths**: Reuse buffers via `sync.Pool`
- **String concatenation in loops**: Use `strings.Builder` not `+`
- **Defer in tight loops**: Can cause GC pressure (use explicit cleanup instead)

## Comparison
- **Timing-safe comparison**: Use `subtle.ConstantTimeCompare()` for secrets/tokens/HMACs
