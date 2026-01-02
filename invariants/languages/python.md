# Python Security Invariants — Memory Leaks, Injections, GIL Issues (v1)

## Injection Vulnerabilities
- **SQL injection**: Use parameterized queries, NEVER string formatting in SQL
  - Pattern: `cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")` (CRITICAL)
  - FIX: `cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))`
- **Command injection**: Use `subprocess.run()` with list args, NEVER `shell=True` with user input
  - Pattern: `subprocess.run(f"ls {user_input}", shell=True)` (CRITICAL)
- **Code injection**: NEVER use `eval()`, `exec()`, `compile()` with user input
- **Pickle deserialization**: NEVER unpickle untrusted data (`pickle.loads(untrusted)`)
  - Use JSON, protobuf, or `jsonpickle` with safe mode
- **YAML unsafe**: Use `yaml.safe_load()`, NEVER `yaml.load()` (allows arbitrary code execution)
- **Template injection**: Use Jinja2 with `autoescape=True`, validate template sources

## Memory Leaks (GC Issues)
- **Circular references**: Objects referencing each other prevent GC (use `weakref`)
- **Global collections**: Growing lists/dicts without cleanup
  - Pattern: `_cache = {}` that grows without eviction (use `functools.lru_cache`)
- **File handles not closed**: ALWAYS use context managers (`with open(...)`)
- **DB connections**: MUST close connections/cursors (use context managers)
- **Thread locals**: Cleanup `threading.local()` when threads end
- **Large object retention**: Holding references to large objects in closures/lambdas

## GIL & Concurrency
- **GIL contention**: Multi-threading doesn't parallelize CPU-bound work (use multiprocessing instead)
- **Race conditions**: Use `threading.Lock()` for shared mutable state
- **Deadlocks**: Acquire locks in consistent order, use timeout
- **Daemon threads**: May not finish cleanup (avoid for critical tasks)
- **Queue.get() blocking**: Use timeout to prevent indefinite blocking

## Resource Management
- **Context managers**: Use `with` for files, sockets, locks, DB connections
  - Pattern: `file = open(path)` without `with` or try/finally
- **Database cursors**: Close cursors explicitly or use context managers
- **Network sockets**: Must close (`sock.close()` or `with socket.socket()`)

## Cryptography
- **Weak RNG**: Use `secrets` module (not `random`) for tokens/keys/nonces
  - Pattern: `random.randint()` for security purposes (CRITICAL)
- **Hashlib for passwords**: Use `hashlib.pbkdf2_hmac()`, `bcrypt`, `argon2` (not plain SHA256)
- **Hardcoded secrets**: No API keys, passwords in source code

## Type Safety & Validation
- **Input validation**: Validate all external input (size, type, format)
- **Type hints**: Use for critical functions (helps catch bugs)
- **None checks**: Validate function args that could be None

## Logging
- **No secrets in logs**: Don't log passwords, tokens, keys
- **Sanitize exceptions**: Don't log full stack traces with user data

## Path Traversal
- **User-controlled paths**: Validate file paths, use `pathlib.Path().resolve()` and check prefix
  - Pattern: `open(user_provided_path)` without validation

## SSRF
- **URL validation**: Check URL scheme/hostname before `requests.get(user_url)`
- **Block internal IPs**: Prevent access to 127.0.0.1, 169.254.169.254, RFC1918 ranges

## Timing Attacks
- **Secret comparison**: Use `hmac.compare_digest()` for comparing secrets/tokens/HMACs
  - NEVER: `if user_token == expected_token` (timing leak)
