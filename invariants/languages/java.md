# Java Security Invariants — Memory Leaks, Threading, Injections (v1)

## Injection Vulnerabilities
- **SQL injection**: Use `PreparedStatement`, NEVER string concatenation in SQL
  - Pattern: `String sql = "SELECT * FROM users WHERE id = " + userId;` (CRITICAL)
- **Command injection**: Avoid `Runtime.exec()` with shell, use `ProcessBuilder` with array
- **XXE (XML External Entity)**: Disable DTD processing in XML parsers
  - `factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);`
- **Deserialization**: NEVER deserialize untrusted data (ObjectInputStream)
  - Use safe formats (JSON, protobuf), or filter classes with `ValidatingObjectInputStream`

## Memory Leaks (GC Issues)
- **Listeners not removed**: Add listeners but forget to remove → memory leak
  - Pattern: `obj.addListener(listener)` without corresponding `removeListener()`
- **ThreadLocal leaks**: Not calling `.remove()` in thread pools → old data persists
- **Static collections**: Growing static `Map`/`List` without eviction policy
- **Classloader leaks**: Holding references to classes/classloaders (esp. in app servers)
- **InputStream/Reader not closed**: MUST use try-with-resources
  - Pattern: `InputStream in = new FileInputStream(file);` without close

## Threading & Concurrency
- **Race conditions**: Unsynchronized access to shared mutable state
- **Double-checked locking**: Broken without `volatile` (use enum singleton instead)
  - Pattern: `if (instance == null) { synchronized { if (instance == null) ... } }`
- **Deadlocks**: Acquire locks in consistent order, use `tryLock()` with timeout
- **Thread pool exhaustion**: Unbounded `Executors.newCachedThreadPool()` with external input
- **Volatile misuse**: `volatile` ensures visibility, NOT atomicity (use `AtomicInteger` etc.)
- **Wait/notify**: ALWAYS in while loop, not if (`while (!condition) { wait(); }`)

## Resource Management
- **Try-with-resources**: Use for AutoCloseable (files, sockets, DB connections)
  - Pattern: `try (FileInputStream fis = new FileInputStream(file)) { ... }`
- **Connection pool leaks**: Return connections to pool in finally block
- **File descriptor leaks**: Close streams/channels explicitly or with try-with-resources

## Cryptography
- **Weak RNG**: Use `SecureRandom`, NEVER `java.util.Random` for keys/tokens
- **Weak ciphers**: Avoid DES, RC4, ECB mode (use AES/GCM)
- **Hardcoded keys**: No embedded keys/passwords in source

## Logging & Error Handling
- **Sensitive data in logs**: No passwords, tokens, PII
- **Stack traces to users**: Catch exceptions, return generic error

## Serialization
- **Implement `serialVersionUID`**: Prevents deserialization version mismatch
- **Mark transient**: Sensitive fields should be `transient` (not serialized)

## NULL Safety
- **NullPointerException prevention**: Use `Objects.requireNonNull()`, Optional<T>
- **@Nullable/@NonNull annotations**: Document nullability contracts
