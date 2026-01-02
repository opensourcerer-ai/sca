# C/C++ Security Invariants — Comprehensive CVE Coverage (v1)

## Memory Safety (CRITICAL — Most Common CVE Source)

### Buffer Overflows
- **Stack buffer overflow**: Writing past array bounds on stack - Patterns: `strcpy()`, `strcat()`, `gets()`, `sprintf()`, unbounded loops writing to fixed-size buffers
  - Evidence: Arrays with fixed size + input from untrusted source
- **Heap buffer overflow**: Writing past malloc'd buffer
  - Patterns: `memcpy(dest, src, user_controlled_size)`, off-by-one errors
- **Mitigation**: Use `strncpy()`, `strncat()`, `snprintf()`, bounds-checked APIs, or C++ `std::string`

### Stack Overflows
- **Large stack allocations**: VLAs (Variable Length Arrays) or `alloca()` with user-controlled size
  - Pattern: `char buf[user_input];` or `alloca(untrusted_size)`
- **Deep recursion**: Unbounded recursion without depth limit
- **Mitigation**: Heap allocation, recursion depth limits, stack canaries (enabled by default in modern compilers)

### Use-After-Free (UAF)
- **Dangling pointers**: Using memory after `free()` or `delete`
  - Pattern: `free(ptr); ... *ptr = value;`
- **Double free**: Calling `free()` twice on same pointer
  - Pattern: `free(ptr); ... free(ptr);`
- **Mitigation**: Set pointers to NULL after free (`ptr = NULL`), use RAII in C++ (smart pointers)

### Uninitialized Variables
- **Reading uninitialized memory**: Variables used before assignment
  - Pattern: `int x; ... return x;` or `char buf[100]; send(sock, buf, 100, 0);`
- **Impact**: Information disclosure (stack/heap contents leak)
- **Mitigation**: Initialize all variables, use compiler warnings (`-Wuninitialized`), sanitizers (MSan)

### Integer Overflows/Underflows
- **Arithmetic overflow**: Integer wrap-around leading to buffer overflow
  - Pattern: `size_t total = count * size;` where multiplication overflows
  - `int len = user_len - offset;` where subtraction underflows
- **Mitigation**: Check for overflow before arithmetic (`__builtin_mul_overflow` in GCC/Clang), use safe arithmetic libraries

### Format String Bugs
- **User-controlled format strings**: Passing user input as format string
  - Pattern: `printf(user_input);` instead of `printf("%s", user_input);`
  - `sprintf(buf, user_input);` instead of `sprintf(buf, "%s", user_input);`
- **Impact**: Memory read/write, RCE
- **Mitigation**: ALWAYS use format string as literal, NEVER pass user input as first arg to printf family

### Null Pointer Dereference
- **Unchecked mallocs**: Using result of `malloc()` without checking for NULL
  - Pattern: `char *buf = malloc(size); strcpy(buf, src);` (no NULL check)
- **Mitigation**: Check all allocations, use `__attribute__((warn_unused_result))`, static analysis

## Concurrency & Race Conditions (CRITICAL for Multi-Threaded Code)

### Race Conditions on Shared Data
- **Missing locks**: Accessing shared variables without mutex
  - Pattern: Multiple threads reading/writing global variables without `pthread_mutex_lock()`
- **Inconsistent locking**: Some accesses protected, others not
- **Mitigation**: All shared mutable state MUST be protected by mutexes or atomics

### Deadlocks
- **Lock ordering**: Acquiring locks in inconsistent order across threads
  - Pattern: Thread A locks M1 then M2; Thread B locks M2 then M1
- **Mitigation**: Define global lock ordering, use `pthread_mutex_trylock()` with timeout

### Time-of-Check-Time-of-Use (TOCTOU)
- **File system race**: Checking file properties then operating on it
  - Pattern: `if (access(file, R_OK) == 0) { fd = open(file, O_RDONLY); }`
- **Impact**: Privilege escalation if attacker swaps file between check and use
- **Mitigation**: Use `O_NOFOLLOW`, open file first then `fstat()`, use file descriptors (not paths)

### Data Races on Non-Atomic Variables
- **Concurrent read/write without synchronization**
  - Pattern: One thread writes `int counter`, another reads, no atomics or locks
- **Mitigation**: Use `std::atomic<>` in C++11+, `_Atomic` in C11, or locks

## Dangerous Functions (Ban List — Flag as Critical)

### Banned: Always Unsafe
- `gets()` — no bounds check, always buffer overflow
- `strcpy()`, `strcat()` — no bounds check (use `strncpy`, `strncat`, or `strlcpy`/`strlcat` where available)
- `sprintf()`, `vsprintf()` — no bounds check (use `snprintf`, `vsnprintf`)
- `scanf("%s", buf)` — no bounds check (use `scanf("%Ns", buf)` where N = sizeof(buf)-1)

### Banned: In Security Contexts
- `system()`, `popen()` — shell injection risk (use `fork` + `execve` instead)
- `mktemp()` — predictable temp files (use `mkstemp()`)
- `rand()`, `srand()` — not cryptographically secure (use `/dev/urandom`, `getrandom()`, or OpenSSL)

## Compiler Hardening Flags (Require in Build System)

### GCC/Clang
- `-Wall -Wextra -Werror` — Warnings as errors
- `-Wformat=2 -Wformat-security` — Format string checks
- `-D_FORTIFY_SOURCE=2` — Runtime buffer overflow checks
- `-fstack-protector-strong` — Stack canaries
- `-fPIE -pie` — Position-independent executable (ASLR)
- `-Wl,-z,relro,-z,now` — Full RELRO (GOT hardening)
- `-fsanitize=address` — AddressSanitizer (dev/CI)
- `-fsanitize=undefined` — UndefinedBehaviorSanitizer (dev/CI)
- `-fsanitize=thread` — ThreadSanitizer (dev/CI)

### MSVC
- `/GS` — Buffer security check
- `/guard:cf` — Control Flow Guard
- `/DYNAMICBASE /NXCOMPAT` — ASLR + DEP
