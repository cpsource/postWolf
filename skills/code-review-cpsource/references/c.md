# C Code Review Guide

> C code review guide focused on memory safety, undefined behavior, and portability. Examples assume C11.

## Table of Contents

- [Pointer and Buffer Safety](#pointer-and-buffer-safety)
- [Ownership and Resource Management](#ownership-and-resource-management)
- [Use-After-Free and Dangling Pointers](#use-after-free-and-dangling-pointers)
- [NULL Pointer Dereference](#null-pointer-dereference)
- [Off-by-One and Boundary Conditions](#off-by-one-and-boundary-conditions)
- [Double Free](#double-free)
- [Conditional Compilation Pitfalls](#conditional-compilation-pitfalls)
- [Cast Safety and Type Confusion](#cast-safety-and-type-confusion)
- [Format String Safety](#format-string-safety)
- [Undefined Behavior Pitfalls](#undefined-behavior-pitfalls)
- [Integer Types and Overflow](#integer-types-and-overflow)
- [Error Handling](#error-handling)
- [Concurrency](#concurrency)
- [Resource Management Beyond Memory](#resource-management-beyond-memory)
- [Security](#security)
- [Input Validation](#input-validation)
- [Macros and Preprocessor](#macros-and-preprocessor)
- [API Design and Const](#api-design-and-const)
- [Portability](#portability)
- [Performance](#performance)
- [Tooling and Build Checks](#tooling-and-build-checks)
- [Review Checklist](#review-checklist)

---

## Pointer and Buffer Safety

### Always carry size with buffers

```c
// ? Bad: ignores destination size
bool copy_name(char *dst, size_t dst_size, const char *src) {
    strcpy(dst, src);
    return true;
}

// ? Good: validate size and terminate
bool copy_name(char *dst, size_t dst_size, const char *src) {
    size_t len = strlen(src);
    if (len + 1 > dst_size) {
        return false;
    }
    memcpy(dst, src, len + 1);
    return true;
}
```

### Avoid dangerous APIs

Prefer `snprintf`, `fgets`, and explicit bounds over `gets`, `strcpy`, or `sprintf`.

```c
// ? Bad: unbounded write
sprintf(buf, "%s", input);

// ? Good: bounded write
snprintf(buf, buf_size, "%s", input);
```

### Use the right copy primitive

```c
// ? Bad: memcpy with overlapping regions
memcpy(dst, src, len);

// ? Good: memmove handles overlap
memmove(dst, src, len);
```

---

## Ownership and Resource Management

### One allocation, one free

Track ownership and clean up on every error path.

```c
// ? Good: cleanup label avoids leaks
int load_file(const char *path) {
    int rc = -1;
    FILE *f = NULL;
    char *buf = NULL;

    f = fopen(path, "rb");
    if (!f) {
        goto cleanup;
    }
    buf = malloc(4096);
    if (!buf) {
        goto cleanup;
    }

    if (fread(buf, 1, 4096, f) == 0) {
        goto cleanup;
    }

    rc = 0;

cleanup:
    free(buf);
    if (f) {
        fclose(f);
    }
    return rc;
}
```

---

## Use-After-Free and Dangling Pointers

Use-after-free is one of the most exploitable memory safety bugs in C/C++.
Review every `free`/`XFREE`/`delete` call and trace what happens to the pointer
afterward.

### Pattern 1: Obvious use after free

```c
// ? Bad: write through freed pointer
char *p = malloc(10);
free(p);
p[0] = 'a'; // UB — use after free
```

### Pattern 2: Free then read through a copy

```c
// ? Bad: alias still points to freed memory
char *original = malloc(64);
char *alias = original;
free(original);
printf("%s\n", alias); // UB — alias is dangling
```

### Pattern 3: Free inside a linked-list walk

```c
// ? Bad: node->next read after node is freed
while (node != NULL) {
    free(node);
    node = node->next; // UB — node already freed
}

// ? Good: save next before freeing
while (node != NULL) {
    struct node *next = node->next;
    free(node);
    node = next;
}
```

### Pattern 4: Conditional free with later use

```c
// ? Bad: p may be freed on error but used after the if block
if (error) {
    free(p);
}
/* ... more code ... */
use(p); // UB if error was true

// ? Good: set to NULL after free, or return/goto cleanup
if (error) {
    free(p);
    p = NULL;
}
```

### Pattern 5: XMEMCPY from a node then freeing the source

This is common in linked-list head-stability patterns (e.g., wolfSSL stacks):

```c
// Potential bug: tmp->next is read via the copy in stack, but tmp is freed
tmp = stack->next;
XMEMCPY(stack, tmp, sizeof(*stack));  // copies tmp's fields into stack
free_node(tmp);                        // frees tmp
// If XMEMCPY copied tmp's pointer fields, those pointers now point to
// valid memory — but verify that tmp itself is not accessed after this.
```

When reviewing this pattern, check:
- Is `tmp` accessed after the free? (bug)
- Do pointer fields copied from `tmp` still point to valid memory? (usually OK)
- Is the freed node's `heap` hint used for the wrong deallocation? (subtle bug)

### Pattern 6: Returning a pointer to stack/local memory

```c
// ? Bad: returns pointer to local buffer
char *get_name(void) {
    char buf[64];
    snprintf(buf, sizeof(buf), "hello");
    return buf; // dangling — buf is gone after return
}
```

### Pattern 7: Realloc invalidating the old pointer

```c
// ? Bad: if realloc fails, old pointer is leaked; if it succeeds, old is dangling
ptr = realloc(ptr, new_size);
// If realloc returns NULL, the original ptr is lost

// ? Good: use a temporary
void *tmp = realloc(ptr, new_size);
if (tmp == NULL) {
    free(ptr); // or handle error with original ptr still valid
    return -1;
}
ptr = tmp;
```

### What to look for during review

- Every `free`/`XFREE`/`delete`: trace all aliases of that pointer forward
- Every `goto cleanup` label: are any pointers used after their free in cleanup?
- Every `XMEMCPY` of a struct: does the source get freed? Are copied pointer
  fields still valid?
- Loops over linked lists: is `next` saved before `free`?
- Error paths: does early return or `goto` skip a NULL assignment?
- Return values: is the returned pointer to heap memory (OK) or stack (bug)?

---

## NULL Pointer Dereference

Dereferencing NULL is undefined behavior — usually a crash, sometimes
exploitable. Review every function that receives a pointer parameter and every
`malloc`/`calloc` return value.

### Pattern 1: Missing NULL check on function parameter

```c
// ? Bad: stack is dereferenced before NULL check
NODE* get_node(NODE* stack, int idx) {
    if (idx > (int)stack->num) {  // crashes if stack == NULL
        return NULL;
    }
    ...
}

// ? Good: NULL check first
NODE* get_node(NODE* stack, int idx) {
    if (stack == NULL || idx < 0 || idx >= (int)stack->num) {
        return NULL;
    }
    ...
}
```

### Pattern 2: Unchecked malloc/calloc

```c
// ? Bad: no NULL check after allocation
char *buf = malloc(size);
memset(buf, 0, size);  // crashes if malloc returned NULL

// ? Good: check before use
char *buf = malloc(size);
if (buf == NULL) {
    return -1;
}
memset(buf, 0, size);
```

### Pattern 3: NULL from one error path used in another

```c
// ? Bad: get_data may return NULL, then passed to strlen
char *data = get_data(input);
size_t len = strlen(data);  // crashes if data is NULL

// ? Good: check intermediate results
char *data = get_data(input);
if (data == NULL) {
    return -1;
}
size_t len = strlen(data);
```

### What to look for during review

- Every function: are pointer parameters checked for NULL before first use?
- Every malloc/calloc/realloc: is the return value checked?
- Every function that returns a pointer: do callers check for NULL?
- Chains of calls: `process(get_data(x))` — if `get_data` can return NULL,
  does `process` handle it, or does it dereference unconditionally?

---

## Off-by-One and Boundary Conditions

Off-by-one errors are among the most common C bugs — fencepost errors in loops,
`>` vs `>=` in bounds checks, and wrong buffer sizes.

### Pattern 1: Wrong comparison operator in bounds check

```c
// ? Bad: allows idx == num, which is one past the end
if (idx > num) {   // should be >=
    return NULL;
}
// walks idx steps — but valid range is [0, num-1]
for (i = 0; i < idx; i++) {
    node = node->next;
}

// ? Good: use >= for 0-based indexing
if (idx >= num) {
    return NULL;
}
```

### Pattern 2: Buffer size off by one

```c
// ? Bad: no room for null terminator
char buf[strlen(src)];
strcpy(buf, src);  // writes one byte past buf

// ? Good: +1 for the terminator
char buf[strlen(src) + 1];
strcpy(buf, src);
```

### Pattern 3: Loop runs one too many or one too few times

```c
// ? Bad: reads arr[n] which is out of bounds
for (i = 0; i <= n; i++) {
    sum += arr[i];
}

// ? Good: strict less-than
for (i = 0; i < n; i++) {
    sum += arr[i];
}
```

### Pattern 4: Fence-post in linked list length vs index

Many linked-list implementations store a `num`/`count` field. When iterating
by index, verify:
- Is `num` 0-based or 1-based?
- Does `num` count elements, or nodes (which may differ if the first node is
  a sentinel)?
- Is the check `idx > num`, `idx >= num`, or `idx > num - 1`?

### What to look for during review

- Every `>` or `<` in a bounds check: should it be `>=` or `<=`?
- Every buffer allocation: does it account for null terminators, headers, or
  padding?
- Every loop: does it iterate exactly N times for N elements?
- Every `num`/`count`/`size` field: is it 0-based or 1-based, and is the
  comparison consistent with that convention?

---

## Double Free

Double free corrupts the allocator's metadata and is exploitable. It often
occurs in error-handling paths where cleanup runs more than once.

### Pattern 1: Goto cleanup without NULLing

```c
// ? Bad: if both fread and fwrite fail, buf is freed twice
buf = malloc(4096);
if (fread(buf, 1, 4096, f) == 0) {
    free(buf);
    goto cleanup;
}
if (fwrite(buf, 1, 4096, out) == 0) {
    goto cleanup;
}
cleanup:
    free(buf);  // double free if first error path was taken
    return -1;

// ? Good: set to NULL after free, or only free in cleanup
buf = malloc(4096);
if (fread(buf, 1, 4096, f) == 0) {
    goto cleanup;  // let cleanup handle the free
}
if (fwrite(buf, 1, 4096, out) == 0) {
    goto cleanup;
}
rc = 0;
cleanup:
    free(buf);  // safe — only freed once
    return rc;
```

### Pattern 2: Free in a called function, then free in caller

```c
// ? Bad: destroy_session frees sess->data, caller also frees it
destroy_session(sess);
free(sess->data);  // double free

// ? Good: clear documentation of who owns what, or NULL after free
```

### Pattern 3: Error path frees, success path frees again

```c
// ? Bad: both branches free buf
if (err) {
    free(buf);
    // falls through...
}
free(buf); // double free when err is true
```

### Pattern 4: Retry loops that don't NULL after close/free

Common in code that retries transient failures (EINTR, EAGAIN, network
reset). A shared `goto cleanup` → `goto try_again` structure closes a
handle in cleanup but does not NULL it. On the next iteration the setup
code runs again, but the cleanup-side `if (handle)` guard is still true
from the prior round if the reopen fails and control reaches cleanup
again — double-close or UAF via stale handle.

```c
// ? Bad: nlg is closed but not NULLed; try_again reuses the stale value
static int do_netlink_op(void)
{
    struct mnlg_socket *nlg;
    int ret;

try_again:
    ret = 0;
    nlg = mnlg_socket_open(...);
    if (!nlg)
        return -errno;

    if (mnlg_socket_send(nlg, ...) < 0) {
        ret = -errno;
        goto out;
    }

out:
    if (nlg)
        mnlg_socket_close(nlg);      // nlg closed but still non-NULL
    if (ret == -EINTR)
        goto try_again;               // loops back; nlg is now a dangling
    if (ret) {                        // pointer but the `if (nlg)` check
        ...                           // above would pass on a second out:
    }
    return ret;
}

// ? Good: NULL the handle immediately after close
out:
    if (nlg) {
        mnlg_socket_close(nlg);
        nlg = NULL;
    }
    if (ret == -EINTR)
        goto try_again;
    ...
```

The stale-pointer risk is subtle: in the *straightforward* `try_again`
flow (open → send fails → cleanup → retry), the stale `nlg` gets
overwritten by the next `mnlg_socket_open()`. The bug shows up on the
path where the retry's `mnlg_socket_open()` itself fails — now the
stale pointer survives, and if any later path revisits `out:` (or an
enclosing cleanup block that also checks `nlg`), we call
`mnlg_socket_close` on a freed pointer.

Real-world example: [wolfSSL/wolfGuard PR
#20](https://github.com/wolfSSL/wolfGuard/pull/20) fixed exactly this
in `kernel_generate_privkey`, `kernel_derive_pubkey`, and
`kernel_generate_psk`.

### What to look for during review

- Every `goto cleanup`: does the cleanup section free something that was
  already freed before the goto?
- Every function that frees memory: do callers also try to free the same
  memory?
- After freeing: is the pointer set to NULL? (`free(p); p = NULL;`)
- `free(NULL)` is safe in C — NULLing after free prevents double-free bugs.
- **Every `goto retry`/`goto try_again` across a cleanup block**: after
  each `close` / `free` / `destroy`, is the handle NULLed so the next
  iteration's cleanup doesn't touch stale memory? This check is easy
  to miss because the common code path happens to work — the bug is on
  the secondary-failure arm.

---

## Conditional Compilation Pitfalls

Heavily `#ifdef`'d code (common in embedded C libraries like wolfSSL, OpenSSL,
mbedTLS) creates multiple "programs" in one file. Bugs can hide in specific
configurations.

### Pattern 1: Implicit switch fallthrough controlled by #ifdef

```c
// When FEATURE_X is defined, case A falls through to case B.
// When FEATURE_X is not defined, case A breaks normally.
// This may be intentional or a bug — verify with tests.
case TYPE_A:
    #ifndef FEATURE_X
        val = NULL;
        break;
    #endif
case TYPE_B:
    val = node->data.generic;
    break;
```

### Pattern 2: Variable declared only in one config

```c
#ifdef USE_ALLOC
    char *buf = malloc(sz);
#endif
    /* ... */
#ifdef USE_ALLOC
    free(buf);
#endif
    return buf;  // may be undeclared if USE_ALLOC is not defined
```

### Pattern 3: Different struct layout per config

```c
struct Conn {
    int fd;
#ifdef USE_TLS
    SSL *ssl;
#endif
    char *buf;
};
// sizeof(Conn) differs — memcpy/memset of sizeof(Conn) from a differently-
// compiled translation unit is UB
```

### Pattern 4: Dead code that silently compiles away

```c
void handle(int type) {
    switch (type) {
#ifdef FEATURE_FOO
        case TYPE_FOO:
            do_foo();
            break;
#endif
        default:
            // TYPE_FOO silently falls to default when FEATURE_FOO is off.
            // Is that intended or a missed case?
            break;
    }
}
```

### What to look for during review

- Every `#ifdef` inside a `switch`: does it create unintentional fallthrough?
- Every `#ifdef` around a variable: is that variable used outside the `#ifdef`?
- Every struct with `#ifdef` members: is `sizeof` used consistently across
  translation units?
- `#endif` comments: do they match the actual `#if`/`#ifdef`? (We found a wrong
  `#endif /* OPENSSL_ALL */` that should have been `OPENSSL_EXTRA`.)
- Think about what the code does in both the defined and undefined config. If
  you only read one path, you miss half the bugs.

---

## Cast Safety and Type Confusion

Wrong casts are a source of subtle corruption and undefined behavior in C.

### Pattern 1: Wrong sizeof in allocation

```c
// ? Bad: allocates wrong size
struct Node *p = malloc(sizeof(struct List));  // should be sizeof(struct Node)

// ? Good: use the variable, not the type
struct Node *p = malloc(sizeof(*p));
```

### Pattern 2: Casting away const then writing

```c
// ? Bad: modifying data through cast-away const is UB if original is const
void modify(const char *s) {
    char *p = (char *)s;
    p[0] = 'X';  // UB if s points to a string literal or const data
}
```

### Pattern 3: Pointer type mismatch

```c
// ? Bad: breaks strict aliasing
float f = 3.14f;
int i = *(int *)&f;  // UB — strict aliasing violation

// ? Good: use memcpy for type punning
int i;
memcpy(&i, &f, sizeof(i));
```

### Pattern 4: Signed/unsigned cast hiding a negative value

```c
// ? Bad: -1 cast to size_t becomes a huge number
int len = get_length();  // may return -1 on error
memcpy(dst, src, (size_t)len);  // if len == -1, copies ~4GB

// ? Good: check before cast
if (len < 0) return -1;
memcpy(dst, src, (size_t)len);
```

### What to look for during review

- Every `malloc`/`calloc`: does `sizeof` match the target type? Prefer
  `sizeof(*ptr)` over `sizeof(TypeName)`.
- Every cast from `const` to non-const: is the underlying data actually
  mutable?
- Every cast between pointer types: does it violate strict aliasing?
- Every cast from signed to unsigned: was the signed value validated first?

---

## Format String Safety

Uncontrolled format strings are a classic C vulnerability — they can crash the
program, leak stack data, or even allow arbitrary writes.

### Pattern 1: User input as format string

```c
// ? Bad: if user_msg contains %s, %n, etc., it's exploitable
printf(user_msg);
syslog(LOG_ERR, user_msg);

// ? Good: always use a format specifier
printf("%s", user_msg);
syslog(LOG_ERR, "%s", user_msg);
```

### Pattern 2: Format/argument mismatch

```c
// ? Bad: %d expects int, but argument is size_t (may be 64-bit)
printf("size: %d\n", sizeof(buf));

// ? Good: use correct format specifier
printf("size: %zu\n", sizeof(buf));
```

### Pattern 3: Missing arguments

```c
// ? Bad: two format specifiers but one argument — reads garbage from stack
printf("name=%s age=%d\n", name);
```

### What to look for during review

- Every `printf`/`sprintf`/`snprintf`/`syslog`/`fprintf`: is the first
  (non-file) argument a string literal, or could it be attacker-controlled?
- Format specifiers vs arguments: do types and counts match?
- `%n` in any format string: this is almost never legitimate in application
  code.
- Functions that forward `...` (variadic): are format strings validated?

---

## Undefined Behavior Pitfalls

### Common UB patterns

```c
// ? Bad: uninitialized read
int x;
if (x > 0) { /* UB */ }

// ? Bad: signed overflow
int sum = a + b;
```

### Avoid pointer arithmetic past the object

```c
// ? Bad: pointer past the end then dereference
int arr[4];
int *p = arr + 4;
int v = *p; // UB
```

---

## Integer Types and Overflow

### Avoid signed/unsigned surprises

```c
// ? Bad: negative converted to large size_t
int len = -1;
size_t n = len;

// ? Good: validate before converting
if (len < 0) {
    return -1;
}
size_t n = (size_t)len;
```

### Check for overflow in size calculations

```c
// ? Bad: potential overflow in multiplication
size_t bytes = count * sizeof(Item);

// ? Good: check before multiplying
if (count > SIZE_MAX / sizeof(Item)) {
    return NULL;
}
size_t bytes = count * sizeof(Item);
```

---

## Error Handling

### Always check return values

```c
// ? Bad: ignore errors
fread(buf, 1, size, f);

// ? Good: handle errors
size_t read = fread(buf, 1, size, f);
if (read != size && ferror(f)) {
    return -1;
}
```

### Consistent error contracts

- Use a clear convention: 0 for success, negative for failure.
- Document ownership rules on success and failure.
- If using `errno`, set it only for actual failures.

---

## Concurrency

### volatile is not synchronization

```c
// ? Bad: data race
volatile int stop = 0;
void worker(void) {
    while (!stop) { /* ... */ }
}

// ? Good: C11 atomics
_Atomic int stop = 0;
void worker(void) {
    while (!atomic_load(&stop)) { /* ... */ }
}
```

### Use mutexes for shared state

Protect shared data with `pthread_mutex_t` or equivalent. Avoid holding locks while doing I/O.

---

## Resource Management Beyond Memory

Files, sockets, mutexes, and mapped regions must be released on every path.

### Pattern: File handle leak on error

```c
// ? Bad: f is leaked if malloc fails
FILE *f = fopen(path, "rb");
char *buf = malloc(4096);
if (!buf) {
    return -1;  // f is leaked
}

// ? Good: cleanup on every exit
FILE *f = fopen(path, "rb");
if (!f) return -1;
char *buf = malloc(4096);
if (!buf) {
    fclose(f);
    return -1;
}
```

### Pattern: Mutex not released on error

```c
// ? Bad: lock held if process() fails
pthread_mutex_lock(&mu);
if (process(data) < 0) {
    return -1;  // lock held forever
}
pthread_mutex_unlock(&mu);

// ? Good: always unlock
pthread_mutex_lock(&mu);
int rc = process(data);
pthread_mutex_unlock(&mu);
return rc;
```

### What to look for

- Every `fopen`/`open`/`socket`/`mmap`/`lock`: is there a matching close/unmap/
  unlock on every path?
- `goto cleanup` patterns: does cleanup close all acquired resources?
- Are cleanup routines idempotent? (`fclose(NULL)` is UB, `free(NULL)` is safe)
- Early returns: do they skip resource release?

---

## Security

### Format string injection

See [Format String Safety](#format-string-safety) above.

### Path traversal

```c
// ? Bad: user controls filename — can escape directory
snprintf(path, sizeof(path), "/data/%s", user_input);
// user_input = "../../etc/passwd" -> reads /etc/passwd

// ? Good: reject path separators, or use basename()
if (strchr(user_input, '/') || strchr(user_input, '\\')) {
    return -1;
}
```

### Secrets in memory

```c
// ? Bad: password left in memory after use
char password[64];
get_password(password);
authenticate(password);
// password still readable in memory, core dumps, swap

// ? Good: zero before leaving scope
authenticate(password);
explicit_bzero(password, sizeof(password));
```

### Unbounded allocation (DoS)

```c
// ? Bad: attacker controls count — can exhaust memory
uint32_t count = read_uint32(input);
Item *items = malloc(count * sizeof(Item));

// ? Good: cap to a sane maximum
if (count > MAX_ITEMS) return -1;
Item *items = malloc(count * sizeof(Item));
```

### What to look for

- Any user/network input used in: format strings, file paths, shell commands,
  SQL, allocation sizes, loop bounds
- Secrets (keys, passwords, tokens): are they zeroed after use?
- Randomness: `rand()` is not cryptographic — use platform CSPRNG
- Crypto: no homegrown algorithms, no hardcoded keys, no ECB mode

---

## Input Validation

### Pattern: Unvalidated function arguments

```c
// ? Bad: no validation — crashes on NULL or negative size
int parse(const char *buf, int size) {
    for (int i = 0; i < size; i++) {
        process(buf[i]);
    }
}

// ? Good: validate at trust boundary
int parse(const char *buf, int size) {
    if (buf == NULL || size < 0) return -1;
    for (int i = 0; i < size; i++) {
        process(buf[i]);
    }
    return 0;
}
```

### Where to validate

- **Trust boundaries**: functions that accept external/user input MUST validate.
- **Internal functions**: lightweight asserts in debug builds; documented
  preconditions in release.
- **Never validate twice**: pick one layer and be consistent.

---

## Macros and Preprocessor

### Parenthesize arguments

```c
// ? Bad: macro with side effects
#define MIN(a, b) ((a) < (b) ? (a) : (b))
int x = MIN(i++, j++);

// ? Good: static inline function
static inline int min_int(int a, int b) {
    return a < b ? a : b;
}
```

### Flexible array members

```c
// ? Bad: sizeof(Packet) does not include the flexible member
struct Packet {
    uint32_t len;
    uint8_t data[];
};
struct Packet *p = malloc(sizeof(struct Packet));  // no room for data

// ? Good: allocate header + payload
struct Packet *p = malloc(sizeof(struct Packet) + payload_len);
```

### Variadic functions

```c
// ? Bad: no way to know argument count — reads garbage
void log_values(const char *fmt, ...) {
    // if caller passes wrong number of args, UB
}
```

Variadic functions cannot validate argument count or types. Prefer typed
alternatives (arrays, structs) where possible.

### Struct initialization

```c
// ? Bad: partial initialization — remaining fields are garbage
struct Config cfg;
cfg.timeout = 30;
// cfg.retries, cfg.flags are uninitialized

// ? Good: zero-initialize then set
struct Config cfg = {0};
cfg.timeout = 30;
```

---

## API Design and Const

### Const-correctness and sizes

```c
// ? Good: explicit size and const input
int hash_bytes(const uint8_t *data, size_t len, uint8_t *out);
```

### Document nullability

Clearly document whether pointers may be NULL. Prefer returning error codes
instead of NULL when possible.

### Minimize interface surface

- Prefer opaque types with accessor functions over exposed structs
- Separate input parameters from output parameters
- Avoid hidden side effects — if a function modifies global state, document it

---

## Portability

### Integer sizes

```c
// ? Bad: assumes int is 32 bits
int flags = 0x80000000;  // implementation-defined if int is 16 bits

// ? Good: use fixed-width types
uint32_t flags = 0x80000000U;
```

### Endianness

```c
// ? Bad: assumes little-endian
uint32_t val = *(uint32_t *)buf;  // also a strict aliasing violation

// ? Good: portable byte-order read
uint32_t val = ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16)
             | ((uint32_t)buf[2] << 8)  | (uint32_t)buf[3];
```

### Struct packing

```c
// ? Bad: assumes no padding between fields
struct Header {
    uint8_t type;
    uint32_t length;
};
// sizeof(Header) may be 5 or 8 depending on alignment

// ? Good: read fields individually, or use compiler-specific packing
// with documented portability constraints
```

### What to look for

- `sizeof(int)`, `sizeof(long)`, `sizeof(void*)` — are these assumed?
- Byte-order assumptions in network/file format code
- Path separators: `/` vs `\\`
- `#pragma pack` or `__attribute__((packed))` — documented and tested?
- Compiler extensions: `typeof`, `__builtin_*`, `__attribute__` — behind
  portability macros?

---

## Performance

### Accidental quadratic behavior

```c
// ? Bad: O(n^2) — strlen called on every iteration
for (int i = 0; i < strlen(s); i++) {
    process(s[i]);
}

// ? Good: compute length once
size_t len = strlen(s);
for (size_t i = 0; i < len; i++) {
    process(s[i]);
}
```

### Unnecessary allocation in loops

```c
// ? Bad: malloc/free on every iteration
for (int i = 0; i < n; i++) {
    char *buf = malloc(4096);
    process(buf);
    free(buf);
}

// ? Good: allocate once outside the loop
char *buf = malloc(4096);
for (int i = 0; i < n; i++) {
    process(buf);
}
free(buf);
```

---

## Tooling and Build Checks

```bash
# Warnings
clang -Wall -Wextra -Werror -Wconversion -Wshadow -std=c11 ...

# Sanitizers (debug builds)
clang -fsanitize=address,undefined -fno-omit-frame-pointer -g ...
clang -fsanitize=thread -fno-omit-frame-pointer -g ...

# Static analysis
clang-tidy src/*.c -- -std=c11
cppcheck --enable=warning,performance,portability src/

# Formatting
clang-format -i src/*.c include/*.h
```

---

## Review Checklist

### Memory and UB
- [ ] All buffers have explicit size parameters
- [ ] No out-of-bounds access or pointer arithmetic past objects
- [ ] No use-after-free: every `free`/`XFREE` traced forward for dangling access
- [ ] No dangling aliases: all copies of a freed pointer are also NULLed or unused
- [ ] Linked-list walks save `next` before freeing the current node
- [ ] `XMEMCPY` of structs: source not accessed after free, copied pointers valid
- [ ] `realloc` uses a temp pointer to avoid leaking on failure
- [ ] No returning pointers to stack-local buffers
- [ ] No uninitialized reads
- [ ] Signed overflow and shift rules are respected

### NULL Pointer Dereference
- [ ] Every function checks pointer parameters for NULL before first dereference
- [ ] Every `malloc`/`calloc`/`realloc` return is checked before use
- [ ] Functions that return pointers: callers check for NULL
- [ ] No unchecked chains like `process(get_data(x))` where `get_data` can return NULL

### Off-by-One and Boundaries
- [ ] Bounds checks use correct operator (`>=` vs `>` for 0-based indices)
- [ ] Buffer allocations include space for null terminators
- [ ] Loops iterate exactly N times for N elements (not N+1 or N-1)
- [ ] `num`/`count`/`size` fields: 0-based vs 1-based convention is consistent

### Double Free
- [ ] `goto cleanup` paths don't free memory already freed before the jump
- [ ] Functions that free memory: callers don't also free the same memory
- [ ] Pointers NULLed after free in error paths (`free(p); p = NULL;`)

### Conditional Compilation
- [ ] `#ifdef` inside `switch` doesn't create unintentional fallthrough
- [ ] Variables declared inside `#ifdef` aren't used outside it
- [ ] `#endif` comments match the corresponding `#if`/`#ifdef`
- [ ] Code reviewed under both defined and undefined configurations
- [ ] Structs with `#ifdef` members: `sizeof` used consistently across TUs

### Cast Safety
- [ ] `malloc`/`calloc` use `sizeof(*ptr)` not `sizeof(TypeName)`
- [ ] No casting away `const` and then writing through the result
- [ ] No strict aliasing violations via pointer casts
- [ ] Signed-to-unsigned casts validated (no negative values slipping through)

### Format Strings
- [ ] No user/external input used as a format string directly
- [ ] Format specifiers match argument types (`%zu` for `size_t`, etc.)
- [ ] Argument count matches format specifier count

### Resource Management
- [ ] Files, sockets, mutexes, handles all released on every path
- [ ] `goto cleanup` closes all acquired resources
- [ ] Cleanup routines are idempotent (`fclose(NULL)` is UB — guard it)
- [ ] Early returns don't skip resource release

### Security
- [ ] No user input in format strings, shell commands, file paths, or SQL
- [ ] Path traversal blocked (reject `..` and path separators in user input)
- [ ] Secrets zeroed after use (`explicit_bzero` or `memset_s`)
- [ ] No `rand()` for security — use platform CSPRNG
- [ ] Allocation sizes capped to prevent DoS

### Input Validation
- [ ] Functions at trust boundaries validate all pointer and size arguments
- [ ] Sizes, lengths, counts, and indexes sanity-checked before use
- [ ] Malformed input rejected cleanly, not silently accepted

### API and Design
- [ ] Ownership rules are documented and consistent
- [ ] const-correctness is applied for inputs
- [ ] Error contracts are clear and consistent
- [ ] Interface minimal and hard to misuse
- [ ] No hidden side effects

### Concurrency
- [ ] No data races on shared state
- [ ] volatile is not used for synchronization
- [ ] Locks are held for minimal time
- [ ] Lock acquisition order consistent (no deadlock)
- [ ] No check-then-act races
- [ ] Condition variables re-check predicates in a loop
- [ ] Signal handlers only use async-signal-safe functions

### Portability
- [ ] No assumptions about `sizeof(int)`, `sizeof(long)`, or `sizeof(void*)`
- [ ] Fixed-width types (`uint32_t`, etc.) used where size matters
- [ ] No endianness assumptions in network/file format code
- [ ] No reliance on struct packing without explicit attributes
- [ ] Compiler extensions behind portability macros

### Performance
- [ ] No accidental quadratic behavior (e.g., `strlen` in loop condition)
- [ ] No unnecessary allocation inside loops
- [ ] Data structures appropriate for expected sizes

### Verification Before Reporting

C code frequently uses idioms that look wrong in isolation but are correct in
context. Before flagging a finding as a bug:

- [ ] **Check callers**: `grep -rn "funcName(" src/` — how is the function
  actually called? A parameter that looks dangerous may never receive the
  problematic value in practice.
- [ ] **Check the test suite**: `grep -rn "funcName" tests/` — do tests assert
  the behavior you think is wrong? If a test passes a sentinel value like `-1`
  and expects a specific result, the code is likely correct.
- [ ] **Trace with concrete values**: For loop bounds, pointer arithmetic, and
  signed/unsigned comparisons, pick specific inputs and walk through the code
  line by line. Write down intermediate variable states.
- [ ] **Watch for intentional C idioms**:
  - Sentinel values (`-1`, `0`, `NULL`) used as "walk to end" or "use default"
  - `XMEMCPY` followed by field fixups (common in linked-list head-stability
    patterns)
  - Unsigned wrap-around used intentionally (e.g., `--idx != 0` with negative
    `idx` to always walk the full list)
  - Switch fallthrough controlled by `#ifdef` (may be intentional per-config)
- [ ] **Tests are ground truth, not doc comments**: If a doc comment says
  "removes the first element" but the test suite asserts LIFO tail-removal,
  trust the tests. Flag the doc comment as misleading, not the code as buggy.
- [ ] **Label unverified findings**: If you cannot find tests or callers to
  confirm, mark the finding as `[unverified]` rather than asserting it is a bug.

### Tooling and Tests
- [ ] Builds clean with warnings enabled
- [ ] Sanitizers run on critical code paths
- [ ] Static analysis results are addressed
