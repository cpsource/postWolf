Here’s a clean, ready-to-use **`DOCUMENTATION_STANDARD.md`** you can drop into your repo.

---

# 📄 DOCUMENTATION_STANDARD.md

## Purpose

This document defines the required documentation standards for all C source code in this project.

The goal is to ensure that code is:

* understandable
* maintainable
* safe to modify
* consistent across developers

> **Rule #1:** Comments must explain *why* and *what*, not just restate the code.

---

# 1. General Principles

* Prefer **clear naming** over excessive comments
* Write comments in **complete, concise sentences**
* Keep comments **accurate and up to date**
* Do not describe obvious behavior
* Document **intent, assumptions, and constraints**

### ❌ Bad

```c
i++;  /* increment i */
```

### ✅ Good

```c
/* Skip index 0 because it is reserved for the root node. */
i++;
```

---

# 2. File Header (Required)

Every `.c` and `.h` file must begin with a header block:

```c
/******************************************************************************
 * File:        filename.c
 * Purpose:     One-line description of the file
 *
 * Description:
 *   Detailed explanation of what this module does.
 *
 * Dependencies:
 *   header1.h
 *   header2.h
 *
 * Notes:
 *   - Thread safety
 *   - Ownership rules
 *   - Limitations
 *
 * Author:      Name
 * Created:     YYYY-MM-DD
 ******************************************************************************/
```

---

# 3. Function Documentation (Required)

Every public function and all non-trivial static functions must have a comment block.

```c
/******************************************************************************
 * Function:    function_name
 *
 * Description:
 *   What the function does and why it exists.
 *
 * Input Arguments:
 *   arg1       - Description
 *   arg2       - Description
 *
 * Returns:
 *   Exact meaning of return value(s).
 *
 * Errors:
 *   Error conditions and behavior.
 *
 * Side Effects:
 *   Any state changes, allocations, I/O, logging, etc.
 *
 * Notes:
 *   Assumptions, ownership rules, thread safety, or caveats.
 ******************************************************************************/
```

## Minimum required sections

* Function
* Description
* Input Arguments
* Returns

---

# 4. Argument Documentation

For each parameter, document:

* purpose
* valid range or format
* whether NULL is allowed
* ownership (if pointer)

### Example

```c
 * Input Arguments:
 *   buffer     - Output buffer (must not be NULL)
 *   size       - Size of buffer in bytes (> 0)
 *   path       - File path string
```

---

# 5. Return Values

Be explicit and precise.

### ❌ Bad

```c
Returns success or failure
```

### ✅ Good

```c
Returns:
  0  on success
 -1  if file cannot be opened
 -2  if buffer is too small
```

---

# 6. Inline Comments

Use inline comments **only when necessary**.

### Use them for:

* non-obvious logic
* tricky math or pointer operations
* protocol rules
* security checks
* workarounds

### ❌ Avoid:

* restating code
* obvious operations

---

# 7. Branches (if/else)

Do **not** comment every branch.

Comment only when:

* the condition is not obvious
* enforcing a rule or invariant
* preventing an error (e.g., divide-by-zero)
* handling a special case

### Example

```c
if (count == 0)
{
    /* Prevent division by zero; empty set is invalid input */
    return ERR_INVALID;
}
```

---

# 8. Switch Statements

Document switches when they represent:

* protocol handling
* command dispatch
* state machines

### Example

```c
/*
 * Dispatch based on message type from client.
 * Unknown types are rejected.
 */
switch (msg->type)
```

Comment individual cases only if needed.

---

# 9. Loops

Document loops when:

* iteration logic is non-obvious
* order matters
* elements are skipped
* mutation occurs during iteration

### Example

```c
/* Iterate backwards so entries can be removed safely */
for (i = count - 1; i >= 0; i--)
```

---

# 10. Magic Numbers

Avoid unexplained constants.

### ❌ Bad

```c
if (retry_count > 7)
```

### ✅ Good

```c
#define MAX_RETRIES 7
if (retry_count > MAX_RETRIES)
```

---

# 11. Struct Documentation

Document struct fields when meaning is not obvious.

```c
typedef struct
{
    int socket_fd;      /* -1 if closed */
    size_t length;      /* Buffer length in bytes */
    char *buffer;       /* Caller-owned memory */
} Connection;
```

---

# 12. Enums

Document enums, especially for state machines.

```c
typedef enum
{
    STATE_INIT,     /* Initial state */
    STATE_ACTIVE,   /* Normal operation */
    STATE_DONE      /* Completed */
} State;
```

---

# 13. Ownership Rules (Required)

Always document memory ownership.

Examples:

```c
Returns:
  Newly allocated buffer (caller must free)
```

```c
Notes:
  Returned pointer is owned by the cache and must not be freed
```

---

# 14. Thread Safety (Required if applicable)

Document:

* thread-safe or not
* required locks

Example:

```c
 * Thread Safety:
 *   Caller must hold mutex before calling
```

---

# 15. Error Handling

Document all meaningful failure modes.

* return codes
* errno usage
* fatal vs recoverable errors

---

# 16. When Comments Are REQUIRED

* every file
* every public function
* non-trivial static functions
* complex logic
* ownership rules
* non-obvious algorithms
* security-sensitive code

---

# 17. When Comments Are NOT Needed

Avoid comments that:

* restate code
* describe trivial operations
* are outdated or misleading

---

# 18. Naming Comes First

Good naming reduces need for comments.

### ❌ Bad

```c
int f(int a, int b);
```

### ✅ Good

```c
int validate_user_age(int age, int minimum_age);
```

---

# 19. Summary Rules

* Explain **why**, not just **what**
* Be precise about inputs and outputs
* Document ownership and side effects
* Comment complex logic, not simple code
* Keep comments accurate

---

# 🔚 Final Rule

> If another developer cannot safely modify your code in 6 months, the documentation is insufficient.

---

If you want, I can next:

* turn this into a **lint/checklist for code reviews**
* or add a **Doxygen-compatible version** so you can auto-generate docs

