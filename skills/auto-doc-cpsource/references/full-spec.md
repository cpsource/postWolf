A good C documentation spec for junior programmers should be **simple, mandatory, and enforceable**. If it gets too fancy, people will ignore it. I would make it cover four levels:

1. file header
2. function header
3. inline comments
4. special rules for complex logic

Here’s a practical spec you can hand them.

---

# C Documentation Specification

## 1. General principles

Documentation should explain:

* **what** the code does
* **why** it exists
* **assumptions and constraints**
* anything that is **not obvious from reading the code**

Documentation should **not** merely repeat the code in English.

Bad:

```c
i++;   /* increment i */
```

Good:

```c
/* Skip index 0 because it is reserved for the root node. */
i++;
```

Rule of thumb:

> Comment the intent, not the syntax.

---

## 2. File header

Every `.c` and `.h` file should begin with a file comment block.

Example:

```c
/******************************************************************************
 * File:        user_lookup.c
 * Purpose:     Implements lookup and validation of user records.
 *
 * Description:
 *   This module provides helper functions for loading, validating,
 *   and searching user records from the on-disk database.
 *
 * Dependencies:
 *   user_lookup.h
 *   database.h
 *
 * Notes:
 *   - This module is not thread-safe.
 *   - Caller owns memory returned by load_user_record().
 *
 * Author:      Jane Smith
 * Created:     2026-04-13
 ******************************************************************************/
```

Minimum required sections:

* File
* Purpose
* Description
* Dependencies
* Notes
* Author
* Created

Optional:

* Revision history
* Thread safety
* Ownership rules

---

## 3. Function header comments

Every non-trivial function should have a comment block immediately above it.

Functions that are `static` and extremely obvious may use a shorter form, but juniors should generally document all functions.

Recommended format:

```c
/******************************************************************************
 * Function:    find_user_by_id
 *
 * Description:
 *   Searches the in-memory user table for the specified user ID and returns
 *   a pointer to the matching record if found.
 *
 * Input Arguments:
 *   table      - Pointer to initialized user table.
 *   user_id    - Null-terminated string containing the target user ID.
 *
 * Returns:
 *   Pointer to matching UserRecord on success.
 *   NULL if no match is found or input is invalid.
 *
 * Errors:
 *   None.
 *
 * Side Effects:
 *   None.
 *
 * Notes:
 *   The returned pointer refers to internal storage and must not be freed
 *   by the caller.
 ******************************************************************************/
UserRecord *find_user_by_id(UserTable *table, const char *user_id)
```

## Required sections

For most functions, require these:

* Function
* Description
* Input Arguments
* Returns

## Strongly recommended sections

Use when applicable:

* Errors
* Side Effects
* Notes
* Preconditions
* Postconditions
* Thread Safety

---

## 4. What should go in each section

### Function

The exact function name.

### Description

One short paragraph describing:

* purpose
* major behavior
* important rules

### Input Arguments

For each parameter:

* meaning
* valid range or format
* ownership if pointer
* whether NULL is allowed

Example:

```c
 * Input Arguments:
 *   buffer     - Output buffer supplied by caller.
 *   size       - Size of output buffer in bytes. Must be greater than 0.
 *   path       - Path to file. Must not be NULL.
```

### Returns

Be precise.
Do not say just “returns success or failure.”

Better:

```c
 * Returns:
 *   0 on success.
 *  -1 if the file could not be opened.
 *  -2 if the buffer is too small.
```

### Errors

Document:

* errno use
* log messages
* fatal behavior
* assertions

### Side Effects

Document:

* modifies global state
* allocates memory
* writes files
* locks mutexes
* changes hardware/network state

### Notes

Document:

* assumptions
* caveats
* special ownership rules
* why design is unusual

---

## 5. When inline comments should be used

Use inline comments when the code’s purpose is not obvious from the surrounding structure.

Good uses:

* unusual arithmetic
* non-obvious pointer manipulation
* workaround for bug or protocol quirk
* tricky state machine transitions
* magic constants
* security-sensitive checks

Example:

```c
/* Reserve one extra byte for the protocol terminator. */
msg_len = payload_len + 1;
```

Do not use inline comments for obvious code:

```c
x = y + 1;   /* add 1 to y */
```

A good rule:

> If a competent programmer would ask “why is this done this way?”, add a comment.

---

## 6. Branches and if/else blocks

You do **not** need to document every `if`.

But you **should** document a branch when:

* the reason for the condition is not obvious
* one branch handles a special case
* the branch enforces a business rule or security rule
* the branch exists due to a bug workaround
* the condition protects against undefined behavior

Example:

```c
if (count == 0)
{
    /* Avoid division by zero. An empty sample set is treated as invalid. */
    return ERR_INVALID_SAMPLE;
}
```

For long or nested branches, consider a block comment before the logic:

```c
/*
 * Three cases are handled here:
 * 1. Existing user with valid session
 * 2. Existing user with expired session
 * 3. New user requiring initialization
 */
```

---

## 7. Switch statements

Yes, switch statements should often be documented, especially if they represent:

* protocol opcodes
* parser states
* command dispatch
* error classifications
* state machines

Add a short block comment above the switch explaining what is being dispatched.

Example:

```c
/*
 * Dispatch based on message type received from the client.
 * Unknown types are rejected for forward-compatibility safety.
 */
switch (msg->type)
{
    case MSG_LOGIN:
        ...
        break;

    case MSG_LOGOUT:
        ...
        break;

    default:
        ...
        break;
}
```

For each `case`, comment only if the action is not obvious.

---

## 8. Loops

Document loops when:

* termination conditions are subtle
* indexes have special meaning
* the loop skips reserved entries
* order matters
* mutation during iteration is risky

Example:

```c
/* Walk backward so entries can be safely removed in place. */
for (i = count - 1; i >= 0; i--)
```

---

## 9. Magic numbers

Any constant whose meaning is not obvious should be named or commented.

Bad:

```c
if (retry_count > 7)
```

Better:

```c
#define MAX_AUTH_RETRIES 7
if (retry_count > MAX_AUTH_RETRIES)
```

If a number must remain literal, explain it:

```c
/* 17 bytes = 16-byte UUID plus 1-byte message type. */
```

---

## 10. Header files

Every public function in a `.h` file should have documentation in the header, because that is the interface contract.

Implementation-only details belong in the `.c` file.

For public APIs, document:

* purpose
* arguments
* return values
* ownership
* thread safety
* error handling

---

## 11. When comments are required

Require comments for:

* every file
* every public function
* every non-trivial static function
* every data structure with non-obvious fields
* every macro with non-obvious behavior
* any tricky branch, loop, or switch
* any workaround, hack, or protocol rule
* all ownership and lifetime rules

---

## 12. When comments should not be used

Avoid comments that:

* restate the code
* become stale easily
* describe old code no longer present
* explain trivial syntax
* narrate every line

Bad:

```c
/* Set done to true */
done = true;
```

Bad:

```c
/* Loop through the array */
for (i = 0; i < count; i++)
```

Unless there is a reason:

```c
/* Skip slot 0 because it is reserved for the sentinel record. */
for (i = 1; i < count; i++)
```

---

## 13. Struct documentation

Document structs, especially if fields have ownership, units, or invariants.

Example:

```c
typedef struct
{
    int socket_fd;          /* Connected socket. -1 if closed. */
    size_t msg_len;         /* Length of msg_buffer in bytes. */
    char *msg_buffer;       /* Caller-owned heap buffer. */
    bool authenticated;     /* True after successful login. */
} ClientSession;
```

If the struct is important, add a block comment above it.

---

## 14. Enum documentation

Document enum meaning, especially for state machines.

Example:

```c
/* Connection state for the session lifecycle. */
typedef enum
{
    SESSION_INIT,       /* Newly created, not yet authenticated. */
    SESSION_ACTIVE,     /* Authenticated and allowed to send requests. */
    SESSION_CLOSED      /* Closed permanently; no further use allowed. */
} SessionState;
```

---

## 15. Error handling documentation

For functions that fail in multiple ways, document all meaningful failure modes.

Example:

```c
 * Returns:
 *   0 on success.
 *  -1 if input is invalid.
 *  -2 if memory allocation fails.
 *  -3 if database write fails.
```

If using `errno`, say so explicitly.

---

## 16. Ownership and lifetime rules

Junior programmers often get this wrong, so make it explicit.

Document:

* who allocates memory
* who frees it
* whether returned pointers are borrowed or owned
* whether buffers must be preallocated

Example:

```c
 * Returns:
 *   Newly allocated string on success. Caller must free().
```

Or:

```c
 * Notes:
 *   Returned pointer is owned by the cache and remains valid until
 *   cache_destroy() is called.
```

---

## 17. Concurrency and locking

If there is threading, always document:

* whether function is thread-safe
* required locks
* lock ordering if relevant

Example:

```c
 * Thread Safety:
 *   Caller must hold session_lock before calling this function.
```

---

## 18. Assertions and invariants

If code depends on invariants, document them near the relevant logic.

Example:

```c
/* Invariant: head is NULL if and only if count is 0. */
```

This is especially useful in linked lists, trees, queues, and state machines.

---

## 19. Documentation style rules

I would give them these style rules:

* Write in complete sentences.
* Keep comments factual and specific.
* Use consistent section names.
* Keep comments updated when code changes.
* Prefer short paragraphs over walls of text.
* Use block comments above functions, not end-of-line clutter.
* Do not decorate comments excessively.

---

# Recommended standard template

Here is a template you can hand them:

```c
/******************************************************************************
 * Function:    function_name
 *
 * Description:
 *   Brief description of what the function does and why it exists.
 *
 * Input Arguments:
 *   arg1       - Meaning of arg1.
 *   arg2       - Meaning of arg2.
 *
 * Returns:
 *   Description of return value(s).
 *
 * Errors:
 *   Description of error conditions, if any.
 *
 * Side Effects:
 *   Description of any state changes, allocations, logging, I/O, etc.
 *
 * Notes:
 *   Any important assumptions, ownership rules, thread-safety notes,
 *   or unusual behavior.
 ******************************************************************************/
```

---

# Practical policy for branches, switch, and inline comments

My recommendation:

* **Branches:** comment only when the purpose is not obvious or the rule is important.
* **Switch statements:** comment the switch as a whole when it represents dispatch or state logic; comment individual cases only if needed.
* **Inline comments:** use sparingly for tricky logic, invariants, magic constants, and “why,” not for obvious code.

---

# One more thing: require self-explanatory names first

Documentation is not a substitute for clean naming.

This:

```c
int f(int a, int b)
```

is harder to save with comments than:

```c
int validate_user_age(int age_years, int minimum_age)
```

So your standard should say:

> Good names come first. Comments explain what names alone cannot.

---

# My suggested minimum rule set for juniors

If you want something enforceable and not too heavy, I’d require:

* file header on every `.c` and `.h`
* function block on every public function
* function block on every non-trivial static function
* comments for tricky logic, invariants, and magic constants
* comments for ownership, side effects, and thread-safety
* no comments that merely restate code
* no plain-English narration of every line

That gives you a strong standard without burying them.

I can turn this into a one-page team standard or a ready-to-paste `DOCUMENTATION_STANDARD.md`.

