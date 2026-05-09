---
name: auto-doc-cpsource
description: |
  Automatically documents C source code (.c and .h files) according to project documentation standards.
  Adds file headers, function documentation blocks, struct/enum documentation, inline comments for
  complex logic, and Doxygen-compatible annotations to public APIs.
  Use when: documenting C code, adding function headers, adding file headers, generating Doxygen comments,
  documenting structs, documenting enums, reviewing documentation completeness, enforcing documentation
  standards on C source files.
allowed-tools:
  - Read
  - Grep
  - Glob
  - Bash
  - Edit
  - Write
  - Agent
---

# auto-doc-cpsource

## Overview

Automatically documents C source code files according to project documentation standards.
Applies file headers, function documentation blocks (with Doxygen annotations for public APIs),
struct/enum documentation, and targeted inline comments for complex logic.

## Instructions

When the user invokes `/auto-doc-cpsource`, document the specified C source file(s) following
the three-layer standard defined in the reference documents.

### Input

The user provides one or more `.c` or `.h` file paths (or a directory to process). Examples:

```
/auto-doc-cpsource src/user_lookup.c
/auto-doc-cpsource src/network/
/auto-doc-cpsource include/api.h
```

If no argument is given, ask which file(s) to document.

### Process

For each target file, follow these steps in order:

#### Step 1: Read and Understand the File

- Read the entire file.
- Identify all functions (public and static), structs, enums, macros, and complex logic blocks.
- Determine which items already have documentation and which need it.

#### Step 2: Add or Update the File Header

Every `.c` and `.h` file must have a file header. Use Doxygen format for `.h` files
and the standard block format for `.c` files (Doxygen is acceptable for `.c` too).

**Standard format (`.c` files):**

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
 *   - Thread safety notes
 *   - Ownership rules
 *   - Limitations
 *
 * Author:      (preserve existing or leave blank)
 * Created:     YYYY-MM-DD (preserve existing or use today's date)
 ******************************************************************************/
```

**Doxygen format (`.h` files and public APIs):**

```c
/**
 * @file filename.h
 * @brief Short description.
 *
 * @details
 * Detailed description of the module.
 *
 * @author (preserve existing or leave blank)
 * @date YYYY-MM-DD
 */
```

#### Step 3: Document Functions

For **every public function** and **every non-trivial static function**, add a documentation block.

**For public functions in `.h` files, use Doxygen format:**

```c
/**
 * @brief    Short one-line summary.
 *
 * @details
 * What the function does and why it exists.
 *
 * @param[in]  arg1    Description (note NULL rules, valid range).
 * @param[out] arg2    Description.
 *
 * @return
 * Description of return value(s). List each code explicitly.
 *
 * @note  Ownership, thread safety, or caveats.
 * @warning  Risks or unsafe behavior.
 */
```

**For functions in `.c` files, use the standard block format:**

```c
/******************************************************************************
 * Function:    function_name
 *
 * Description:
 *   What the function does and why it exists.
 *
 * Input Arguments:
 *   arg1       - Description (valid range, NULL rules, ownership)
 *   arg2       - Description
 *
 * Returns:
 *   Exact meaning of return value(s).
 *   0  on success
 *  -1  on specific failure
 *
 * Errors:
 *   Error conditions and behavior.
 *
 * Side Effects:
 *   State changes, allocations, I/O, logging.
 *
 * Notes:
 *   Assumptions, ownership rules, thread safety, caveats.
 ******************************************************************************/
```

**Minimum required sections:** Function, Description, Input Arguments, Returns.
Add Errors, Side Effects, and Notes when applicable.

#### Step 4: Document Structs and Enums

Add documentation to structs and enums, especially for:
- Fields with non-obvious meaning
- Ownership semantics
- Valid ranges or units
- State machine states

Use `/**< */` inline comments for struct/enum fields:

```c
typedef struct
{
    int socket_fd;      /**< Connected socket (-1 if closed) */
    size_t length;      /**< Buffer length in bytes */
    char *buffer;       /**< Caller-owned memory */
} Connection;
```

#### Step 5: Add Inline Comments for Complex Logic

Add inline comments **only where needed** for:
- Non-obvious logic or tricky math
- Magic numbers (prefer `#define` constants instead)
- Security checks
- Workarounds or protocol rules
- Loop invariants or non-obvious iteration order
- Branch conditions that enforce rules or prevent errors
- Switch statements that represent dispatch, state machines, or protocol handling

**Do NOT add comments that:**
- Restate the code in English
- Describe trivial operations
- Narrate every line

#### Step 6: Document Ownership and Lifetime

For every function that allocates, borrows, or transfers memory ownership, document:
- Who allocates
- Who frees
- Whether returned pointers are borrowed or owned
- Whether buffers must be preallocated

#### Step 7: Document Thread Safety (if applicable)

If the code uses threading, document:
- Whether each function is thread-safe
- Required locks
- Lock ordering if relevant

### Output

After documenting the file:

1. Show a summary of changes made:
   - File header: added/updated/already present
   - Functions documented: count (list names)
   - Structs/enums documented: count
   - Inline comments added: count
   - Ownership rules documented: count
   - Thread safety notes: count

2. If any documentation decisions were ambiguous (e.g., unclear ownership,
   uncertain thread safety), list them as questions for the user to verify.

### Rules

1. **Preserve existing correct documentation.** Do not overwrite documentation that is
   already accurate and complete. Update it only if it is incorrect, incomplete, or
   does not follow the standard format.

2. **Never change functional code.** Only add or modify comments and documentation blocks.
   Exception: replacing magic numbers with `#define` constants is allowed and encouraged.

3. **Explain why, not what.** Comments must explain intent, assumptions, and constraints --
   not restate the code.

4. **Be precise about return values.** List each return code explicitly with its meaning.

5. **Good naming comes first.** If a function or variable name is unclear, suggest a rename
   in the summary but do not rename it automatically.

6. **Dependencies section accuracy.** List only headers that are actually `#include`d.

7. **Date handling.** Preserve existing dates. Only use today's date for newly created headers.

## Reference Documents

- [Documentation Standard](references/documentation-standard.md) - Core documentation rules
- [Doxygen Specification](references/doxygen-spec.md) - Doxygen-compatible format
- [Full Documentation Spec](references/full-spec.md) - Complete practical specification

## Examples

### Example Input

```
/auto-doc-cpsource src/user_lookup.c
```

### Example Output

The skill reads the file, adds documentation, then reports:

```
Documented src/user_lookup.c:
  - File header: added
  - Functions documented: 5 (find_user_by_id, validate_user, load_users, free_user_table, hash_user_id)
  - Structs documented: 2 (UserRecord, UserTable)
  - Enums documented: 1 (UserStatus)
  - Inline comments added: 3 (magic number, loop invariant, ownership note)
  - Ownership rules documented: 2 (load_users return, free_user_table)
  - Thread safety: noted module as not thread-safe in file header

Questions for verification:
  1. find_user_by_id: Is the returned pointer guaranteed valid until table destruction?
  2. load_users: Should this function be considered thread-safe if called with separate tables?
```
