Great idea — adding **Doxygen compatibility** lets you enforce structure *and* auto-generate docs.

Below is an updated section you can append to your standard.

---

# 📘 Doxygen-Compatible Documentation

All public APIs and important internal functions **must use Doxygen-style comments**.

Doxygen comments begin with:

```c
/** ... */
```

---

## 1. Function Documentation (Doxygen Format)

### Required format:

```c
/**
 * @brief    Short one-line summary of the function.
 *
 * @details
 * Detailed description explaining what the function does and why.
 *
 * @param[in]  table     Pointer to initialized user table.
 * @param[in]  user_id   Null-terminated string containing user ID.
 *
 * @return
 * Pointer to UserRecord on success.
 * NULL if no match is found.
 *
 * @note
 * Returned pointer refers to internal storage and must not be freed.
 *
 * @warning
 * Not thread-safe.
 */
UserRecord *find_user_by_id(UserTable *table, const char *user_id);
```

---

## 2. Parameter Tags

Use explicit direction tags:

* `@param[in]` → input only
* `@param[out]` → output only
* `@param[in,out]` → modified by function

### Example:

```c
/**
 * @param[in]  input     Input buffer
 * @param[out] output    Output buffer
 * @param[in,out] len    On input: buffer size, on output: bytes written
 */
```

---

## 3. Return Values

Use `@return` for function results.

If multiple return codes exist, list them clearly:

```c
/**
 * @return
 *  0  Success
 * -1  Invalid input
 * -2  File not found
 */
```

---

## 4. Common Doxygen Tags

Use these consistently:

| Tag        | Purpose                  |
| ---------- | ------------------------ |
| `@brief`   | Short summary            |
| `@details` | Full description         |
| `@param`   | Function arguments       |
| `@return`  | Return value             |
| `@note`    | Important notes          |
| `@warning` | Risks or unsafe behavior |
| `@retval`  | Specific return values   |
| `@pre`     | Preconditions            |
| `@post`    | Postconditions           |
| `@see`     | Related functions        |
| `@ingroup` | Grouping APIs            |

---

## 5. Struct Documentation

```c
/**
 * @brief Represents a client session.
 *
 * @details
 * Holds connection state and message buffers.
 */
typedef struct
{
    int socket_fd;      /**< Connected socket (-1 if closed) */
    size_t length;      /**< Buffer length in bytes */
    char *buffer;       /**< Caller-owned memory */
} ClientSession;
```

---

## 6. Enum Documentation

```c
/**
 * @brief Connection state.
 */
typedef enum
{
    STATE_INIT,     /**< Initial state */
    STATE_ACTIVE,   /**< Normal operation */
    STATE_DONE      /**< Completed */
} State;
```

---

## 7. File-Level Documentation

Place at top of file:

```c
/**
 * @file user_lookup.c
 * @brief User lookup and validation functions.
 *
 * @details
 * Provides utilities for loading and searching user records.
 *
 * @author Jane Smith
 * @date 2026-04-13
 */
```

---

## 8. Groups (Optional but Recommended)

Group related functions:

```c
/**
 * @defgroup user_api User API
 * @brief Functions for user management
 */

/**
 * @ingroup user_api
 */
```

---

## 9. Inline Comments (Doxygen Style)

Use `/**< */` for inline field comments:

```c
int count; /**< Number of active users */
```

---

## 10. Style Rules for Doxygen

* Always include `@brief`
* Keep `@brief` to one line
* Use `@details` for longer explanations
* Align parameter descriptions
* Be consistent across all files
* Do not mix plain comments with Doxygen for public APIs

---

## 11. Minimum Requirements

For all public functions:

* `@brief`
* `@param` (for each argument)
* `@return`
* `@details` (if non-trivial)

---

## 12. Build Documentation (Optional)

To generate docs:

```bash
doxygen -g
doxygen Doxyfile
```

---

# 🔚 Final Rule

> If it’s part of the public interface, it must be Doxygen-documented.

---

If you want next step, I can:

* generate a **ready-to-use Doxyfile tuned for C projects**
* or add a **code review checklist enforcing this standard**

