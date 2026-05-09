# C/C++ Master Review Checklist

> Walk through every section for each C/C++ review. Report findings under the
> section headings. Sections with no findings should be noted as clean.

## 1. Correctness

- [ ] Does the code do what the specification appears to require?
- [ ] Are all return values, outputs, and side effects correct?
- [ ] Are corner cases handled: empty input, zero, one item, max size, negative
  values, duplicates, null pointers?
- [ ] Are error paths correct, not just the happy path?
- [ ] Are integer calculations correct, including overflow, truncation, sign
  extension, and implicit conversions?
- [ ] Are comparisons correct for signed vs unsigned values?
- [ ] Are loop bounds correct, with no off-by-one errors?
- [ ] Are all switch cases covered, with sensible default handling?
- [ ] Are assumptions about input format, ordering, ranges, or state made
  explicit and validated?
- [ ] Does the code behave correctly under partial failure?

## 2. Memory Safety

- [ ] Any possible buffer overflow or out-of-bounds read/write?
- [ ] Any use-after-free?
- [ ] Any double free?
- [ ] Any memory leaks?
- [ ] Any dereference of null, dangling, or uninitialized pointers?
- [ ] Any reads from uninitialized memory?
- [ ] Is allocated memory sized correctly, including element count times element
  size?
- [ ] Are string operations safe, including room for the terminating null?
- [ ] Are memcpy, memmove, strncpy, snprintf, and similar calls used correctly?
- [ ] In C++, are ownership rules clear for raw pointers, references, smart
  pointers, containers, and views?

## 3. Resource Management

- [ ] Are files, sockets, mutexes, handles, descriptors, and mapped regions
  always released?
- [ ] Are early returns and error exits leak-safe?
- [ ] In C++, is RAII used where appropriate?
- [ ] Are destructors, cleanup blocks, or defer-like patterns reliable?
- [ ] Are acquisition and release paired consistently?
- [ ] Are cleanup routines idempotent where needed?
- [ ] **Retry loops (`goto try_again` / `continue` across cleanup):** after
  each `close` / `free` / `destroy` in the cleanup block, is the handle
  set to NULL so the next iteration doesn't touch a stale pointer if the
  retry's setup fails? (See `c.md` §Double-Free, Pattern 4.)

## 4. Undefined Behavior and Implementation Traps

- [ ] Any signed integer overflow?
- [ ] Any shift by negative or too-large count?
- [ ] Any invalid pointer arithmetic?
- [ ] Any strict aliasing violations?
- [ ] Any misaligned access assumptions?
- [ ] Any dependence on evaluation order or sequence points?
- [ ] Any returning references or pointers to dead stack objects?
- [ ] Any invalid casts, especially reinterpret-style casts?
- [ ] Any union type punning or low-level tricks that are non-portable or
  unsafe?
- [ ] Any assumptions about object lifetime that the language does not guarantee?

## 5. Concurrency and Thread Safety

- [ ] Any data races?
- [ ] Are shared variables protected consistently?
- [ ] Are lock acquisition orders consistent, avoiding deadlock?
- [ ] Are atomics used correctly with suitable memory ordering?
- [ ] Is there any check-then-act race?
- [ ] Are condition variables used correctly, including predicate re-checking?
- [ ] Could callbacks or virtual calls happen while holding a lock?
- [ ] Are thread lifetimes and shutdown paths safe?
- [ ] Are reference counts or shared ownership updates thread-safe?
- [ ] Could signal handlers, interrupts, or async callbacks interact unsafely?

## 6. Security

- [ ] Are all untrusted inputs validated?
- [ ] Any injection risk: shell, SQL, format-string, path, command, environment?
- [ ] Any unsafe string formatting with user-controlled format strings?
- [ ] Any path traversal or symlink race risk?
- [ ] Any insecure temp file usage?
- [ ] Any secrets logged, copied, or left in memory longer than needed?
- [ ] Any weak randomness for security-sensitive purposes?
- [ ] Any cryptography misuse: homegrown crypto, bad modes, hardcoded keys,
  missing verification?
- [ ] Any privilege boundary issues?
- [ ] Any denial-of-service risk from unbounded allocation, recursion, retries,
  parsing, or lock contention?

## 7. Input Validation and Defensive Programming

- [ ] Are function arguments validated?
- [ ] Are preconditions and postconditions clear?
- [ ] Are sizes, lengths, counts, and indexes sanity-checked?
- [ ] Is malformed input rejected cleanly?
- [ ] Are impossible states prevented or at least detected?
- [ ] Are invariants checked in debug or assertion builds?
- [ ] Is fail-closed behavior used where security matters?

## 8. Error Handling

- [ ] Are all relevant return codes checked?
- [ ] Are errno or library-specific error states handled correctly?
- [ ] Are exceptions used safely and consistently in C++?
- [ ] Are errors propagated with enough context?
- [ ] Are cleanup and rollback correct on failure?
- [ ] Is the code mixing exception and non-exception styles in dangerous ways?
- [ ] Are assertions misused for runtime error handling?
- [ ] Is logging of failures useful and non-noisy?

## 9. API and Interface Design

- [ ] Is the function/class/module contract clear?
- [ ] Are names accurate and unambiguous?
- [ ] Is ownership explicit in the API?
- [ ] Are const-correctness and immutability used properly?
- [ ] Are interfaces minimal and hard to misuse?
- [ ] Are parameter types appropriate, or too permissive?
- [ ] Are outputs separated clearly from inputs?
- [ ] Are hidden side effects surprising?
- [ ] Is the abstraction level consistent?
- [ ] Does the API expose internal details unnecessarily?

## 10. C-Specific Issues

- [ ] Are macros safe, parenthesized, and free of side-effect surprises?
- [ ] Should a macro be an inline function instead?
- [ ] Are sizeof expressions applied to the right object, not the type name by
  habit?
- [ ] Is struct initialization complete and correct?
- [ ] Are flexible array members handled correctly?
- [ ] Are variadic functions used safely?
- [ ] Are casts hiding real problems?
- [ ] Are string and memory APIs chosen carefully?
- [ ] Are `#ifdef` blocks creating unintentional fallthrough, dead code, or
  struct layout differences?
- [ ] Do `#endif` comments match their `#if`/`#ifdef`?

## 11. C++-Specific Issues

- [ ] Is RAII used consistently?
- [ ] Are smart pointers used correctly: unique_ptr, shared_ptr, weak_ptr?
- [ ] Is shared_ptr used only where shared ownership is truly needed?
- [ ] Are move and copy semantics correct?
- [ ] Are rule-of-three/five/zero issues present?
- [ ] Are destructors virtual where polymorphic deletion is possible?
- [ ] Are object slicing risks present?
- [ ] Are references, spans, string_views, and iterators safe with respect to
  lifetime?
- [ ] Are templates readable, constrained, and producing sensible errors?
- [ ] Are noexcept, explicit, override, final, and constexpr used
  appropriately?
- [ ] Are exceptions safe across constructors, destructors, and callbacks?
- [ ] Is inheritance justified, or would composition be safer?

## 12. Performance

- [ ] Any obvious algorithmic problems?
- [ ] Any accidental quadratic or worse behavior?
- [ ] Any unnecessary copies, allocations, or string churn?
- [ ] Any cache-unfriendly access patterns in hot paths?
- [ ] Any repeated work that can be hoisted or memoized?
- [ ] Are data structures appropriate for expected sizes and operations?
- [ ] Are I/O calls batched sensibly?
- [ ] Are locks held longer than necessary?
- [ ] Is performance tuning justified by context, or just complexity without
  benefit?
- [ ] Are micro-optimizations hurting clarity for no real gain?

## 13. Portability

- [ ] Does the code assume a platform, compiler, endianness, word size, or ABI?
- [ ] Are fixed-width integer types used where needed?
- [ ] Any assumptions about struct packing or alignment?
- [ ] Any non-portable compiler extensions?
- [ ] Any Windows/POSIX differences ignored?
- [ ] Any filesystem, newline, path-separator, or locale assumptions?
- [ ] Any time, clock, or timezone assumptions?
- [ ] Any build flags or library version dependencies not documented?

## 14. Style and Readability

- [ ] Is the code understandable without reverse engineering?
- [ ] Are functions short enough and focused?
- [ ] Are names meaningful?
- [ ] Are comments accurate and useful?
- [ ] Are stale or misleading comments present?
- [ ] Is the control flow straightforward?
- [ ] Are deeply nested branches avoidable?
- [ ] Are magic numbers named?
- [ ] Is duplicated logic factored sensibly?
- [ ] Is formatting consistent with project standards?

## 15. Maintainability

- [ ] Is the code easy to modify safely?
- [ ] Are responsibilities well separated?
- [ ] Is there unnecessary coupling?
- [ ] Are tricky areas isolated and documented?
- [ ] Are dependencies minimal and justified?
- [ ] Does the code invite bugs because the same rule must be remembered in many
  places?
- [ ] Are helper functions introduced where they clarify repeated patterns?
- [ ] Is the module boundary sensible?

## 16. Testability and Tests

- [ ] Is the code structured so it can be tested?
- [ ] Are there unit tests for normal cases, edge cases, and error cases?
- [ ] Are there regression tests for known bugs?
- [ ] Are failure paths tested?
- [ ] Are concurrency-sensitive parts testable?
- [ ] Are security-relevant checks covered by tests?
- [ ] Are assertions or diagnostics in place for debug builds?
- [ ] Are tests deterministic and isolated?

## 17. Logging, Observability, Diagnostics

- [ ] Does the code log enough to diagnose failures?
- [ ] Does it avoid logging secrets or noisy spam?
- [ ] Are log levels appropriate?
- [ ] Are identifiers included to correlate events?
- [ ] Are error messages actionable?
- [ ] Are metrics or counters needed for production diagnosis?

## 18. Build and Integration Concerns

- [ ] Does the code compile cleanly with warnings enabled?
- [ ] Would it survive `-Wall -Wextra -Werror` or equivalent?
- [ ] Any sanitizer issues likely under ASan, UBSan, TSan, MSan?
- [ ] Any static analysis warnings likely from clang-tidy, cppcheck, Coverity,
  PVS-Studio?
- [ ] Are dependencies and includes minimal and correct?
- [ ] Any ODR or link-time hazards in C++?
- [ ] Are feature flags and configuration handled safely?

## 19. Backward Compatibility

- [ ] Does the change break ABI or API?
- [ ] Are serialized formats, wire formats, or file formats still compatible?
- [ ] Are config formats and defaults stable?
- [ ] Are version checks or migration paths needed?
- [ ] Could old clients or peers misbehave with this change?

## 20. Review of Assumptions and Risk

- [ ] What assumptions does the code make that could be false in production?
- [ ] What is the blast radius if this fails?
- [ ] Is there a simpler design with fewer failure modes?
- [ ] Are the hardest-to-review parts really necessary?
- [ ] What would an attacker, fuzz tester, or exhausted maintainer break first?
