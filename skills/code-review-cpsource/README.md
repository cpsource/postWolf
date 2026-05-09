# code-review-cpsource

A structured code review skill for [Claude Code](https://claude.ai/code) with
a mandatory verification phase and a 20-section C/C++ master checklist.

Forked from [code-review-excellence](https://github.com/awesome-skills/code-review-skill)
and improved based on real false-positive failures found during a review of
wolfSSL's `src/ssl_sk.c`.

## What changed from the original

The original skill produced a false positive — it flagged intentional LIFO
pop semantics as a high-severity bug because it didn't cross-reference the
test suite. This fork adds:

- **Mandatory verification phase (Phase 3.5)** — every suspected bug must be
  checked against tests, callers, and concrete execution traces before being
  reported as a finding
- **20-section C/C++ master checklist** — correctness, memory safety, resource
  management, UB, concurrency, security, input validation, error handling, API
  design, C-specific, C++-specific, performance, portability, style,
  maintainability, testability, logging, build, backward compatibility, risk
- **Compact 10-question review prompt** — what can crash, corrupt memory, leak,
  be exploited, deadlock, trigger UB, hurt maintainability, and what tests are
  missing
- **4-bucket severity system** — Critical, Major, Minor, Questions/Assumptions
- **Expanded C guide** (~1,200 lines) — NULL deref, off-by-one, double free,
  use-after-free, `#ifdef` pitfalls, cast safety, format strings, security,
  input validation, portability, performance
- **Expanded C++ guide** (~740 lines) — virtual destructors, composition vs
  inheritance, noexcept/constexpr, null/unchecked access, cast safety, expanded
  concurrency (lock ordering, check-then-act, condition variables)
- **Always-on C/C++ checks** — 10 mandatory items even in a quick review

## Installation

```bash
# macOS / Linux
git clone https://github.com/cpsource/code-review-cpsource.git \
  ~/.claude/skills/code-review-cpsource

# Windows (PowerShell)
git clone https://github.com/cpsource/code-review-cpsource.git `
  "$env:USERPROFILE\.claude\skills\code-review-cpsource"
```

## Usage

Once installed, invoke it from the Claude Code prompt:

```
/code-review-cpsource code review src/ssl_sk.c
/code-review-cpsource security review src/tls13.c
/code-review-cpsource code review src/internal.c
```

## Supported languages

| Category | Language/Framework | Guide | Key topics |
|----------|--------------------|-------|------------|
| **Systems** | C | `references/c.md` | Memory safety, UB, NULL deref, off-by-one, `#ifdef`, format strings, portability |
| | C++ | `references/cpp.md` | RAII, lifetime, move/copy, virtual dtors, composition, noexcept, concurrency |
| | Qt | `references/qt.md` | Object model, signals/slots, thread safety |
| **Frontend** | React 19 | `references/react.md` | Hooks, Server Components, Suspense, TanStack Query v5 |
| | Vue 3 | `references/vue.md` | Composition API, reactivity, composables |
| | TypeScript | `references/typescript.md` | Type safety, async/await, immutability |
| | CSS/Less/Sass | `references/css-less-sass.md` | Variables, responsive, performance |
| **Backend** | Java 17/21 | `references/java.md` | Spring Boot 3, virtual threads, JPA |
| | Python | `references/python.md` | Mutable defaults, async, typing |
| | Go | `references/go.md` | Goroutines, channels, context, interfaces |
| | Rust | `references/rust.md` | Ownership, unsafe, async, error handling |
| **Cross-cutting** | Architecture | `references/architecture-review-guide.md` | SOLID, anti-patterns, coupling |
| | Performance | `references/performance-review-guide.md` | Web Vitals, N+1, complexity |
| | Security | `references/security-review-guide.md` | All-language security checklist |

## Review process

```
Phase 1 - Context Gathering
  Read PR description, check CI status, understand requirements
                    |
                    v
Phase 2 - High-Level Review
  Architecture - Performance impact - Test strategy
                    |
                    v
Phase 3 - Line-by-Line Analysis
  Logic - Security - Maintainability - Edge cases
                    |
                    v
Phase 3.5 - Verify Before Reporting  <-- NEW
  Check tests - Check callers - Trace with concrete values
  Distinguish "looks wrong" from "is wrong"
                    |
                    v
Phase 4 - Summary & Decision
  Structured feedback in 4 severity buckets
```

For C/C++ reviews, the skill walks through all 20 sections of the
[master checklist](references/c-cpp-master-checklist.md) and answers the
compact 10-question prompt.

## Severity buckets

| Bucket | Meaning |
|--------|---------|
| **Critical** | Memory corruption, auth bypass, data race, UB reachable in production, data loss |
| **Major** | Wrong behavior, leak, missing validation, bad API design |
| **Minor** | Style, readability, small inefficiency, naming, comments |
| **Questions** | May be okay, but needs confirmation from the author |

## Repository structure

```
code-review-cpsource/
|
+-- SKILL.md                              # Core skill (~300 lines)
+-- README.md
+-- LICENSE
+-- CONTRIBUTING.md
|
+-- references/
|   +-- c-cpp-master-checklist.md         # 20-section mandatory C/C++ checklist
|   +-- c.md                              # C review guide (~1,200 lines)
|   +-- cpp.md                            # C++ review guide (~740 lines)
|   +-- react.md                          # React 19 / Next.js
|   +-- vue.md                            # Vue 3 Composition API
|   +-- rust.md                           # Rust ownership, async, unsafe
|   +-- typescript.md                     # TypeScript strict mode
|   +-- java.md                           # Java 17/21 & Spring Boot 3
|   +-- python.md                         # Python async, typing, pytest
|   +-- go.md                             # Go goroutines, channels, context
|   +-- qt.md                             # Qt object model, signals/slots
|   +-- css-less-sass.md                  # CSS/Less/Sass
|   +-- architecture-review-guide.md      # SOLID, anti-patterns
|   +-- performance-review-guide.md       # Web Vitals, N+1, memory leaks
|   +-- security-review-guide.md          # Security checklist
|   +-- common-bugs-checklist.md          # Language-specific bug patterns
|   +-- code-review-best-practices.md     # Communication guidelines
|
+-- assets/
|   +-- review-checklist.md               # Quick reference checklist
|   +-- pr-review-template.md             # PR review comment template
|
+-- scripts/
    +-- pr-analyzer.py                    # PR complexity analyzer
```

## Origin and license

Forked from [awesome-skills/code-review-skill](https://github.com/awesome-skills/code-review-skill).

MIT License. See [LICENSE](./LICENSE).
