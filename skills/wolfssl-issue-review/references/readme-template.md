# README-issue-N.md — section skeleton

Use this as the starting structure for every review. Delete
parenthetical guidance, keep the H2 headings verbatim (the reply-
assembly step keys off them).

---

```markdown
# Issue #N — <short bug summary>

## The bug

Upstream: <https://github.com/wolfSSL/wolfssl/issues/N>

<One paragraph: what the user sees, under what conditions. Quote
error codes/log messages verbatim. If there are multiple failure
modes, enumerate them with bullets — each bullet stands alone.>

## Upstream status

Checked on YYYY-MM-DD with `gh`:

- Issue opened YYYY-MM-DD by `<reporter>`, <N comments, any assignee,
  any labels>.
- `gh pr list --repo wolfSSL/wolfssl --state all --search "N"` →
  <result: "no PRs" / list of PRs>.
- `gh search issues --repo wolfSSL/wolfssl --include-prs "N"` →
  <result>.
- Keyword searches for <list the 2-3 terms you used> → <result>.
  <If there's a historical related hit that turned out to be
  unrelated, name it and say why.>

Conclusion: <one sentence. Is anything already addressing this?>

## Root cause

<Point directly at the file:line of the defect. Quote the offending
code in a ```c block. Explain in 2-5 sentences the state flow that
makes the symptom happen.>

<Use ### sub-headings when the root cause has multiple components
(e.g. "Eager encapsulation during parse" + "Shared state gets
clobbered" + "Selection happens afterwards"). Each sub-heading is
one aspect of the same root cause, not a separate bug.>

## Why the current design exists

<Optional. Include when the bug is not a simple oversight but an
artefact of a conscious design choice. Quote the relevant comment
from the code. Helps reviewers understand why "just fix it" isn't
the whole answer.>

## Proposed fix

<Name the functions and line numbers. Describe the smallest viable
change. Use a numbered list for multi-touch-point fixes.>

<After the fix list, add a "After the fix:" paragraph enumerating the
invariants that now hold — this is how a reviewer audits the change
for completeness.>

## Caveats and risks

<Bullet every concern. Examples:
- Memory: does the fix add allocations? How many?
- Build-config guards: does the fix need to survive with feature X
  disabled?
- Backward compatibility: will an older version's output still parse?
- Async-crypto path: does the fix handle WC_PENDING_E?
- Threading: is the code path called under a lock?>

## Tests to add

<Either describe tests included in the patch, or list follow-up
tests not yet written. If "not yet written", each bullet should be
specific enough that someone else could write it:>

1. <Concrete test description — inputs, expected output, which
   assertion would have caught the bug.>
2. <...>

## Files touched by the proposed patch

- `<path/to/file1.c>` — <what changed>
- `<path/to/file2.c>` — <what changed>

See `issue-N.patch` alongside this file.

## Appendix — end-to-end verification

<Describe what `issue-N-test.c` does, in 8-10 numbered steps. Start
from key generation or setup, walk through the bug-triggering call,
end with the PASS/FAIL decision. This section is the "how do I know
the fix works" evidence for a reviewer who won't run the test.>

### Observed results

| Scenario | Unpatched server | Patched server |
|----------|------------------|----------------|
| <mode 1> | **FAIL** — <exact failure text> | **PASS** — <exact pass text> |
| <mode 2> | **FAIL** — <...> | **PASS** — <...> |

<Brief sentence on what the BEFORE/AFTER distinction proves.>

## Running the test harness

`test.sh` alongside this README automates the entire BEFORE/AFTER
verification. From the wolfSSL repo root:

```sh
./issue-N/test.sh
```

What it does, in order:

1. Resets `<source file>` to clean via `git checkout`.
2. Runs `./configure <flags>` so the affected code is built in.
3. Builds wolfSSL, compiles the reproducer.
4. BEFORE pass: runs the reproducer, `pkill`s the server between
   runs.  Expected to FAIL.
5. Applies `issue-N.patch` and rebuilds.
6. AFTER pass: same spawn / run / `pkill` dance.  Expected to PASS.
7. Prints a colored 4-line summary.
8. On exit, restores the tree to the state it had before the run.

Exit status: `0` only when all outcomes match expectation, `1`
otherwise — usable as a regression gate.
```

## Section checklist

Before finalizing, verify every section above is present or
consciously omitted:

- [ ] The bug
- [ ] Upstream status (no, really — always run the queries)
- [ ] Root cause
- [ ] Why the current design exists (optional; include if the defect
      is an artefact of a design choice, not an oversight)
- [ ] Proposed fix
- [ ] Caveats and risks
- [ ] Tests to add (always — even if the answer is "none, covered by
      the included reproducer")
- [ ] Files touched by the proposed patch
- [ ] Appendix — end-to-end verification (skip only if no C
      reproducer was feasible; note why)
- [ ] Running the test harness
