# Detailed workflow recipes

Per-phase command recipes. Read this file when executing a phase and
something is unclear.

## Phase 0 — Verify the sub-repo

Before anything else, confirm that `<wolfssl-tree>/wolfssl-issues/`
exists and is a git working tree. Artefacts go there, not into the
wolfSSL source tree itself.

```sh
test -d /home/ubuntu/wolfssl/wolfssl-issues/.git \
    || { echo "wolfssl-issues sub-repo not found — clone it first"; exit 1; }
```

## Phase 1 — Prepare the tree

Default wolfSSL tree location: `/home/ubuntu/wolfssl`.

```sh
cd /home/ubuntu/wolfssl
git status --short
```

If there are staged or modified files, stash them. Note: the
`tests/psk_oracle_test.c` file in the author's tree has occasionally
shown up with a zero-byte blob in the index but a non-empty working
copy, which makes `git stash push` fail with
`"Entry '...' not uptodate. Cannot merge."`. Refresh the index entry
before stashing:

```sh
# Only run if the blob hash is e69de29bb2d1d6434b8b29ae775ad8c2e48c5391
# (empty-blob OID) for a file whose working copy is non-empty.
git ls-files -s tests/psk_oracle_test.c
git add tests/psk_oracle_test.c
```

Then:

```sh
git stash push -m "pre-review-N stash"
git pull
git stash pop
```

If `git stash pop` reports conflicts, tell the user and stop — the pop
conflict needs human judgment.

## Phase 2 — Fetch the issue

```sh
gh issue view N --repo wolfSSL/wolfssl
gh issue view N --repo wolfSSL/wolfssl --comments
```

Notes to extract from the issue body:

- **Affected files / functions** — usually named by reporter.
- **Reproduction steps** — exact commands or configuration.
- **Observed symptoms** — error codes, log snippets, wire behaviour.
- **Reporter's suspected root cause**, if any — use this as a hypothesis
  to verify or refute, not as ground truth.

## Phase 3 — Upstream scan (required)

Goal: fill the `Upstream status` section of the README with verified
facts, not assumptions.

### Direct number search

```sh
gh pr list --repo wolfSSL/wolfssl --state all --search "N" \
    --limit 20 --json number,title,state,url,updatedAt
gh search issues --repo wolfSSL/wolfssl --include-prs "N" --limit 20
```

`gh search prs` and `gh search issues` do not accept `--state all` —
query open and closed separately or omit the flag.

### Keyword searches

Pull 2-4 identifiers / phrases from the issue body:

- Function names mentioned (`TLSX_KeyShareEntry_Parse`,
  `SetAsymKeyDer`, ...)
- Unusual error strings quoted in the report
  (`"Buffer error, output too small"`)
- File paths when the issue calls them out
- High-signal domain terms (`multiple key shares`, `unused-bits byte`)

```sh
gh search prs --repo wolfSSL/wolfssl "<term>" --limit 10
gh search issues --repo wolfSSL/wolfssl "<term>" --limit 10
```

### Summarise

Record, in order:

1. When the issue was opened, by whom.
2. Whether any PR references the issue number.
3. Whether any other issue mentions it.
4. Results of the keyword sweep: matches, near-misses, none.

If nothing is found, say so explicitly. A negative result is useful
information.

## Phase 4 — Root-cause read

```sh
grep -rn "<function_name>" src/ wolfcrypt/src/ --include="*.c"
```

Read around each hit — typically 30-60 surrounding lines — to
understand the call graph and state flow. Pay attention to:

- Where is the stated symptom's target written? (e.g.
  `ssl->arrays->preMasterSecret`, a `len` out-param, a return code.)
- Are there any ordering assumptions (first-writer-wins vs. chosen-
  writer-wins)?
- Does the code fork on a `#if` that might not apply to the reporter's
  build? If so, check the configuration implied by the reproduction
  steps.

### Independent cross-check

Before finalizing the diagnosis, spawn a sub-agent:

```
Agent(
  description="Cross-check wolfSSL-issue-N diagnosis",
  subagent_type="Explore",
  prompt="I believe the root cause of wolfSSL issue #N is <hypothesis>.
    Independently verify by: (1) reading <file:line>; (2) listing every
    call site of <function>; (3) checking whether any existing test in
    tests/ or wolfcrypt/test/ exercises this path. Report any caller or
    test that contradicts the hypothesis."
)
```

## Phase 5 — Write the README

Start from the template: [readme-template.md](readme-template.md).

Fill section-by-section. Keep the exact H2 headings — the reply-
assembly step expects them.

## Phase 6 — Generate the patch

```sh
# Modify source in-tree:
# (Edit the files)

# Capture the diff:
mkdir -p wolfssl-issues/issue-N
git diff <files> > wolfssl-issues/issue-N/issue-N.patch

# Verify the patch applies cleanly starting from the clean tree:
git checkout -- <files>
git apply --check wolfssl-issues/issue-N/issue-N.patch
echo "apply-check exit = $?"
```

If `git apply --check` fails, the patch has a malformed hunk. Rebuild
it: apply the edits again, `git diff`, do not hand-edit the patch
file.

After verification, either keep the source patched for Phase 10 or
revert with `git checkout` — the test.sh will re-apply the patch
itself.

## Phase 7 — C reproducer

See [../assets/issue-10287-example.md](../assets/issue-10287-example.md)
for the guided tour of the canonical worked example.

Skeleton:

```c
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
/* + wolfcrypt headers for the APIs you need */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv)
{
    /* 1. Setup: wolfSSL_Init, WC_RNG, any keygen */
    /* 2. Trigger: call the buggy API with a crafted input */
    /* 3. Check: compare output to expected; print PASS or FAIL */
    /* 4. Cleanup: free keys, wolfSSL_Cleanup */
    return pass ? 0 : 1;
}
```

Build line that works against the in-tree libwolfssl:

```sh
gcc -Wall -Wextra -I$REPO -L$REPO/src/.libs \
    issue-N-test.c -lwolfssl -lm -o issue-N-test
```

Run with `LD_LIBRARY_PATH=$REPO/src/.libs`.

## Phase 8 — `test.sh`

Copy [test-sh-template.sh](test-sh-template.sh) to
`wolfssl-issues/issue-N/test.sh` and `chmod +x`. Fill the
placeholders at the top of the file. The template's `REPO` resolution
assumes the script is at `wolfssl-issues/issue-N/test.sh` and walks
up two levels to reach the wolfSSL repo root.

### Placeholders

- `<ISSUE_N>` — the issue number.
- `<CFG_FLAGS>` — configure flags needed. Examples:
  - Issue #10019: `--enable-ed25519`
  - Issue #10287: `--enable-mlkem --enable-tls-mlkem-standalone --enable-pqc-hybrids`
- `<TEST_RUN_1_LABEL>`, `<TEST_RUN_1_FLAG>` — pair for the first
  reproducer run.
- `<TEST_RUN_2_LABEL>`, `<TEST_RUN_2_FLAG>` — pair for the second (or
  empty, if the bug has only one mode).
- `<SOURCE_FILE_RELATIVE>` — the file the patch touches, e.g.
  `src/tls.c` or `wolfcrypt/src/asn.c`. The script resets it via
  `git checkout`.

### Must-haves

- `set -u` but *not* `set -e` (test failures are expected BEFORE).
- `trap restore_tree EXIT` to recover even on abort.
- `pkill` loop that retries with `pgrep` check between runs.
- `LD_LIBRARY_PATH=$LIB_DIR` for every reproducer invocation.
- 4-line coloured summary at the end.
- Exit 0 iff all expected outcomes match.

## Phase 9 — `.gitignore`

```sh
echo "issue-N-test" > wolfssl-issues/issue-N/.gitignore
```

## Phase 10 — Run `test.sh`

```sh
./wolfssl-issues/issue-N/test.sh
```

Expected final line: `Overall: all four outcomes as expected.`

If it says otherwise, stop and diagnose:

- BEFORE unexpectedly PASSED: reproducer is not triggering the bug.
  Check your understanding of which code path exercises it.
- AFTER unexpectedly FAILED: patch is incomplete or the test is
  checking the wrong thing.

## Phase 11 — Takeaway checklist

Full text in [takeaways.md](takeaways.md). Before committing, walk
through the three questions. It is acceptable to answer
"considered and rejected for X" but not acceptable to skip the
question.

## Phase 12 — Commit (in the wolfssl-issues sub-repo)

```sh
cd <wolfssl-tree>/wolfssl-issues
git add issue-N/
git commit -m "Add issue-N review artefacts

<one-paragraph summary of the bug>

- README-issue-N.md : analysis
- issue-N.patch     : proposed fix (<N-line> unified diff)
- issue-N-test.c    : self-contained reproducer
- test.sh           : before/after harness

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

If the wolfssl-issues sub-repo has pre-existing staged work, use
pathspec so the commit is scoped to just `issue-N/`:

```sh
git commit -- issue-N/
```

After committing, show `git log -1` and `git diff HEAD~1..HEAD --stat`
to the user, and **ask before pushing**. `git push` is a shared-state
action — same category as posting a GitHub comment.

## Phase 13 — Draft the reply

See [reply-format.md](reply-format.md) for the exact shell recipe.
Save to `/tmp/issue-N-reply.md`. Show the first 30 lines and the last
10 lines to the user plus the total byte count, and wait.

## Phase 14 — Post

Only after the user says "post it" or equivalent:

```sh
gh issue comment N --repo wolfSSL/wolfssl --body-file /tmp/issue-N-reply.md
```

Print the returned URL.
