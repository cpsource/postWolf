# Reply-body assembly recipe

The GitHub issue reply has a fixed shape:

1. One-line intro naming the artefacts included.
2. The README content, starting from `## The bug` (drop the H1 and
   the `Upstream:` back-reference line — they're redundant on the
   issue itself).
3. Three `<details>` collapsible sections in this order:
   - `issue-N.patch` in a `diff` fence
   - `issue-N-test.c` in a `c` fence
   - `test.sh` in a `bash` fence
4. One-line closer offering a PR.

## Shell recipe

```sh
N=<ISSUE_NUMBER>
ISSUE_DIR="$REPO/wolfssl-issues/issue-$N"

{
  cat <<'HEAD'
Took a crack at this. Root-cause analysis, proposed fix, a self-contained reproducer, and an automated BEFORE/AFTER verification script are all below. (Queried `gh` first — no existing PR references this issue and no other issue mentions it.)

---

HEAD
  # README content. Skip the H1 (line 1), the blank between it and
  # "Upstream:" (line 2), and the "Upstream:" paragraph. Start from
  # the first real section heading.
  sed -n '3p;7,$p' "$ISSUE_DIR/README-issue-$N.md"

  cat <<'MID1'

---

<details>
<summary><b><code>issue-NUMBER.patch</code></b> — N-line fix in `src/file.c`</summary>

```diff
MID1
  cat "$ISSUE_DIR/issue-$N.patch"
  cat <<'MID2'
```

</details>

<details>
<summary><b><code>issue-NUMBER-test.c</code></b> — self-contained reproducer</summary>

```c
MID2
  cat "$ISSUE_DIR/issue-$N-test.c"
  cat <<'MID3'
```

</details>

<details>
<summary><b><code>test.sh</code></b> — BEFORE/AFTER harness</summary>

```bash
MID3
  cat "$ISSUE_DIR/test.sh"
  cat <<'TAIL'
```

</details>

Happy to turn this into a PR if useful.
TAIL
} > /tmp/issue-$N-reply.md
```

### Replace the placeholders

Before running the `cat` recipe, edit the three `<summary>` lines
and the `HEAD` intro so that:

- The summary mentions the actual number of lines in the patch.
- The summary mentions the actual target file path (or files, if >1).
- The intro mentions the concrete finding (e.g. "no existing PR
  references this issue" — only if verified in Phase 3).

## Size check

Comments on GitHub issues are capped at 65_536 bytes. After writing
the file:

```sh
wc -c /tmp/issue-$N-reply.md
```

If it's over 60_000 bytes, the C test file is the usual culprit.
Options:

- Link to the file in a gist instead of embedding it.
- Drop less-critical parts of the reproducer (hex dumps, comment
  blocks).
- Split into two comments (less preferred — maintainers want one
  reviewable artefact).

## Fence collision check

All three files embedded in the reply are expected to be fence-clean
(no triple-backticks inside them). Sanity check:

```sh
for f in "$ISSUE_DIR/issue-$N.patch" "$ISSUE_DIR/issue-$N-test.c" "$ISSUE_DIR/test.sh"; do
    if grep -q '^```' "$f"; then
        echo "WARNING: $f contains triple-backticks; fence will break"
    fi
done
```

If any file contains triple-backticks, use four-backtick fences in
the `<details>` wrapper around that file, then close with four.

## Preview to user

Before posting, show the user:

```sh
head -40 /tmp/issue-$N-reply.md
echo "... [body omitted] ..."
tail -10 /tmp/issue-$N-reply.md
wc -c -l /tmp/issue-$N-reply.md
```

Wait for explicit "post it" (or equivalent). Do not post on any
response that's ambiguous — ask again.

## Post command

```sh
gh issue comment "$N" --repo wolfSSL/wolfssl --body-file /tmp/issue-$N-reply.md
```

Returns a URL; print it.
