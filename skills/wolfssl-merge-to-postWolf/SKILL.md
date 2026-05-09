---
name: wolfssl-merge-to-postWolf
description: |
  Merge a single file from upstream wolfSSL (~/wolfssl/<filename>) into the
  postWolf fork (~/postWolf/<filename>), then verify the postWolf build.
  Three-way merge where a base can be located, manual conflict resolution
  otherwise. The destination is left modified-in-place in postWolf's working
  tree (checked out, not staged, not committed). After merging, runs the
  top-level postWolf build and `make check` to confirm the tree still
  compiles and tests pass.
  Use when: the user invokes /wolfssl-merge-to-postWolf <path>, says
  "merge <path>", "merge filename <path>", "pull <path> from wolfssl into
  postWolf", or supplies a wolfssl-relative path with merge intent.
allowed-tools:
  - Read
  - Bash
  - Edit
  - Write
  - Grep
---

# wolfssl-merge-to-postWolf

## Overview

One-shot workflow to bring a single file from upstream wolfSSL into the
postWolf fork. Source and destination paths share the same suffix:

- Source:      `/home/ubuntu/wolfssl/<filename>`
- Destination: `/home/ubuntu/postWolf/<filename>`

The destination is **left checked out** — modified in the working tree
but never staged, committed, or pushed. The user inspects, then commits
themselves when satisfied.

## Inputs

- `<filename>` — path relative to the wolfssl tree root, e.g.
  `wolfcrypt/src/aes.c`. Extract from the invocation text. If the user
  said "merge filename" with no path, ask for the path.

## Guardrails

- **Never** `git commit`, `git add`, `git push`, or `git reset --hard`
  in postWolf. The destination must end the run as an unstaged
  working-tree modification.
- **Never** rename wolfSSL upstream identifiers (`wolfssl/`,
  `wolfcrypt/`, `wolfSSL_*`, `wc_*`, `WOLFSSL_*`). See postWolf
  `CLAUDE.md`.
- **Zero compiler warnings** on the postWolf build is a hard rule
  (postWolf `CLAUDE.md`). If the merge introduces a warning, fix the
  code rather than suppress it.
- Refuse to start if `/home/ubuntu/wolfssl` or `/home/ubuntu/postWolf`
  are not git working trees.
- If the source path doesn't exist in `~/wolfssl`, abort.
- If the destination path doesn't exist in `~/postWolf`, ask whether
  the user wants this treated as a new-file copy or whether the path
  is a typo.

## Workflow

### Phase 1 — Validate

```sh
test -f /home/ubuntu/wolfssl/<filename>   || abort "no such source"
test -f /home/ubuntu/postWolf/<filename>  || ask user (new file?)
git -C /home/ubuntu/wolfssl  rev-parse --is-inside-work-tree
git -C /home/ubuntu/postWolf rev-parse --is-inside-work-tree
git -C /home/ubuntu/postWolf status --short -- <filename>
```

If the destination is already modified or staged, surface that to the
user before proceeding — the merge would mix with their pending work.

### Phase 2 — Quick equality check

```sh
diff -u /home/ubuntu/postWolf/<filename> /home/ubuntu/wolfssl/<filename>
```

If identical, skip Phase 3-4 and go straight to the build verify
(Phase 5) so the user still gets a "tree still builds" confirmation.

### Phase 3 — Three-way merge

Identify a BASE (common-ancestor) version of the file from wolfssl
history. Heuristic ladder, stop on first that works:

1. If postWolf's copy of the file matches some commit in wolfssl
   exactly, use that wolfssl commit as BASE:
   ```sh
   git -C /home/ubuntu/wolfssl log --oneline -- <filename> | head -50
   # for each candidate <rev>:
   git -C /home/ubuntu/wolfssl show <rev>:<filename> > /tmp/cand.txt
   diff -q /tmp/cand.txt /home/ubuntu/postWolf/<filename>
   ```
2. If no exact match, pick the wolfssl commit whose blob has the
   smallest `diff --stat` against postWolf's copy.
3. As a last resort, fall back to "no base" (BASE = empty) — every
   line will appear in conflict markers and be resolved manually in
   Phase 4.

Save BASE, LOCAL, REMOTE:

```sh
git -C /home/ubuntu/wolfssl show <rev>:<filename> > /tmp/merge-base.txt
cp /home/ubuntu/postWolf/<filename> /tmp/merge-local.txt
cp /home/ubuntu/wolfssl/<filename>  /tmp/merge-remote.txt
```

Run `git merge-file` in-place against the destination:

```sh
git merge-file --diff3 \
    -L "postWolf (LOCAL)" -L "base @<rev>" -L "wolfssl (REMOTE)" \
    /home/ubuntu/postWolf/<filename> \
    /tmp/merge-base.txt \
    /tmp/merge-remote.txt
```

Exit code = 0 → clean merge; jump to Phase 5.
Exit code > 0 → that many conflicts; proceed to Phase 4.

### Phase 4 — Resolve conflicts

For each conflict block (`<<<<<<<` ... `|||||||` ... `=======` ...
`>>>>>>>`):

- Read 30-60 lines of context around the block in the destination.
- Inspect upstream intent:
  ```sh
  git -C /home/ubuntu/wolfssl log -p --follow -- <filename> | head -300
  git -C /home/ubuntu/wolfssl log --oneline --since="6 months ago" -- <filename>
  ```
- Look for postWolf-specific markers in the LOCAL side (post-quantum
  additions, extra logging, `WOLFSSL_*` macros that don't exist
  upstream, Merkle / MTC hooks). When upstream and postWolf both
  touched the same hunk, prefer **combining** — keep postWolf's
  additions and layer in upstream's fix — rather than picking one
  side wholesale.
- Edit the destination file to remove the markers and produce the
  merged code.
- After all blocks, verify nothing was missed:
  ```sh
  grep -nE '^(<<<<<<<|\|\|\|\|\|\|\||=======|>>>>>>>) ' \
      /home/ubuntu/postWolf/<filename>
  ```
  Output must be empty.

### Phase 5 — Build verify (top-level make)

```sh
cd /home/ubuntu/postWolf
make 2>&1 | tee /tmp/merge-build.log
```

If the tree was never configured in this session, run
`./configure.sh` first (one-time per worktree) and then `make`.

If the build fails:
- Read the error, find the source line, fix in-place — usually a
  signature mismatch from the merge or a missing #include.
- Iterate. Do not patch around warnings; fix the cause.

If the build emits any `warning:` line, that's a hard fail under the
postWolf zero-warnings rule. Address before moving on.

### Phase 6 — make check

```sh
cd /home/ubuntu/postWolf
make check 2>&1 | tee /tmp/merge-check.log
```

If a test fails:
- Read the failing test's log; trace back to the merged hunk that
  changed behaviour.
- Decide: was the upstream change intended to alter behaviour (and
  the postWolf-specific test needs updating), or did the merge drop
  a postWolf-side guard? Bias toward the latter — postWolf tests are
  the source of truth.

### Phase 7 — Report

Print a short report:

- File: `<filename>`
- Source rev: `<wolfssl HEAD short-sha>`
- BASE rev: `<rev>` (or "none — fallback merge")
- Conflicts: `<N>` (and one-line per block describing the resolution)
- Build: `OK` / `failed (fixed)` / `failed`
- `make check`: `OK` / `<N> failed`
- `git -C /home/ubuntu/postWolf status --short` showing the
  destination file as `M` (modified, unstaged).

Stop. Do not commit. Do not stage. The user owns the next step.

## Tips for conflict resolution

- postWolf often layers post-quantum primitives (ML-KEM-768,
  ML-DSA-87) on top of wolfSSL's classical paths. When a hunk shows
  upstream tweaking a classical-only branch and postWolf adding a
  PQ branch alongside, the answer is almost always "keep both."
- postWolf's `socket-level-wrapper-*` and `mtc-keymaster/` trees do
  not exist upstream — merges should never touch them.
- Upstream identifiers (`wc_*`, `WOLFSSL_*`, `wolfssl/`,
  `wolfcrypt/`) are immutable. If a conflict appears to rename one,
  keep the upstream name.
- Three-line rule: if a conflict block can be resolved by deleting
  three lines or fewer, prefer the more local/conservative
  resolution. Don't take the opportunity to refactor.

## Style

- Terse, technical. No marketing language.
- Quote file paths with line numbers when explaining a fix
  (`wolfcrypt/src/aes.c:1234`).
- No emojis.
- One-paragraph end-of-run summary; the user reads `git status` and
  the build log for the full picture.
