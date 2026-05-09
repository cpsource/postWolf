---
name: cut-release
description: |
  Cut a tagged postWolf release: flip CHANGELOG.md [Unreleased] -> [vX.Y.Z],
  re-sign the top-level MANIFEST, commit the release marker on the current
  phase-N branch, merge phase-N -> master, tag master HEAD as vX.Y.Z
  (annotated, with release notes pulled from the CHANGELOG entry), push
  master + tag, then optionally create the next phase branch.
  Encapsulates the multi-step ritual that's easy to fumble manually
  (forgetting the CHANGELOG flip, tagging the wrong commit, signing
  with the wrong identity, etc.).
  Use when: the user invokes /cut-release, says "cut a release", "release
  vX.Y.Z", "tag a release", "merge phase to master and tag", "ship vX.Y.Z",
  or asks to bump the postWolf version with the merge-to-master ritual.
allowed-tools:
  - Read
  - Bash
  - Edit
  - Write
  - AskUserQuestion
---

# cut-release — postWolf release ritual

## Overview

Postwolf's release flow has eight discrete steps that go together but
are easy to fumble piecemeal:

1. Pick the next version (patch / minor / major bump from the last tag,
   OR an explicit `vX.Y.Z`).
2. Flip `CHANGELOG.md` `[Unreleased]` content into a new `[X.Y.Z]` entry
   dated with today's UTC date; leave a fresh empty `[Unreleased]`.
3. Re-sign the top-level repo MANIFEST so the release commit verifies
   on a fresh clone (`sign-dir.sh -g <publisher> .`).
4. Commit "release X.Y.Z" on the current phase branch.
5. Push the phase branch to origin.
6. Switch to `master`, pull, fast-forward (or real) merge from the
   phase branch, push.
7. Tag `master` HEAD with `vX.Y.Z` as an annotated tag whose body is
   the new CHANGELOG entry verbatim; push the tag.
8. Switch back to the phase branch (or — recommended — create the
   next phase branch from master and switch there).

This skill walks the user through it, asking only the decisions that
require human judgement (version bump kind, publisher identity, next
phase number) and executing the rest.

## When to invoke

Trigger phrases:
- `/cut-release` (slash form)
- "cut a release", "release v0.2.0", "ship 0.1.1"
- "tag a release", "tag the next release"
- "merge phase to master and tag"
- "bump version", "release the next version"

Do NOT invoke for:
- "tag" without context (could mean a git tag for some other purpose)
- merging without releasing (that's just `git checkout master + git merge`)
- updating CHANGELOG.md alone (that doesn't need the merge/tag ritual)

## Inputs (gather via AskUserQuestion if not given)

| Input | Default if unspecified | Notes |
|---|---|---|
| **Bump kind** | ASK | `patch` / `minor` / `major`, OR an explicit `vX.Y.Z` if user named one in the trigger phrase |
| **Publisher identity** | `factsorlie.com` if `~/.TPM/factsorlie.com/` exists, else first auto-discovered identity | Used by `sign-dir.sh` for the MANIFEST re-sign step |
| **Next phase branch** | ASK (default suggestion: increment the current phase number by 1) | After tagging, create + switch.  Set to "skip" to stay on the released phase branch. |

## Preconditions (verify before starting)

Bail with a clear message if any fails:

- **Working tree clean.**  `git status --porcelain` must be empty.  If
  not: tell the user which files are dirty and stop.
- **On a phase branch.**  Current branch must match `phase-[0-9]+`.
  Cutting from `master` is a different ritual (hotfix tag) — refuse
  for now and ask the user to switch.
- **CHANGELOG.md `[Unreleased]` populated.**  At least one non-empty
  subsection (Added / Changed / Fixed / Removed) under `[Unreleased]`.
  If empty, ask: "release with no changelog entries?" — accept yes
  but warn loudly.
- **Local in sync with origin.**  `git fetch origin <phase>` then
  ensure `git rev-parse HEAD == git rev-parse origin/<phase>`.  If
  ahead, push first; if behind, pull first; if diverged, refuse.
- **Build is clean.**  `make -f Makefile.tools 2>&1 | grep -cE 'warning:|error:'`
  must be 0.  If non-zero, refuse — releases ship clean builds only.

## Procedure

### 1. Determine the version

```sh
git tag -l 'v*' --sort=-v:refname | head -1
```

Last tag becomes the base.  Apply the bump kind:

| Kind | From `vX.Y.Z` | To |
|---|---|---|
| patch | `v0.1.0` | `v0.1.1` |
| minor | `v0.1.0` | `v0.2.0` |
| major | `v0.1.0` | `v1.0.0` (caution — confirm explicitly) |

If user gave an explicit `vX.Y.Z`, validate it's strictly greater
than the last tag.

### 2. Flip CHANGELOG.md

Read `CHANGELOG.md`, find the `## [Unreleased]` heading, and:

- Insert a new section **above** the existing `[Unreleased]` content,
  titled `## [X.Y.Z] — YYYY-MM-DD` (UTC date, ISO-8601), with the
  body copied verbatim from `[Unreleased]`.  Add a one-sentence
  release-blurb at the top of the new section if the bump kind is
  minor or major.
- Replace the `[Unreleased]` body with `(no changes since X.Y.Z)`.

**Capture the new section's body in memory** — it becomes the tag
message body in step 7.

### 3. Re-sign the top-level MANIFEST

```sh
cd ~/postWolf
sign-dir.sh -g <publisher> .
```

Verify it passed:

```sh
verify-dir.sh <publisher> .
```

### 4. Commit the release marker

```sh
git add CHANGELOG.md MANIFEST.sha256 MANIFEST.sig
git commit -m "$(cat <<'EOF'
release X.Y.Z

<one-line summary lifted from the new CHANGELOG entry>

Top-level MANIFEST refreshed.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

### 5. Push the phase branch

```sh
git push origin <phase>
```

### 6. Merge phase -> master

Per the project's standing rule (memory: `feedback_merge_to_master.md`),
use a real git merge, NOT `git branch -f`:

```sh
git checkout master
git pull
git merge <phase>            # fast-forward expected (no diverging history)
git push origin master
```

If merge isn't fast-forward, refuse and ask the user — diverging
history during a release ritual is a signal to stop and investigate.

### 7. Tag and push

Build the annotated tag message from the captured CHANGELOG section:

```sh
git tag -a vX.Y.Z -m "$(cat <<'EOF'
postWolf vX.Y.Z

<full body of the new CHANGELOG section, verbatim>
EOF
)"
git push origin vX.Y.Z
```

### 8. Switch back / create next phase

If the user gave a next-phase number (or accepted the default):

```sh
git checkout master
git checkout -b phase-N+1
git push -u origin phase-N+1
```

Otherwise switch back to the released phase:

```sh
git checkout <phase>
```

## Post-conditions (report to user)

Print a short summary:

- Released **vX.Y.Z** on `master` (commit `<short-sha>`).
- Tag pushed to `origin`.
- Now on **`<branch>`** (current working branch).
- Next: when you accumulate work on `<branch>`, run `/cut-release`
  again.

## Verification commands the user can run

```sh
git tag -l 'v*'                     # see all postWolf tags
git describe --tags HEAD            # version string for the current commit
git log --oneline master..<branch>  # commits ahead of last release
verify-dir.sh <publisher> .         # confirm MANIFEST verifies
```

## Failure recovery

If the ritual fails partway:

| Step that failed | Recovery |
|---|---|
| 2 (CHANGELOG edit) | `git checkout CHANGELOG.md` to undo; nothing pushed yet. |
| 3 (sign-dir) | Same — discard MANIFEST changes. |
| 4 (commit) | `git reset HEAD~1 --soft` to keep the changes staged but undo the commit. |
| 5 (push phase) | Already committed locally; just retry the push. |
| 6 (merge to master) | If push to master failed, check for upstream changes and re-attempt.  Do NOT force-push. |
| 7 (tag push) | Locally tagged but not pushed; just `git push origin vX.Y.Z` again.  If you need to delete the local tag, `git tag -d vX.Y.Z`. |
| 8 (next-phase branch) | Create the branch manually with `git checkout -b phase-N+1 master`. |

## Defaults / conventions

- Tag prefix: `v` (matches existing `v0.1.0`).
- Date format in CHANGELOG section header: `YYYY-MM-DD` UTC (matches
  `[0.1.0] — 2026-05-09`).
- `sign-dir.sh -g` is mandatory for the MANIFEST refresh — without
  `-g`, gitignored build artifacts get included and the MANIFEST
  fails to verify on fresh clones.
- The `Co-Authored-By:` trailer follows project convention.
- After the tag is pushed, the repo's "default branch" remains
  `master`; phase branches are working space.
