# wolfssl-issue-review

A [Claude Code](https://claude.ai/code) skill that runs the full wolfSSL
GitHub-issue review workflow in one invocation. From a single
`review issue 10287` prompt, it produces (under
`<wolfssl-tree>/wolfssl-issues/issue-N/`):

- **`README-issue-N.md`** — 10-section analysis (bug, upstream
  status, root cause, proposed fix, caveats, tests to add,
  end-to-end verification)
- **`issue-N.patch`** — unified diff against current master
- **`issue-N-test.c`** — self-contained C reproducer that
  actually triggers the bug
- **`test.sh`** — BEFORE/AFTER harness with PASS/FAIL gate,
  `pkill`-based server cleanup, and tree-restore on exit
- **`.gitignore`** — excludes the compiled binary
- A local git commit in the `wolfssl-issues` sub-repo (not pushed
  automatically — you approve)
- A drafted GitHub reply body (posted only on your explicit approval)

The `wolfssl-issues/` directory is a sibling git repository inside
the wolfSSL working tree — typically a clone of the companion repo
that holds per-issue review artefacts (e.g.
[`CpsourceInc/wolfssl-issues`](https://github.com/CpsourceInc/wolfssl-issues)).

## Background

This skill codifies the workflow behind the reviews for
[issue #10019](https://github.com/wolfSSL/wolfssl/issues/10019),
[#10271](https://github.com/wolfSSL/wolfssl/issues/10271), and
[#10287](https://github.com/wolfSSL/wolfssl/issues/10287). Those
three reviews followed the same 14 phases by hand. The cost of
manually repeating each phase — and the risk of skipping one — was
the motivation for turning the procedure into a skill.

## Install

```sh
git clone https://github.com/cpsource/wolfssl-issue-review
cd wolfssl-issue-review
./skill-install.sh
```

The script copies `SKILL.md`, `README.md`, `LICENSE`, `references/`,
and `assets/` into `~/.claude/skills/wolfssl-issue-review/`. It does
*not* copy `.git/`, so the install location stays clean. Re-running
the script reinstalls over the top of the existing install.

Uninstall: `./skill-install.sh --uninstall`.

(If you'd rather keep the source-of-truth inside
`~/.claude/skills/` and pull updates with `git pull`, you can clone
directly: `git clone https://github.com/cpsource/wolfssl-issue-review
~/.claude/skills/wolfssl-issue-review`. Both layouts work.)

## Prerequisites

- **Claude Code** CLI (this skill is authored for it).
- **`gh` CLI**, authenticated as a user with read access to
  `wolfSSL/wolfssl` (`gh auth status` should show a valid token).
- **wolfSSL clone** at `/home/ubuntu/wolfssl` by default. Other paths
  work; tell Claude the path when invoking.
- **wolfssl-issues sub-repo** at `<wolfssl-tree>/wolfssl-issues/` —
  must exist and be a git working tree. Typically
  `git clone git@github.com:CpsourceInc/wolfssl-issues ~/wolfssl/wolfssl-issues`.
  The skill refuses to run if this directory is missing.
- **Build toolchain**: `autoconf`, `automake`, `libtool`, `gcc`,
  `make` — enough to run `./configure && make` against wolfSSL.
- Port **11111** free (the default `./examples/server/server` port
  used by the harness).

## Usage

Natural-language:

```
review issue 10287
```

Or explicit slash:

```
/wolfssl-issue-review 10287
```

The skill recognises both forms. The issue number is required; if you
omit it the skill will ask.

### What happens

1. **Tree prep** — stashes your dirty work (if any), pulls, pops back.
2. **Fetch** — `gh issue view N`.
3. **Upstream scan** — `gh pr list --search`, `gh search issues
   --include-prs`, plus keyword searches for the function names in
   the issue body. Results land in the README's `Upstream status`
   section.
4. **Root-cause read** — greps and reads the affected code; traces
   data flow; locates the smallest viable fix.
5. **Write README, patch, C reproducer, and `test.sh`**.
6. **Run `test.sh` end-to-end** — both orderings BEFORE and AFTER the
   patch. Must show 4/4 expected outcomes.
7. **Takeaway checklist** (required before commit):
   - Did I skip any "latent only" findings? Reconsider if the fix is
     ≤3 lines.
   - Do the functions I'm fixing have zero existing test coverage? If
     so, add a concrete-value regression assertion.
   - Does the diagnosis connect the code defect to the user-visible
     symptom in the issue?
8. **Commit locally** — single commit under `issue-N/`.
9. **Draft reply** — README body first, then `<details>` collapsible
   sections for patch, C test, and `test.sh`.
10. **Wait for your approval**, then post via `gh issue comment`.

At no point does the skill post to GitHub without your explicit
go-ahead.

## Skill layout

```
wolfssl-issue-review/
├── SKILL.md                    # main prompt (what Claude reads)
├── README.md                   # this file
├── LICENSE                     # MIT
├── references/
│   ├── workflow.md             # per-phase command recipes
│   ├── readme-template.md      # README-issue-N.md section skeleton
│   ├── test-sh-template.sh     # parametric BEFORE/AFTER harness
│   ├── reply-format.md         # reply-body assembly recipe
│   └── takeaways.md            # three lessons from the ssl_load review
└── assets/
    └── issue-10287-example.md  # guided tour of the canonical example
```

## Tone

Reviews produced by this skill match the house style of the three
worked examples:

- Terse technical prose.
- Exact `file.c:line` references.
- Tables for BEFORE/AFTER matrices and file/line/severity summaries.
- No emojis, no marketing adjectives.

## Licence

MIT. See [LICENSE](LICENSE).

## Related skills

- [`code-review-cpsource`](https://github.com/cpsource/code-review-cpsource)
  — general-purpose C/C++ code review with a 20-section checklist
  and mandatory verification phase. This skill is the wolfSSL-specific,
  end-to-end-output variant of that idea.
- [`auto-doc-cpsource`](https://github.com/cpsource/auto-doc-cpsource)
  — automatic Doxygen-style documentation for C code.
