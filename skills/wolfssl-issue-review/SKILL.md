---
name: wolfssl-issue-review
description: |
  Full end-to-end review workflow for a wolfSSL GitHub issue: prepares the
  local tree, fetches the issue, scans upstream for prior PRs and issues,
  reads the affected source, produces a per-issue directory with a README
  analysis, a proposed patch, a self-contained C reproducer, and a
  BEFORE/AFTER test harness, commits locally, and drafts a GitHub comment
  reply. Stops before posting; user must approve the reply body.
  Use when: reviewing a wolfSSL issue, "review issue N", /wolfssl-issue-review,
  triaging a wolfSSL bug report, preparing a fix proposal for wolfSSL, writing
  a patch plus reproducer for a wolfSSL GitHub issue.
allowed-tools:
  - Read
  - Grep
  - Glob
  - Bash
  - Edit
  - Write
  - Agent
---

# wolfssl-issue-review

## Overview

One-shot review workflow for a wolfSSL GitHub issue. The user says
`review issue 10287` (or invokes `/wolfssl-issue-review 10287`) and this
skill produces the same artifacts the author has been hand-crafting for
issues #10019, #10271, #10287, and #9753:

```
<wolfssl-repo>/wolfssl-issues/issue-N/
├── README-issue-N.md        # 10-section analysis with Upstream status
├── issue-N.patch            # unified diff against current master
├── issue-N-test.c           # self-contained C reproducer (if feasible)
├── test.sh                  # BEFORE/AFTER harness, PASS/FAIL gate
└── .gitignore               # excludes the compiled binary
```

`wolfssl-issues/` is a sibling git repository alongside the wolfSSL
source — typically a clone of the companion repo where per-issue
review artefacts live (e.g. `CpsourceInc/wolfssl-issues`). Commits
for the review go into that repo, not the wolfSSL tree.

## Inputs

- Issue number `N` (required). Extract from the invocation text.
- Repo: `wolfSSL/wolfssl` unless the user overrides.
- Local wolfSSL tree: `/home/ubuntu/wolfssl` unless the user overrides.
- Local issues repo: `<wolfssl-tree>/wolfssl-issues/` — must exist and
  be a git working tree. If it doesn't exist, stop and ask the user
  to clone it first.

## Guardrails

- **Never post** the GitHub reply without showing the body to the user and
  receiving explicit approval. `gh issue comment` only runs on "post it".
- **Never push** the wolfssl-issues commit without explicit approval.
  Same pattern — show the commit, ask, then push.
- **Never amend public commits** or force-push.
- **Refuse to start** if `<wolfssl-tree>/wolfssl-issues/` is missing
  or not a git working tree. The artefacts have nowhere to go.
- If the tree is dirty, stash before pull and pop after. Check for the
  `tests/psk_oracle_test.c` index-stale pattern observed in the author's
  workflow (empty-blob entry with non-empty working copy) and refresh with
  `git add` before stashing.
- If `test.sh` BEFORE runs do **not** FAIL, stop and reassess the diagnosis
  — the bug reproducer must first reproduce.

## Workflow

The workflow is 14 phases. Detailed per-phase recipes are in
[references/workflow.md](references/workflow.md). High-level:

### Phase 1 — Prepare the tree

```sh
cd /home/ubuntu/wolfssl
git status --short
# If working tree is dirty: stash tracked + staged; preserve untracked
git stash push -m "pre-review-N stash"
git pull
git stash pop
```

### Phase 2 — Fetch the issue

```sh
gh issue view N --repo wolfSSL/wolfssl
gh issue view N --repo wolfSSL/wolfssl --comments
```

Extract from the issue body: affected files, function names,
reproduction steps, stated symptoms. These become search terms for
Phase 3 and read targets for Phase 4.

### Phase 3 — Upstream scan (required)

Scan for prior work so the `Upstream status` section of the README is
grounded in fact. Minimum queries:

```sh
# Direct number reference
gh pr list --repo wolfSSL/wolfssl --state all --search "N"
gh search issues --repo wolfSSL/wolfssl --include-prs "N"

# Keyword: pull 2-3 identifier/function names from the issue body
gh search prs --repo wolfSSL/wolfssl "<function_name>" --limit 10
gh search prs --repo wolfSSL/wolfssl "<symptom_phrase>" --limit 10
gh search issues --repo wolfSSL/wolfssl "<key_term>" --limit 10
```

Record findings verbatim for the README — including the negative result
("no PRs found, no issue mentions, keyword searches empty").

### Phase 4 — Root-cause read

- Grep for function names from the issue in the affected files.
- Read surrounding 30-60 lines to understand state flow.
- Trace every path that writes to the stated symptom's target
  (`ssl->arrays->preMasterSecret`, a returned length, etc.).
- Locate the smallest possible fix. Default to the existing
  codebase's idioms.
- Before finalizing: spawn a sub-agent with the Agent tool to
  independently cross-check the diagnosis against callers and tests.
  (Same pattern as `code-review-cpsource` Phase 3.5 verification.)

### Phase 5 — Write `wolfssl-issues/issue-N/README-issue-N.md`

All per-issue artefacts go under `<wolfssl-tree>/wolfssl-issues/issue-N/`.
Create the directory if it doesn't exist.

Use [references/readme-template.md](references/readme-template.md) as
the skeleton. Mandatory H2 sections:

1. The bug
2. Upstream status
3. Root cause
4. Why the current design exists (if relevant)
5. Proposed fix
6. Caveats and risks
7. Tests to add (if applicable)
8. Files touched by the proposed patch
9. Appendix — end-to-end verification
10. Running the test harness

### Phase 6 — Generate the patch

```sh
# Apply edits in-tree
# Edit: <source files>
git diff <files> > wolfssl-issues/issue-N/issue-N.patch
# Verify
git apply --check wolfssl-issues/issue-N/issue-N.patch
# Revert working tree
git checkout -- <files>
```

### Phase 7 — Write the C reproducer

Write `wolfssl-issues/issue-N/issue-N-test.c` as a self-contained
program that uses wolfSSL APIs (or hand-crafts protocol bytes) to
trigger the bug. Exit code 0 on PASS, non-zero on FAIL.

Canonical worked example — a TLS 1.3 ClientHello + full client-side
key-schedule reproducer — lives in the companion
`CpsourceInc/wolfssl-issues` repo at
`wolfssl-issues/issue-10287/issue-10287-test.c`. See
[assets/issue-10287-example.md](assets/issue-10287-example.md) for a
guided tour. Adapt the patterns as needed; not every bug needs a full
protocol implementation.

Common reproducer shapes:

- API round-trip (e.g. #10019): encode → decode → expect bytes; inject a
  known-good blob; expect decoder to accept.
- Protocol MitM (e.g. #10287): hand-craft a wire packet, send via TCP
  to `./examples/server/server`, decrypt the response with locally-
  computed keys.
- Pure-unit regression (e.g. #10271): encoder emits expected bytes for a
  fixed input; decoder rejects a known-bad input.

If the bug genuinely cannot be reproduced in a standalone program (e.g.
build-system only, hardware path), skip this file and note why in the
README.

### Phase 8 — Write `test.sh`

Copy [references/test-sh-template.sh](references/test-sh-template.sh)
to `wolfssl-issues/issue-N/test.sh` and fill in the placeholders.
The template already assumes it lives two levels below the wolfSSL
repo root (`HERE/../..`), matching the new layout.

- `<ISSUE_N>` — the issue number
- `<CFG_FLAGS>` — `./configure` flags needed for the affected code
- `<TEST_RUN_1_LABEL>` / `<TEST_RUN_1_FLAG>` — e.g. "Case 1
  (hybrid-first)" / `--hybrid-first`
- `<TEST_RUN_2_LABEL>` / `<TEST_RUN_2_FLAG>` — if the bug has two modes

Chmod +x. The script must:
- Reset `src/<file>.c` to clean via `git checkout` before each pass.
- Run `./configure $CFG_FLAGS`, build wolfSSL, compile the C test.
- BEFORE: run the reproducer against unpatched wolfSSL, expect FAIL.
- Apply the patch, rebuild.
- AFTER: run again, expect PASS.
- `pkill -f examples/server/server` between every run (with a short
  retry loop in case the port is slow to release).
- `trap` handler restores the tree on any exit path.
- Print a 4-line colored summary.
- Exit 0 iff all outcomes match expectation.

### Phase 9 — Write `wolfssl-issues/issue-N/.gitignore`

One line: `issue-N-test` (the compiled binary name). No other entries.

### Phase 10 — Run `test.sh`

Run it. Expect all four outcomes as expected. If BEFORE doesn't FAIL,
the reproducer is wrong. If AFTER doesn't PASS, the patch is wrong.

### Phase 11 — Takeaway checklist (required before commit)

Before committing, answer each of these explicitly. They come from
lessons learned reviewing `src/ssl_load.c`: a clean 5/6 bug-match
with the upstream fix that could have been 6/6 if the three traps
below had been avoided. Full text in
[references/takeaways.md](references/takeaways.md).

- [ ] **Latent bugs**: Did I flag anything as "latent only, skip"?
      Re-check whether the fix is really >3 lines. If ≤3 lines, fix it.
- [ ] **Zero-coverage functions**: Do the functions I touched have any
      existing tests? If no, add at least one assertion in my C test (or
      a test case in the tests/ directory) that would have caught the
      specific bug I'm fixing. Concrete value checks, not just
      non-nil / non-zero.
- [ ] **Wire-level trace**: Does the diagnosis connect the code defect to
      the user-visible symptom in the issue? If I can only say "this
      variable is wrong", keep tracing.

### Phase 12 — Commit locally (and optionally push)

The commit goes into the **wolfssl-issues sub-repo**, not the wolfSSL
tree:

```sh
cd <wolfssl-tree>/wolfssl-issues
git add issue-N/
git commit -m "Add issue-N review artefacts

<short description>

- README-issue-N.md : analysis
- issue-N.patch     : proposed fix (<N lines>)
- issue-N-test.c    : self-contained reproducer
- test.sh           : before/after harness

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

Do **not** push automatically. After committing, show the commit
(`git log -1`) to the user and ask whether to `git push`. Push is a
shared-state action; treat it like posting the GitHub reply.

### Phase 13 — Draft the GitHub reply

Assemble reply body per [references/reply-format.md](references/reply-format.md):

1. **One-line intro** summarising what was done (analysis + patch +
   reproducer + harness).
2. **Full content of `README-issue-N.md`**, minus the H1 title and the
   "Upstream:" back-reference line. Start directly with the
   `## The bug` section.
3. **`<details>`** blocks in this order:
   - `issue-N.patch` (```diff)
   - `issue-N-test.c` (```c)
   - `test.sh` (```bash)
4. **Closing line** offering a PR.

Show the body to the user. **Do not post.**

### Phase 14 — Post (only on user approval)

```sh
gh issue comment N --repo wolfSSL/wolfssl --body-file /tmp/issue-N-reply.md
```

Print the resulting comment URL.

## Style conventions

Match the tone of the issue-10287 README:

- Terse, technical prose.
- Quote code with exact `file.c:line` references.
- Tables for BEFORE/AFTER results, file/line/severity summaries.
- Markdown collapsible sections only for the reply body (not inside
  the README itself).
- No emojis.
- No marketing language ("robust", "seamlessly", "best-in-class").
