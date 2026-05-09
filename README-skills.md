# postWolf skills

Skills are Claude Code packages that bundle a documented workflow
(plus optional helper scripts and reference files) under a stable
trigger phrase.  When a user invokes the skill — by typing
`/skill-name`, by uttering one of the trigger phrases listed in
the skill's `description`, or via the `Skill` tool — Claude loads
the skill's `SKILL.md` body and follows it.

The directory layout under `skills/` mirrors what gets installed
into `~/.claude/skills/`.  Each subdirectory is one self-contained
skill.

## Skills shipped here

| Skill | One-line purpose | Trigger |
|---|---|---|
| [`cut-release/`](skills/cut-release/) | Cut a tagged postWolf release: CHANGELOG flip, MANIFEST re-sign, commit, merge phase→master, annotated tag, push.  Encapsulates the eight-step ritual. | `/cut-release`, "cut a release", "release vX.Y.Z", "ship 0.1.1", "merge phase to master and tag" |
| [`wolfssl-merge-to-postWolf/`](skills/wolfssl-merge-to-postWolf/) | Three-way merge of a single file from `~/wolfssl/<path>` into `~/postWolf/<path>`, then build + `make check`.  Used for bringing upstream wolfSSL fixes into the fork. | `/wolfssl-merge-to-postWolf <path>`, "merge `<path>`", "pull `<path>` from wolfssl into postWolf" |
| [`wolfssl-issue-review/`](skills/wolfssl-issue-review/) | End-to-end triage of a wolfSSL GitHub issue: fetch issue, scan for prior PRs, read affected source, produce a per-issue dir with README analysis + patch + C reproducer + BEFORE/AFTER harness, commit locally, draft GitHub comment.  Stops before posting. | `/wolfssl-issue-review`, "review issue N", "triage wolfSSL bug N" |
| [`auto-doc-cpsource/`](skills/auto-doc-cpsource/) | Automatic C source documentation (`.c` / `.h`) per project standards: file headers, Doxygen-style function blocks, struct/enum docs, inline comments for non-obvious logic. | "document C code", "add function headers", "generate Doxygen comments" |
| [`code-review-cpsource/`](skills/code-review-cpsource/) | Comprehensive code review for React 19, Vue 3, Rust, TypeScript, Java, Python, C/C++.  Includes a mandatory verification phase — every suspected bug must be cross-referenced against test suite, callers, and concrete execution traces before reporting. | "code review", "review this PR", "review changes" |

## How a skill is structured

Minimal layout:

```
skills/<name>/
├── SKILL.md          # required — frontmatter + instructions for Claude
└── (optional)
    ├── README.md     # human-readable overview (separate from SKILL.md)
    ├── LICENSE
    ├── references/   # static reference files the skill cites
    ├── scripts/      # helper scripts the skill may shell out to
    └── assets/       # images, fixtures, etc.
```

`SKILL.md` always opens with YAML frontmatter:

```yaml
---
name: <skill-name>            # must match the directory name
description: |
  Multi-line description.  Claude indexes this to decide when the
  skill applies; the "Use when:" sentence at the bottom drives
  trigger matching.
allowed-tools:                # optional whitelist
  - Read
  - Bash
  - Edit
  - Write
---
```

Below the frontmatter, the body is free-form Markdown — typically
"Overview", "When to invoke", "Inputs", "Procedure", "Verification",
"Failure recovery".  Claude reads it on every invocation.

## Installing the skills on a fresh machine

Skills live under `~/.claude/skills/` (per-user) — that's the only
place Claude Code looks.  This repo's `skills/` directory is just
a checked-in mirror so the workflows are version-controlled
alongside the code they operate on.

To install everything in this directory onto a new dev box:

```sh
mkdir -p ~/.claude/skills
cp -r ~/postWolf/skills/* ~/.claude/skills/
```

To install one skill:

```sh
cp -r ~/postWolf/skills/cut-release ~/.claude/skills/
```

After copying, restart any running `claude` session (or open a new
one) — the skill index is loaded at session start.  The new
trigger phrases (`/cut-release`, etc.) become available
immediately in the next session.

To verify a skill is loaded:

```
> /<skill-name>
```

…should respond with the skill's body.  Or ask `claude` "what
skills are available?" and look for the name in the listing.

## Updating a skill

The canonical copy is the one under `~/.claude/skills/` — that's
what Claude actually reads at runtime.  When you edit a skill,
update both:

```sh
# 1. Edit the in-repo copy (so the change ships with the project):
$EDITOR ~/postWolf/skills/<name>/SKILL.md

# 2. Sync to the runtime location (so the change takes effect):
cp -r ~/postWolf/skills/<name>/. ~/.claude/skills/<name>/
```

Or develop in `~/.claude/skills/` and copy back to the repo when
the workflow stabilises.  The cut-release skill in this directory
was developed in-runtime first, then copied here.

## Authoring a new skill

1. Pick a name in `kebab-case`.  Avoid clashing with built-in
   skill names (`init`, `review`, `simplify`, `update-config`,
   `keybindings-help`, `loop`, `schedule`, `claude-api`, etc.).
2. Create `skills/<name>/SKILL.md` with the frontmatter above.
3. The `description` is the **most important field** — Claude
   uses it to decide when the skill applies.  End it with a
   precise "Use when:" sentence listing the trigger phrases
   (slash form + natural-language paraphrases).
4. The body should walk Claude through the workflow:
   preconditions, inputs (use `AskUserQuestion` for choices),
   step-by-step procedure, verification, failure recovery.
5. If the skill needs helper scripts or reference files, add
   them in `scripts/` / `references/` and have `SKILL.md` cite
   their relative paths.
6. Test by copying to `~/.claude/skills/<name>/` and invoking
   it from a fresh `claude` session.
7. When stable, commit the in-repo copy.

## Built-in vs project skills

Claude Code ships with several built-in skills that are NOT in
this directory and are NOT shipped per-project — they're part of
the harness:

```
update-config, keybindings-help, simplify, fewer-permission-prompts,
loop, schedule, claude-api, init, review, security-review
```

If a built-in skill conflicts with a project skill name, the
project skill wins (per-user `~/.claude/skills/` shadows the
built-ins).  Avoid the conflict by picking distinctive names.

## See also

- `mtc-keymaster/README.md` — MTC architecture (relevant to
  `cut-release`'s MANIFEST signing step).
- `fips-framework/README-getting-started-guide.md` — how the
  FIPS workflow uses signed manifests; the `sign-dir.sh` /
  `verify-dir.sh` invariants the `cut-release` skill relies on.
- `CHANGELOG.md` — what `cut-release` flips on each invocation.
