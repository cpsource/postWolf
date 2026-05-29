#!/usr/bin/env bash
#
# install.sh — sync the repo's skills into the live Claude Code skills dir.
#
# Each subdirectory here (the ones containing a SKILL.md) is copied into
# ${CLAUDE_SKILLS_DIR:-$HOME/.claude/skills}/<name>/, replacing any existing
# copy. Claude Code loads skills from that directory, so this is what makes
# a repo skill actually take effect.
#
# Usage:
#   ./install.sh           # install all skills
#   ./install.sh iranian   # install only the named skill(s)

set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST_DIR="${CLAUDE_SKILLS_DIR:-$HOME/.claude/skills}"

mkdir -p "$DEST_DIR"

# Build the list of skills to install: explicit args, or every subdir with a SKILL.md.
skills=()
if [ "$#" -gt 0 ]; then
    skills=("$@")
else
    for d in "$SRC_DIR"/*/; do
        [ -f "${d}SKILL.md" ] && skills+=("$(basename "$d")")
    done
fi

if [ "${#skills[@]}" -eq 0 ]; then
    echo "No skills found to install." >&2
    exit 1
fi

for name in "${skills[@]}"; do
    src="$SRC_DIR/$name"
    if [ ! -f "$src/SKILL.md" ]; then
        echo "skip: '$name' is not a skill (no SKILL.md)" >&2
        continue
    fi
    rm -rf "${DEST_DIR:?}/$name"
    cp -r "$src" "$DEST_DIR/$name"
    echo "installed: $name -> $DEST_DIR/$name"
done
