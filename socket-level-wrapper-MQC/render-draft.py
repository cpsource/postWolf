#!/usr/bin/env python3
"""
Render an IETF Internet-Draft .txt from the .md source of truth.

Usage:
    python3 render-draft.py draft-page-mqc-protocol-00.md \
        > draft-page-mqc-protocol-00.txt

The input is a Markdown file with these conventions (matching the MQC
draft):
  - Title block in a leading triple-backtick code fence (lines 1-N).
  - "# Title", "## Section", "### Subsection" headings.
  - Tables in pipe-syntax (| col | col |, with a | --- | --- | rule row).
  - Code/JSON blocks in triple-backtick fences.
  - Inline **bold** and `code` markup (markup is stripped on render).
  - "---" horizontal rules used as section dividers (rendered as blank).
  - Bullet lists with leading "- ".

The output is a 72-column, 56-line-per-page IETF I-D plain text.
"""

import re
import sys
import textwrap

PAGE_LINES = 56
LINE_WIDTH = 72
BODY_INDENT = "   "      # column 4
# Code blocks: emit their .md contents verbatim (no extra indent).  The
# .md is responsible for laying out code/ASCII-art at column boundaries
# that satisfy the 72-column rule without further indentation.
CODE_INDENT = ""
BANNER = "Internet-Draft          Merkle Quantum Connect          April 2026"


def make_footer(n: int) -> str:
    # The original draft uses an extra space before [Page N] for single
    # digits so the closing bracket aligns with double-digit pages.
    if n < 10:
        return f"Page, Ed.             Expires 23 October 2026                [Page {n}]"
    return f"Page, Ed.             Expires 23 October 2026               [Page {n}]"


def strip_inline(text: str) -> str:
    """Remove **bold** and `code` markdown so the inner text shows plain."""
    text = re.sub(r"\*\*(.+?)\*\*", r"\1", text)
    text = re.sub(r"`([^`]+)`", r"\1", text)
    # Also unescape markdown's escape sequences we use ("\*", "\_").
    text = re.sub(r"\\([*_])", r"\1", text)
    return text


def wrap_paragraph(text: str, indent: str) -> list[str]:
    """Wrap a paragraph at LINE_WIDTH with the given indent on every line."""
    width = LINE_WIDTH - len(indent)
    wrapped = textwrap.wrap(
        text,
        width=width,
        break_long_words=False,
        break_on_hyphens=False,
    )
    return [indent + ln for ln in wrapped] if wrapped else [""]


def render_table(rows: list[list[str]]) -> list[str]:
    """Render a markdown table as a simple plain-text two-column-ish table.

    Strategy: two-column tables become "Term  -- Definition"; multi-column
    tables get column-aligned with spaces. Width is capped at LINE_WIDTH.
    """
    if not rows:
        return []
    ncols = len(rows[0])
    # Compute column widths.
    col_w = [max(len(strip_inline(r[i])) for r in rows) for i in range(ncols)]
    # Cap total width.
    total = sum(col_w) + 3 * (ncols - 1) + len(BODY_INDENT)
    if total > LINE_WIDTH:
        # Reduce widest column until it fits.
        deficit = total - LINE_WIDTH
        widest = max(range(ncols), key=lambda i: col_w[i])
        col_w[widest] = max(10, col_w[widest] - deficit)
    out = []
    for r in rows:
        cells = [strip_inline(c) for c in r]
        # Wrap each cell to its column width.
        wrapped = [
            textwrap.wrap(c, width=col_w[i]) or [""] for i, c in enumerate(cells)
        ]
        height = max(len(w) for w in wrapped)
        for h in range(height):
            parts = []
            for i in range(ncols):
                cell = wrapped[i][h] if h < len(wrapped[i]) else ""
                parts.append(cell.ljust(col_w[i]))
            out.append(BODY_INDENT + "   ".join(parts).rstrip())
        out.append("")
    if out and out[-1] == "":
        out.pop()
    return out


def render(md_text: str) -> list[str]:
    """Convert markdown to a flat list of plain-text lines (un-paginated)."""
    lines = md_text.split("\n")
    out: list[str] = []

    # 1) Strip the leading title-block fence (lines 1..first '```' close).
    if lines and lines[0].strip() == "```":
        # Copy the contents of the fence verbatim (it's the IETF title block).
        i = 1
        while i < len(lines) and lines[i].strip() != "```":
            out.append(lines[i])
            i += 1
        # Skip the closing fence.
        i += 1
        # Two blank lines after the title block before the document title.
        out.append("")
        out.append("")
    else:
        i = 0

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # Section divider --- → blank line
        if stripped == "---":
            if out and out[-1] != "":
                out.append("")
            i += 1
            continue

        # Code/JSON fence: emit body indented at CODE_INDENT.
        m = re.match(r"^```", stripped)
        if m:
            i += 1
            block = []
            while i < len(lines) and not lines[i].lstrip().startswith("```"):
                block.append(lines[i].rstrip())
                i += 1
            i += 1  # skip closing fence
            if out and out[-1] != "":
                out.append("")
            for bl in block:
                out.append((CODE_INDENT + bl) if bl else "")
            out.append("")
            continue

        # Headings.
        m = re.match(r"^(#{1,6})\s+(.+?)\s*$", stripped)
        if m:
            depth = len(m.group(1))
            title = strip_inline(m.group(2))
            if out and out[-1] != "":
                out.append("")
            if depth == 1:
                # Top-of-document title — center it like an IETF title.
                centered = title.center(LINE_WIDTH).rstrip()
                out.append(centered)
                out.append("")
                # If the next non-blank line is a bold-only paragraph
                # (e.g., "**draft-page-mqc-protocol-00**"), treat it as
                # the centered draft-name subtitle.
                j = i + 1
                while j < len(lines) and lines[j].strip() == "":
                    j += 1
                if j < len(lines):
                    sub = lines[j].strip()
                    sub_match = re.match(r"^\*\*([^*]+)\*\*$", sub)
                    if sub_match:
                        out.append(sub_match.group(1).center(LINE_WIDTH).rstrip())
                        out.append("")
                        i = j + 1
                        continue
            else:
                out.append(title)
                out.append("")
            i += 1
            continue

        # Numbered list / TOC entry: "1. Item", "1.1. Item", etc.  Each
        # entry stays on its own line (don't merge into a paragraph).
        if re.match(r"^\d+(\.\d+)*\.\s+\S", stripped):
            out.append(BODY_INDENT + strip_inline(stripped))
            i += 1
            continue

        # Tables: '| ... | ... |' header row, followed by separator '|---|...'
        if stripped.startswith("|") and i + 1 < len(lines) and re.match(
            r"^\|[\s:|-]+\|$", lines[i + 1].strip()
        ):
            rows: list[list[str]] = []
            while i < len(lines) and lines[i].lstrip().startswith("|"):
                row_line = lines[i].strip()
                if re.match(r"^\|[\s:|-]+\|$", row_line):
                    i += 1
                    continue
                cells = [c.strip() for c in row_line.strip("|").split("|")]
                rows.append(cells)
                i += 1
            if out and out[-1] != "":
                out.append("")
            out.extend(render_table(rows))
            out.append("")
            continue

        # Bullet list: "- ..." → "   o  ..."
        m = re.match(r"^-\s+(.*)$", stripped)
        if m:
            bullet_indent = BODY_INDENT + "o  "
            cont_indent = BODY_INDENT + "   "
            buf = strip_inline(m.group(1))
            i += 1
            # Continuation lines (indented more than bullet origin).
            while i < len(lines) and lines[i].startswith("  ") and lines[i].strip():
                buf += " " + strip_inline(lines[i].strip())
                i += 1
            wrapped = textwrap.wrap(
                buf,
                width=LINE_WIDTH - len(bullet_indent),
                break_long_words=False,
                break_on_hyphens=False,
            )
            if not wrapped:
                wrapped = [""]
            out.append(bullet_indent + wrapped[0])
            for ln in wrapped[1:]:
                out.append(cont_indent + ln)
            continue

        # Blank line → paragraph boundary.
        if stripped == "":
            if out and out[-1] != "":
                out.append("")
            i += 1
            continue

        # Plain paragraph: gather contiguous non-blank, non-special lines.
        para = [stripped]
        i += 1
        while (
            i < len(lines)
            and lines[i].strip()
            and not lines[i].lstrip().startswith(("#", "```", "|", "- ", "---"))
        ):
            para.append(lines[i].strip())
            i += 1
        prose = strip_inline(" ".join(para))
        out.extend(wrap_paragraph(prose, BODY_INDENT))

    # Collapse runs of blank lines to a single blank.
    cleaned: list[str] = []
    for ln in out:
        if ln == "" and cleaned and cleaned[-1] == "":
            continue
        cleaned.append(ln)
    # Trim leading/trailing blanks.
    while cleaned and cleaned[0] == "":
        cleaned.pop(0)
    while cleaned and cleaned[-1] == "":
        cleaned.pop()
    return cleaned


def split_page_one(content: list[str]) -> tuple[list[str], list[str]]:
    """Locate the boundary between page 1 (cover) and page 2+ body.

    Page 1 holds the cover (title, abstract, status, copyright).  We
    pick the last paragraph break (blank line) that fits within
    PAGE_LINES - 2 lines, so the footer lands on PAGE_LINES with at
    least one blank above it.  If the cover overruns even that, the
    BCP 78 / Trust legal-provisions paragraph naturally spills to
    page 2 — matching the IETF convention.
    """
    target = PAGE_LINES - 2
    cut = None
    for i in range(min(len(content), target), 0, -1):
        if i < len(content) and content[i] == "":
            cut = i
            break
    if cut is None:
        # No blank found — fall back to truncating at target.
        cut = min(target, len(content))
    page1 = content[:cut]
    while page1 and page1[-1] == "":
        page1.pop()
    rest = content[cut:]
    while rest and rest[0] == "":
        rest.pop(0)
    return page1, rest


def paginate(content: list[str]) -> str:
    """Lay out 'content' as a 56-line-per-page IETF I-D plain text."""
    page1, rest = split_page_one(content)

    out: list[str] = []
    out.extend(page1)
    # Pad page 1 to PAGE_LINES - 1 lines with blanks, then footer.
    # Convention: at least one blank line between final content and the
    # footer.  If page 1 content extends all the way to that line, drop
    # one trailing line to make room (rare).
    while len(out) < PAGE_LINES - 1:
        out.append("")
    if out and out[-1].strip() != "":
        out.pop()
        out.append("")
    out.append(make_footer(1))

    BREAK_BLOCK = ["", BANNER, "", ""]      # 4 lines under previous footer
    PAGE_BODY = PAGE_LINES - len(BREAK_BLOCK) - 1   # 51

    page_n = 2
    idx = 0
    while idx < len(rest):
        out.extend(BREAK_BLOCK)
        chunk = rest[idx : idx + PAGE_BODY]
        idx += PAGE_BODY

        # Avoid ending a page on a section heading: detect a numbered
        # heading at the bottom and push it forward so it leads the next
        # page.
        if (
            idx < len(rest)
            and chunk
            and re.match(r"^\d+(\.\d+)*\.\s+\S", chunk[-1])
        ):
            idx -= 1
            chunk = chunk[:-1]
        # Avoid breaking immediately after a section heading: if the
        # heading is the LAST non-blank line of this chunk, push it forward.
        non_blank = [j for j, l in enumerate(chunk) if l.strip()]
        if non_blank:
            last = non_blank[-1]
            if (
                last >= len(chunk) - 2
                and idx < len(rest)
                and re.match(r"^\d+(\.\d+)*\.\s+\S", chunk[last])
            ):
                # Trim trailing lines back to before the heading.
                idx -= len(chunk) - last
                chunk = chunk[:last]

        # Ensure at least one blank line between final content and the
        # footer.  If the chunk filled completely with the last line
        # being content, push that line back to the next page.
        if len(chunk) == PAGE_BODY and chunk and chunk[-1].strip() != "":
            idx -= 1
            chunk = chunk[:-1]
        while len(chunk) < PAGE_BODY:
            chunk.append("")
        out.extend(chunk)
        out.append(make_footer(page_n))
        page_n += 1

    return "\n".join(out) + "\n"


def main() -> int:
    if len(sys.argv) != 2:
        sys.stderr.write(f"usage: {sys.argv[0]} draft.md\n")
        return 2
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        md = f.read()
    rendered = render(md)
    output = paginate(rendered)
    sys.stdout.write(output)
    # Lint pass: flag any output line over LINE_WIDTH columns.  These
    # always reflect over-length content in the source .md (long URLs,
    # uncommented identifiers in code blocks, etc.) — the renderer does
    # not silently mangle them.  Reporting on stderr keeps the redirect-
    # to-file workflow clean.
    long_lines = [
        (i + 1, len(ln))
        for i, ln in enumerate(output.split("\n"))
        if len(ln) > LINE_WIDTH
    ]
    if long_lines:
        sys.stderr.write(
            f"warning: {len(long_lines)} output line(s) exceed "
            f"{LINE_WIDTH} columns; .md source needs editing:\n"
        )
        for n, w in long_lines:
            sys.stderr.write(f"  line {n}: {w} cols\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
