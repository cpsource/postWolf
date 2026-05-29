#!/usr/bin/env python3
"""
fetch_press.py — Gather articles from Iranian Farsi-language press for cross-checking
a Western claim. Outputs a handoff file for analysis in Claude.ai.

Usage:
    python3 fetch_press.py --claim "Trump threatened to bomb Oman" --outlets all
    python3 fetch_press.py --search "تنگه هرمز" --outlets irgc
    python3 fetch_press.py --urls https://www.tasnimnews.com/fa/news/... https://sharghdaily.com/...

This script does NOT analyze. It fetches and packages.
"""

import argparse
import datetime as dt
import json
import os
import re
import sys
import time
import urllib.parse
from pathlib import Path

try:
    import requests
except ImportError:
    sys.exit("Missing dependency: pip install --break-system-packages requests chardet")

try:
    import chardet
except ImportError:
    chardet = None  # encoding detection optional but recommended

# Optional: machine translation. Falls back gracefully if unavailable.
TRANSLATOR_AVAILABLE = False
try:
    from deep_translator import GoogleTranslator
    TRANSLATOR_AVAILABLE = True
except ImportError:
    pass  # silent — handoff file will note translation unavailable


# ---------------------------------------------------------------------------
# Outlet directory — keep in sync with references/iranian_press_landscape.md
# ---------------------------------------------------------------------------

OUTLETS = {
    # faction -> list of (name, base_url, optional_rss_url)
    "establishment": [
        ("Iran Newspaper", "https://www.irannewspaper.ir", None),
        ("IRNA", "https://www.irna.ir", "https://www.irna.ir/rss"),
        ("IRNA English", "https://en.irna.ir", None),
    ],
    "reformist": [
        ("Shargh", "https://www.sharghdaily.com", None),
        ("Etemad", "https://www.etemadnewspaper.ir", None),
        ("Jamaran", "https://www.jamaran.news", None),
    ],
    "irgc": [
        ("Tasnim", "https://www.tasnimnews.com", "https://www.tasnimnews.com/fa/rss/feed/0/8/0/"),
        ("Fars News", "https://www.farsnews.ir", "https://www.farsnews.ir/rss"),
        ("Javan", "https://www.javanonline.ir", None),
        ("Mashregh", "https://www.mashreghnews.ir", None),
    ],
    "hardline": [
        ("Kayhan", "https://www.kayhan.ir", None),
        ("Vatan-e Emrooz", "https://www.vatanemrooz.ir", None),
    ],
    "economic": [
        ("Donya-ye Eqtesad", "https://www.donya-e-eqtesad.com", None),
    ],
    "opposition": [
        ("Iran International", "https://www.iranintl.com/en", None),
        ("BBC Persian", "https://www.bbc.com/persian", None),
    ],
}

DEFAULT_SPREAD = [
    ("IRNA", "https://www.irna.ir", "https://www.irna.ir/rss"),
    ("Shargh", "https://www.sharghdaily.com", None),
    ("Tasnim", "https://www.tasnimnews.com", "https://www.tasnimnews.com/fa/rss/feed/0/8/0/"),
    ("Kayhan", "https://www.kayhan.ir", None),
]

# Browser-ish user agent. Many Iranian sites reject default requests/curl UAs.
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "fa,en-US;q=0.7,en;q=0.3",
}

TIMEOUT = 20  # seconds
SLEEP_BETWEEN = 1.5  # be polite


# ---------------------------------------------------------------------------
# Fetching
# ---------------------------------------------------------------------------

def fetch(url: str) -> tuple[bool, str, str]:
    """Fetch a URL. Returns (success, text_or_error, final_url)."""
    try:
        resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True)
    except requests.exceptions.RequestException as e:
        return False, f"Request failed: {e}", url

    if resp.status_code != 200:
        return False, f"HTTP {resp.status_code}", resp.url

    # Encoding detection — Iranian sites are mostly UTF-8 but not all.
    if chardet is not None and (not resp.encoding or resp.encoding.lower() == "iso-8859-1"):
        detected = chardet.detect(resp.content)
        if detected and detected.get("encoding"):
            resp.encoding = detected["encoding"]

    return True, resp.text, resp.url


def extract_headlines_and_excerpts(html: str, base_url: str, max_items: int = 8) -> list[dict]:
    """
    Best-effort extraction without a full parser. Looks for common headline patterns:
    <h1>, <h2>, <h3> tags, and anchor texts that look like headlines.
    Returns a list of dicts: {headline, url, excerpt}.
    """
    results = []
    seen = set()

    # Strip script/style blocks first to avoid junk text
    cleaned = re.sub(r"<script[^>]*>.*?</script>", "", html, flags=re.DOTALL | re.IGNORECASE)
    cleaned = re.sub(r"<style[^>]*>.*?</style>", "", cleaned, flags=re.DOTALL | re.IGNORECASE)

    # Pattern 1: <hN>...<a href="...">TEXT</a>...</hN>
    pattern_h_a = re.compile(
        r'<h[1-4][^>]*>\s*<a[^>]*href="([^"]+)"[^>]*>(.*?)</a>\s*</h[1-4]>',
        flags=re.DOTALL | re.IGNORECASE,
    )
    for m in pattern_h_a.finditer(cleaned):
        href, text = m.group(1), strip_tags(m.group(2)).strip()
        if not text or len(text) < 12:
            continue
        full_url = urllib.parse.urljoin(base_url, href)
        if full_url in seen:
            continue
        seen.add(full_url)
        results.append({"headline": text, "url": full_url, "excerpt": ""})
        if len(results) >= max_items:
            return results

    # Pattern 2: <a class="...title..." href="...">TEXT</a>
    pattern_title_a = re.compile(
        r'<a[^>]*class="[^"]*(?:title|headline|tit)[^"]*"[^>]*href="([^"]+)"[^>]*>(.*?)</a>',
        flags=re.DOTALL | re.IGNORECASE,
    )
    for m in pattern_title_a.finditer(cleaned):
        href, text = m.group(1), strip_tags(m.group(2)).strip()
        if not text or len(text) < 12:
            continue
        full_url = urllib.parse.urljoin(base_url, href)
        if full_url in seen:
            continue
        seen.add(full_url)
        results.append({"headline": text, "url": full_url, "excerpt": ""})
        if len(results) >= max_items:
            return results

    # Pattern 3: bare <hN>TEXT</hN> (no link inside)
    pattern_h_only = re.compile(r"<h[1-3][^>]*>(.*?)</h[1-3]>", flags=re.DOTALL | re.IGNORECASE)
    for m in pattern_h_only.finditer(cleaned):
        text = strip_tags(m.group(1)).strip()
        if not text or len(text) < 12 or text in [r["headline"] for r in results]:
            continue
        results.append({"headline": text, "url": "", "excerpt": ""})
        if len(results) >= max_items:
            return results

    return results


def strip_tags(s: str) -> str:
    s = re.sub(r"<[^>]+>", " ", s)
    s = re.sub(r"\s+", " ", s)
    return s.strip()


def extract_article_text(html: str, max_chars: int = 3000) -> str:
    """Extract main article body text. Very rough — strips boilerplate, joins paragraphs."""
    cleaned = re.sub(r"<script[^>]*>.*?</script>", "", html, flags=re.DOTALL | re.IGNORECASE)
    cleaned = re.sub(r"<style[^>]*>.*?</style>", "", cleaned, flags=re.DOTALL | re.IGNORECASE)
    cleaned = re.sub(r"<nav[^>]*>.*?</nav>", "", cleaned, flags=re.DOTALL | re.IGNORECASE)
    cleaned = re.sub(r"<header[^>]*>.*?</header>", "", cleaned, flags=re.DOTALL | re.IGNORECASE)
    cleaned = re.sub(r"<footer[^>]*>.*?</footer>", "", cleaned, flags=re.DOTALL | re.IGNORECASE)

    paragraphs = re.findall(r"<p[^>]*>(.*?)</p>", cleaned, flags=re.DOTALL | re.IGNORECASE)
    text_pieces = []
    for p in paragraphs:
        clean = strip_tags(p)
        if len(clean) > 40:  # skip tiny captions/labels
            text_pieces.append(clean)

    full = "\n\n".join(text_pieces)
    if len(full) > max_chars:
        full = full[:max_chars] + "..."
    return full


# ---------------------------------------------------------------------------
# Translation
# ---------------------------------------------------------------------------

def translate(text: str) -> str:
    """Machine-translate Farsi to English. Returns empty string on failure."""
    if not TRANSLATOR_AVAILABLE or not text.strip():
        return ""
    try:
        # Google Translate has length limits; chunk if needed
        chunks = [text[i:i + 4500] for i in range(0, len(text), 4500)]
        translated_chunks = []
        for chunk in chunks:
            translated_chunks.append(GoogleTranslator(source="fa", target="en").translate(chunk))
            time.sleep(0.3)
        return "\n".join(filter(None, translated_chunks))
    except Exception as e:
        return f"[Translation failed: {e}]"


# ---------------------------------------------------------------------------
# Outlet selection
# ---------------------------------------------------------------------------

def resolve_outlets(spec: str) -> list[tuple[str, str, str | None]]:
    """Turn the --outlets argument into a list of (name, base_url, rss_url)."""
    if not spec or spec == "all":
        return DEFAULT_SPREAD

    selected = []
    for token in spec.split(","):
        token = token.strip().lower()
        if token in OUTLETS:
            selected.extend(OUTLETS[token])
        else:
            print(f"[warn] Unknown outlet group: {token}", file=sys.stderr)

    # Deduplicate by URL
    seen = set()
    unique = []
    for item in selected:
        if item[1] in seen:
            continue
        seen.add(item[1])
        unique.append(item)
    return unique


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--claim", help="The Western claim being cross-checked", default="")
    parser.add_argument("--outlets", help="Outlet groups: establishment,reformist,irgc,hardline,economic,opposition,all", default="all")
    parser.add_argument("--urls", nargs="+", help="Explicit article URLs to fetch instead of crawling")
    parser.add_argument("--search", help="(Currently unused; reserved) Farsi search query", default="")
    parser.add_argument("--output-dir", help="Where to write outputs", default=None)
    parser.add_argument("--no-translate", action="store_true", help="Skip machine translation")
    parser.add_argument("--max-per-outlet", type=int, default=6, help="Max headlines per outlet")
    args = parser.parse_args()

    timestamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    if args.output_dir:
        outdir = Path(args.output_dir)
    else:
        outdir = Path.cwd() / f"farsi-press-check-{timestamp}"
    outdir.mkdir(parents=True, exist_ok=True)

    print(f"[+] Output directory: {outdir}")
    if not TRANSLATOR_AVAILABLE and not args.no_translate:
        print("[!] deep-translator not installed — translations will be skipped.")
        print("    Install with: pip install --break-system-packages deep-translator")

    results = []  # list of dicts to write to handoff file

    if args.urls:
        # Explicit URL mode
        for url in args.urls:
            print(f"[+] Fetching {url}")
            ok, body, final_url = fetch(url)
            if not ok:
                print(f"    [fail] {body}")
                results.append({
                    "outlet": urllib.parse.urlparse(url).netloc,
                    "faction": "unknown",
                    "url": url,
                    "status": "failed",
                    "error": body,
                })
                continue
            article_text = extract_article_text(body)
            translated = translate(article_text) if not args.no_translate else ""
            results.append({
                "outlet": urllib.parse.urlparse(url).netloc,
                "faction": "unknown",
                "url": final_url,
                "status": "ok",
                "headline_fa": "",  # could extract <title> here
                "headline_en": "",
                "article_fa": article_text,
                "article_en": translated,
            })
            # Save raw HTML
            (outdir / f"{sanitize(urllib.parse.urlparse(url).netloc)}.html").write_text(body, encoding="utf-8")
            time.sleep(SLEEP_BETWEEN)
    else:
        # Outlet-crawl mode: hit each outlet's homepage, pull headlines
        outlets = resolve_outlets(args.outlets)
        if not outlets:
            sys.exit("[fatal] No outlets selected.")

        for name, base_url, rss_url in outlets:
            faction = faction_of(name)
            print(f"[+] {name} ({faction}) — {base_url}")
            ok, body, final_url = fetch(base_url)
            if not ok:
                print(f"    [fail] {body}")
                results.append({
                    "outlet": name,
                    "faction": faction,
                    "url": base_url,
                    "status": "failed",
                    "error": body,
                })
                time.sleep(SLEEP_BETWEEN)
                continue

            (outdir / f"{sanitize(name)}.html").write_text(body, encoding="utf-8")
            headlines = extract_headlines_and_excerpts(body, final_url, max_items=args.max_per_outlet)
            print(f"    [ok] {len(headlines)} headlines extracted")

            outlet_result = {
                "outlet": name,
                "faction": faction,
                "url": final_url,
                "status": "ok",
                "headlines": [],
            }
            for h in headlines:
                fa = h["headline"]
                en = translate(fa) if (not args.no_translate and fa) else ""
                outlet_result["headlines"].append({
                    "headline_fa": fa,
                    "headline_en": en,
                    "url": h["url"],
                })
            results.append(outlet_result)
            time.sleep(SLEEP_BETWEEN)

    # Write the handoff markdown file
    handoff_path = outdir / "claude-ai-handoff.md"
    write_handoff(handoff_path, args.claim, results, timestamp)
    print(f"\n[+] Handoff file: {handoff_path}")
    print("[+] Next step: paste the contents of this file into Claude.ai for analysis.")

    # Also write a machine-readable JSON
    json_path = outdir / "results.json"
    json_path.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[+] Machine-readable JSON: {json_path}")


def faction_of(outlet_name: str) -> str:
    for faction, items in OUTLETS.items():
        for name, _, _ in items:
            if name == outlet_name:
                return faction
    return "unknown"


def sanitize(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]", "_", name)


def write_handoff(path: Path, claim: str, results: list[dict], timestamp: str) -> None:
    lines = []
    lines.append(f"# Farsi Press Check")
    lines.append("")
    lines.append(f"**Claim being checked:** {claim or '(no specific claim given)'}")
    lines.append(f"**Timestamp:** {timestamp}")
    lines.append("")

    reached = [r for r in results if r.get("status") == "ok"]
    failed = [r for r in results if r.get("status") == "failed"]
    lines.append(f"**Outlets reached:** {len(reached)}")
    lines.append(f"**Outlets failed:** {len(failed)}")
    if failed:
        lines.append("")
        lines.append("Failures:")
        for r in failed:
            lines.append(f"- {r['outlet']} ({r.get('faction', 'unknown')}): {r.get('error', 'unknown error')}")
    lines.append("")
    lines.append("---")
    lines.append("")

    for r in reached:
        lines.append(f"## {r['outlet']} — *{r.get('faction', 'unknown')}*")
        lines.append("")
        lines.append(f"URL: {r['url']}")
        lines.append("")

        if "headlines" in r:
            for h in r["headlines"]:
                lines.append(f"### {h['headline_fa']}")
                if h.get("headline_en"):
                    lines.append(f"*Translation: {h['headline_en']}*")
                if h.get("url"):
                    lines.append(f"Link: {h['url']}")
                lines.append("")
        elif "article_fa" in r:
            lines.append("**Article (Farsi):**")
            lines.append("")
            lines.append(r["article_fa"])
            lines.append("")
            if r.get("article_en"):
                lines.append("**Article (machine translation):**")
                lines.append("")
                lines.append(r["article_en"])
                lines.append("")
        lines.append("---")
        lines.append("")

    lines.append("## Notes for Claude.ai analysis")
    lines.append("")
    lines.append("- Machine translation above is rough. For dense political/religious essays, send the Farsi original to Claude.ai for a careful read.")
    lines.append("- Compare factional spread: does establishment, reformist, IRGC, hardline all agree, or do they diverge?")
    lines.append("- Note what's *missing*: a story prominent in Western press that's silent in Iranian press (or vice versa) is itself informative.")
    lines.append("- Check whether any outlets failed to respond — Iranian sites are sometimes intermittent.")
    lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    main()
