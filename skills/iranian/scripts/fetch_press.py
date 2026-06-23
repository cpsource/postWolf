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

# ---------------------------------------------------------------------------
# Loaded-terms glossary — keep in sync with references/loaded_terms_glossary.md
#
# These Farsi terms do not survive machine translation; the distinction the
# translator collapses is often the actual finding (e.g. تفاهم‌نامه = non-binding
# MOU vs توافق = agreement, both rendered "agreement" by Google Translate).
# Each entry: (farsi_variants, translit, neutral_gloss, what_it_signals)
# ---------------------------------------------------------------------------

GLOSSARY = [
    # --- Agreement strength (the most important axis) ---
    (["تفاهم‌نامه", "تفاهم نامه"], "tafāhom-nāmeh", "memorandum of understanding (MOU)",
     "Non-binding. Deliberately weaker than a treaty — signals nothing binding was conceded."),
    (["تفاهم"], "tafāhom", "understanding",
     "Mutual understanding. Non-binding; no obligations created."),
    (["توافق‌نامه", "توافق نامه"], "tavāfoq-nāmeh", "agreement document",
     "Written agreement on terms — stronger than تفاهم."),
    (["توافق"], "tavāfoq", "agreement / accord",
     "The sides actually agreed on terms. Stronger than تفاهم (merely 'understood')."),
    (["قرارداد"], "qarārdād", "contract",
     "Binding contract with obligations."),
    (["معاهده"], "moʿāhede", "treaty",
     "Formal, binding, usually ratified — the strongest commitment word."),
    # --- Cessation of hostilities ---
    (["آتش‌بس", "آتش بس"], "ātash-bas", "ceasefire",
     "A ceasefire proper (mutual, negotiated)."),
    (["ترک مخاصمه"], "tark-e mokhāseme", "cessation of hostilities",
     "Legalistic cessation; broader than آتش‌بس."),
    (["توقف"], "tavaqof", "halt / stoppage",
     "A halt — can be unilateral, temporary, conditional. Weaker than a ceasefire."),
    (["وقفه"], "vaqfe", "pause / interlude",
     "A pause; implies hostilities may resume."),
    # --- Sanctions ---
    (["لغو تحریم"], "laghv-e tahrim", "lifting of sanctions",
     "PERMANENT removal — the maximal Iranian demand."),
    (["تعلیق تحریم"], "taʿliq-e tahrim", "suspension of sanctions",
     "TEMPORARY, reversible suspension — a much smaller concession than لغو."),
    (["رفع تحریم"], "rafʿ-e tahrim", "removal of sanctions",
     "Removal of sanctions' effect."),
    # --- Nuclear ---
    (["حق مسلم"], "haqq-e mosallam", "inalienable right",
     "'Our inalienable right [to enrich]' — non-negotiable framing."),
    (["تعلیق غنی‌سازی", "تعلیق غنی سازی"], "taʿliq-e ghani-sāzi", "suspension of enrichment",
     "A major concession term — significant if an Iranian source uses it approvingly."),
    (["غنی‌سازی", "غنی سازی"], "ghani-sāzi", "enrichment",
     "Uranium enrichment."),
    # --- Rhetorically loaded / pejorative register ---
    (["فضاسازی", "فضا سازی"], "fazā-sāzi", "'atmosphere-building'",
     "SPIN / manufactured hype. Pejorative — a tell that the outlet is dismissing a claim as propaganda."),
    (["جنگ روانی"], "jang-e ravāni", "psychological war",
     "Frames the other side's messaging as an attack. Dismissive."),
    (["بزرگ‌نمایی", "بزرگ نمایی"], "bozorg-namāyi", "'magnification'",
     "Exaggeration / blowing out of proportion. Dismissive."),
    (["تجاوز"], "tajāvoz", "aggression / assault",
     "Casts the other side as the aggressor (vs neutral حمله 'attack'). Editorial."),
    (["استکبار"], "estekbār", "'arrogance'",
     "'Global arrogance' = the US-led West. Ideological in-group framing."),
    (["شیطان بزرگ"], "sheytān-e bozorg", "'Great Satan'",
     "= the US. Maximal-hostility register."),
    (["مقاومت"], "moqāvemat", "'the Resistance'",
     "The Axis of Resistance. Approving in-group framing."),
    (["پاسخ کوبنده"], "pāsokh-e koubande", "'crushing response'",
     "Threat-rhetoric register."),
    (["نفوذ"], "nofuz", "'infiltration'",
     "Used to smear negotiators/reformists as foreign agents — a hardline attack term."),
    (["بصیرت"], "basirat", "'insight / discernment'",
     "Loyalty-signalling buzzword."),
    (["خط قرمز"], "khatt-e qermez", "red line",
     "Non-negotiable limit."),
    # --- Negotiation framing ---
    (["مذاکره غیرمستقیم", "مذاکره غیر مستقیم"], "mozākere-ye gheyr-e mostaqim", "indirect negotiation",
     "Indirect talks (via mediator) — Iran often insists on this framing to avoid the optics of direct US talks. Politically load-bearing."),
    (["مذاکره مستقیم"], "mozākere-ye mostaqim", "direct negotiation",
     "Direct talks — often refused by Iran for domestic reasons."),
]

# English trigger words in a Western claim, mapped to the Farsi commitment spectrum the
# analyst should verify. Used by the "Terminology gap check" section.
CLAIM_TRIGGERS = [
    (["deal", "agreement", "accord", "pact"],
     "Western 'deal/agreement' — check whether the Iranian source uses توافق/قرارداد (a real "
     "agreement) or only تفاهم/تفاهم‌نامه (a non-binding understanding/MOU). That gap is a finding."),
    (["ceasefire", "truce", "armistice"],
     "Western 'ceasefire' — check whether the Iranian source uses آتش‌بس (true ceasefire) or only "
     "توقف/وقفه (a halt/pause). A weaker word signals they decline to call it a mutual ceasefire."),
    (["lift sanctions", "lifting sanctions", "sanctions relief", "remove sanctions", "ease sanctions"],
     "Western 'lift/relief sanctions' — check whether the Iranian source uses لغو (PERMANENT removal) "
     "or تعلیق (TEMPORARY suspension). These are very different concessions."),
    (["surrender", "capitulate", "capitulation", "concede", "concession"],
     "Western 'surrender/concede' — Iranian sources rarely use such terms; check what word they "
     "actually use and whether the framing is being inverted for the domestic audience."),
    (["halt enrichment", "stop enrichment", "suspend enrichment", "end enrichment"],
     "Western 'halt enrichment' — check for تعلیق غنی‌سازی (a major concession) vs reaffirmation of "
     "حق مسلم ('inalienable right'), which signals refusal."),
]


def scan_loaded_terms(text: str) -> list[dict]:
    """Scan Farsi text for glossary terms. Returns matched entries with counts, most-specific
    first (longer terms checked before their substrings so تفاهم‌نامه wins over تفاهم)."""
    if not text:
        return []
    hits = {}
    for variants, translit, gloss, signal in GLOSSARY:
        count = sum(text.count(v) for v in variants)
        if count:
            key = translit
            if key not in hits:
                hits[key] = {
                    "fa": variants[0],
                    "translit": translit,
                    "gloss": gloss,
                    "signal": signal,
                    "count": count,
                }
    # Suppress a shorter term's count that is wholly contained in a longer matched term,
    # to avoid double-reporting تفاهم inside every تفاهم‌نامه.
    matched_fa = {h["fa"] for h in hits.values()}
    for h in list(hits.values()):
        for other in matched_fa:
            if other != h["fa"] and h["fa"] in other:
                # shorter term subsumed by a longer matched term; keep but note overlap
                h["subsumed_by"] = other
    return sorted(hits.values(), key=lambda h: -h["count"])


def claim_gap_checks(claim: str) -> list[str]:
    """Return terminology-gap prompts triggered by English words in the Western claim."""
    if not claim:
        return []
    low = claim.lower()
    out = []
    for triggers, note in CLAIM_TRIGGERS:
        if any(t in low for t in triggers):
            out.append(note)
    return out


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

TIMEOUT = 20  # seconds (default connect+read timeout)
# Iranian sites are intermittently slow to *accept* a connection (network
# disruptions, overloaded servers). On a connect timeout we don't give up
# immediately — we retry the connection once with a longer connect timeout.
CONNECT_RETRY_TIMEOUT = 60  # seconds; connect timeout for the single retry
SLEEP_BETWEEN = 1.5  # be polite

# Hard cap on how much of any single page we pull into memory. This box has very
# little RAM, and an unbounded download (a bloated homepage, an inline data blob,
# or a misbehaving response) plus the decode + several full-size regex copies in
# extract_*() is enough to trigger the OOM killer. Streaming to this cap bounds the
# peak. 5 MB is far more HTML than any real article/homepage needs — the excess is
# scripts and tracking junk we strip anyway. Tunable via --max-html-mb.
MAX_HTML_BYTES = 5 * 1024 * 1024


# ---------------------------------------------------------------------------
# Fetching
# ---------------------------------------------------------------------------

def fetch(url: str) -> tuple[bool, str, str]:
    """Fetch a URL, capping how much is read into memory. Returns (success, text_or_error, final_url)."""
    # First attempt uses the normal timeout. If the *connection* times out (not a
    # read/HTTP error), Iranian sites often just need more patience — retry once
    # with a 60 s connect timeout before declaring failure.
    attempts = (TIMEOUT, (CONNECT_RETRY_TIMEOUT, TIMEOUT))
    resp = None
    for i, to in enumerate(attempts):
        try:
            resp = requests.get(url, headers=HEADERS, timeout=to,
                                allow_redirects=True, stream=True)
            break
        except requests.exceptions.ConnectTimeout as e:
            if i + 1 < len(attempts):
                print(f"    [warn] connect timed out; retrying once with "
                      f"{CONNECT_RETRY_TIMEOUT}s connect timeout", file=sys.stderr)
                continue
            return False, f"Request failed: {e}", url
        except requests.exceptions.RequestException as e:
            return False, f"Request failed: {e}", url

    with resp:  # ensure the connection is released even if we stop reading early
        if resp.status_code != 200:
            return False, f"HTTP {resp.status_code}", resp.url

        # Read at most MAX_HTML_BYTES so a giant or runaway response can't exhaust RAM.
        chunks = []
        total = 0
        truncated = False
        try:
            for chunk in resp.iter_content(chunk_size=65536):
                if not chunk:
                    continue
                chunks.append(chunk)
                total += len(chunk)
                if total >= MAX_HTML_BYTES:
                    truncated = True
                    break
        except requests.exceptions.RequestException as e:
            return False, f"Request failed mid-stream: {e}", resp.url
        raw = b"".join(chunks)

        if truncated:
            print(f"    [warn] page exceeded {MAX_HTML_BYTES // (1024 * 1024)} MB cap; "
                  f"truncated to first {len(raw)} bytes", file=sys.stderr)

        # Encoding detection — Iranian sites are mostly UTF-8 but not all. Detect over
        # the (already capped) bytes so this stays bounded too.
        encoding = resp.encoding
        if chardet is not None and (not encoding or encoding.lower() == "iso-8859-1"):
            detected = chardet.detect(raw)
            if detected and detected.get("encoding"):
                encoding = detected["encoding"]
        if not encoding:
            encoding = "utf-8"

        return True, raw.decode(encoding, errors="replace"), resp.url


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
    parser.add_argument("--max-html-mb", type=float, default=None,
                        help="Per-page download cap in MB (memory guard; default 5). "
                             "Lower it on very small machines.")
    args = parser.parse_args()

    if args.max_html_mb is not None:
        global MAX_HTML_BYTES
        MAX_HTML_BYTES = int(args.max_html_mb * 1024 * 1024)

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
            loaded = scan_loaded_terms(article_text)
            if loaded:
                print(f"    [terms] {len(loaded)} loaded term(s): "
                      f"{', '.join(h['translit'] for h in loaded[:5])}")
            results.append({
                "outlet": urllib.parse.urlparse(url).netloc,
                "faction": "unknown",
                "url": final_url,
                "status": "ok",
                "headline_fa": "",  # could extract <title> here
                "headline_en": "",
                "article_fa": article_text,
                "article_en": translated,
                "loaded_terms": loaded,
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
            # Scan all headline text (homepage crawl has no article body) for loaded terms.
            loaded = scan_loaded_terms(" ".join(h["headline"] for h in headlines))
            if loaded:
                print(f"    [terms] {len(loaded)} loaded term(s): "
                      f"{', '.join(h['translit'] for h in loaded[:5])}")
            outlet_result["loaded_terms"] = loaded
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

        loaded = r.get("loaded_terms") or []
        if loaded:
            lines.append("**Loaded terminology detected** (don't trust the machine translation on these):")
            lines.append("")
            for h in loaded:
                note = f" — _also matched inside {h['subsumed_by']}_" if h.get("subsumed_by") else ""
                lines.append(
                    f"- **{h['fa']}** ({h['translit']}, ×{h['count']}) — "
                    f"\"{h['gloss']}\". {h['signal']}{note}"
                )
            lines.append("")
        lines.append("---")
        lines.append("")

    # Terminology gap check — surface as a finding, not buried in translation.
    gap_notes = claim_gap_checks(claim)
    all_terms = {}
    for r in reached:
        for h in (r.get("loaded_terms") or []):
            if h.get("subsumed_by"):
                continue
            entry = all_terms.setdefault(h["translit"], {"fa": h["fa"], "gloss": h["gloss"],
                                                          "signal": h["signal"], "outlets": set()})
            entry["outlets"].add(r["outlet"])
    if gap_notes or all_terms:
        lines.append("## Terminology gap check")
        lines.append("")
        lines.append("Machine translation collapses Farsi distinctions that are often the actual "
                     "story (e.g. تفاهم‌نامه = non-binding MOU vs توافق = agreement). Treat any "
                     "gap below as a **finding**, not a translation artifact.")
        lines.append("")
        if gap_notes:
            lines.append("**Triggered by the Western claim — verify against the Farsi above:**")
            lines.append("")
            for n in gap_notes:
                lines.append(f"- {n}")
            lines.append("")
        if all_terms:
            lines.append("**Loaded terms found across outlets:**")
            lines.append("")
            for translit, e in sorted(all_terms.items(), key=lambda kv: -len(kv[1]["outlets"])):
                outlets = ", ".join(sorted(e["outlets"]))
                lines.append(f"- **{e['fa']}** ({translit}) — \"{e['gloss']}\". {e['signal']} "
                             f"_[{outlets}]_")
            lines.append("")
        lines.append("---")
        lines.append("")

    lines.append("## Notes for Claude.ai analysis")
    lines.append("")
    lines.append("- Machine translation above is rough. For dense political/religious essays, send the Farsi original to Claude.ai for a careful read.")
    lines.append("- **Terminology:** if a Western 'deal/ceasefire/lift sanctions' maps to a weaker Farsi word (تفاهم‌نامه / توقف / تعلیق), say so explicitly — that gap is a finding. See the Terminology gap check above and `references/loaded_terms_glossary.md`.")
    lines.append("- Compare factional spread: does establishment, reformist, IRGC, hardline all agree, or do they diverge?")
    lines.append("- Note what's *missing*: a story prominent in Western press that's silent in Iranian press (or vice versa) is itself informative.")
    lines.append("- Check whether any outlets failed to respond — Iranian sites are sometimes intermittent.")
    lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    main()
