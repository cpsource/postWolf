---
name: iranian
description: Cross-check a Western news claim, US official statement, or media framing against what the Iranian Farsi-language press is saying about the same event. Use whenever the user asks to verify, fact-check, cross-reference, or sanity-check a Western/US statement against Iranian sources, or says things like "is this true", "what does the Iranian press say", "check this against Farsi sources", or "does Iran agree with this". Also use when the user pastes a Western article about Iran, the Middle East, US-Iran negotiations, the Strait of Hormuz, sanctions, the nuclear program, or related topics and wants the Iranian-side perspective. Gathers raw Farsi articles from major Iranian outlets representing different factions (establishment, reformist, IRGC-aligned, hardline) and packages them for analysis in Claude.ai.
---

# Iranian Press Check

This skill cross-checks a Western/US claim about Iran against what the Iranian Farsi-language press is reporting on the same topic. It gathers raw Farsi articles from outlets across the factional spectrum, packages them for review, and leaves the analytical work to be done in Claude.ai where conversational back-and-forth is easier.

## When to use this skill

Use this skill whenever:
- The user pastes a Western article about Iran and wants the Iranian perspective
- The user asks "is this true" or "what does the Iranian press say" about a statement involving Iran
- A US official statement, Trump quote, or Western framing needs cross-checking
- The user is researching Iran-US negotiations, the Strait of Hormuz, sanctions, the nuclear program, the 2026 war, or related topics

The skill is most valuable for *contested or one-sided* Western reporting where the Iranian press is likely to have a different framing.

## Core philosophy

The point is **not** to declare one side right. The point is to surface what each side's press is actually saying, so the user can see the territory between them. Iranian state media has its own biases; Western media has its own. The value comes from juxtaposition, not from picking a winner.

This skill is the **fetch layer**. The analysis layer is the user pasting the gathered material into Claude.ai for conversational analysis.

## Workflow

### Step 1: Extract the claim

Identify the specific factual claim or framing to check. Examples:

- "Trump threatened to bomb Oman if it doesn't cooperate"
- "Iran agreed to a 60-day ceasefire MOU"
- "The US will lift sanctions in exchange for strait demining"
- "Iran is enriching uranium to near-weapons grade"

Narrow it down to one or two specific claims. If the user pastes a long article, ask which claims they most want checked. Vague claims ("Iran is bad") aren't checkable; specific factual or quote-attribution claims are.

### Step 2: Identify relevant Iranian outlets

See `references/iranian_press_landscape.md` for the full landscape and which outlets represent which factions. Aim to gather from **at least 3 outlets across factions** to get genuine triangulation, not just one perspective.

A good default spread:
- One establishment voice (e.g., `irannewspaper.ir` or `en.irna.ir`)
- One reformist voice (e.g., `sharghdaily.com` or `etemadnewspaper.ir`)
- One IRGC-aligned voice (e.g., `tasnimnews.com` or `farsnews.ir`)
- Optionally one hardline voice (e.g., `kayhan.ir`)

### Step 3: Run the fetch script

```bash
python3 scripts/fetch_press.py --claim "the claim text" --outlets establishment,reformist,irgc
```

Or with explicit URLs if the user has specific articles in mind:

```bash
python3 scripts/fetch_press.py --urls https://www.tasnimnews.com/fa/news/... https://sharghdaily.com/...
```

Or search-based:

```bash
python3 scripts/fetch_press.py --search "تنگه هرمز" --outlets all
```

The script writes raw Farsi text and (optionally) machine translations to a timestamped output directory. It does NOT do analysis — that's the user's next step.

### Step 3.5: Check loaded terminology (do not let translation bury the story)

Some Farsi political terms do not survive machine translation — and the distinction the
translator collapses is often *the actual finding*. The canonical case: a Western source says
the sides reached a **"deal,"** but Iranian sources say **تفاهم‌نامه** (a non-binding
*memorandum of understanding*). Google Translate renders both as "agreement," and the gap —
binding vs non-binding — disappears. Same for rhetorically loaded terms like **فضاسازی**
("atmosphere-building" = spin / manufactured hype), which the translator flattens into
something neutral.

**Rule: when a Western claim uses a strong word (deal, agreement, ceasefire, lift sanctions)
and the Iranian source uses a weaker or differently-loaded Farsi word, that gap is a finding.
Report it explicitly — do not let it dissolve into a translation.**

The fetch script scans fetched text against `references/loaded_terms_glossary.md` and emits a
**"Loaded terminology detected"** section plus a **"Terminology gap check"** against the claim
in the handoff. Read those sections before packaging, and surface any real gap to the user.
See `references/loaded_terms_glossary.md` for the full term tables and the report format.

### Step 4: Package the results

After fetching, summarize for the user what was found:

- How many articles from how many outlets
- The headlines (with quick gist translations)
- Which factional perspectives are represented
- Any outlets that failed to respond (genuinely common with Iranian sites)

Then output a single `claude-ai-handoff.md` file containing:
- The original claim being checked
- The headlines and excerpts from each outlet, with Farsi original AND machine translation
- The loaded-terminology scan and any terminology gap against the claim (see Step 3.5)
- A note pointing to the directory with the full articles for deeper analysis

Tell the user explicitly: "Paste this handoff file (or the specific articles you want analyzed) into Claude.ai for the analysis step."

### Step 5: Do NOT analyze in Claude Code

This is the key architectural choice. Claude Code is good at the fetch-and-store mechanics; Claude.ai is better at the conversational analysis (translating dense political essays, weighing factional signals, comparing framings turn by turn). When the user asks for analysis in Claude Code, gently redirect: "I've gathered the material. The analysis flows better in claude.ai — paste the handoff file there and we'll work through it."

Exception: if the user explicitly insists on analyzing in Claude Code, do it, but note that the conversational rhythm will be less fluid.

## Timing your run (time zones + publication cutoffs)

*Applicable as of 2026-06-17. The facts below can drift — re-verify if Iran reinstates DST (it
dropped it in 2022), if the user relocates from US Eastern, or if the Iranian working week
changes. Convert any clock advice to the user's actual time zone before giving it.*

The high-signal content (front-page framing, named editorials like Shariatmadari's Kayhan
notes, reformist op-eds) is set by the **morning-paper print cycle**, not posted continuously —
so *when* you fetch materially changes what you catch.

**Time-zone facts:**
- Iran (IRST) = **UTC+3:30, no DST** (fixed offset year-round).
- US Eastern: **EDT = UTC−4** (summer) → Iran is **7.5 h ahead**; **EST = UTC−5** (winter) →
  Iran is **8.5 h ahead**. Iran does not shift with US DST, so the ideal Eastern clock time
  moves by an hour at each US changeover.

**Iranian publication rhythm:**
- Dailies are **morning papers**. Editorial/front-page content locks at the **night print
  deadline (~11 PM–1 AM Tehran)** and is fully online by **early morning Tehran (~6–7 AM)**.
- Wires (Fars, Tasnim, IRNA) run all day, peaking through the Tehran work day (~8 AM–8 PM);
  official statements cluster in the afternoon.
- **Weekend is Thursday–Friday.** Friday is the true holiday (thin news, and **most dailies
  print no Friday edition** — so there's no Thursday-night print cycle). Thursday is a de facto
  half/closed day (offices shut, official wire output drops). **Work week is Saturday–Wednesday;
  Wednesday is the last full work day.**

**Recommended run window (default — most complete daily snapshot):**
- **~11:00 AM–12:00 PM EDT** (≈ 6:30–7:30 PM Tehran) → that morning's print editions + a full
  work-day of wire/official copy + afternoon reactions, before the night deadline starts a new
  cycle. In winter, shift to **~10:00 AM EST** for the same Tehran moment.
- **Days: Saturday–Wednesday Eastern.** **Avoid Thursday and (especially) Friday** — those map
  to the Iranian weekend: stale content, quiet officials, no fresh paper.

**Variant — chasing the freshest editorial framing** (next morning's front pages/op-eds hot off
the deadline): run **~4:00–6:00 PM EDT** (≈ midnight Tehran). Trade-off: you gain tomorrow's
framing but lose that day's late-afternoon wire reactions. For fast-moving wire stories
(contested-interpretation fights playing out hour to hour), prefer the default 11 AM window.

## Practical fetch notes

Iranian sites can be tricky to fetch. The script handles common cases but be aware:

**User agent matters.** Many Iranian sites block default `curl` or `requests` user agents. The script sends a realistic browser user agent by default.

**Encoding.** Most modern Iranian sites are UTF-8, but legacy pages can be Windows-1256. The script auto-detects via `chardet`.

**Reachability is intermittent.** Sometimes a site is up; sometimes it isn't. Iran has had network disruptions (the 88-day blackout that ended late May 2026). Don't assume failure means the site is down forever — try again later, try a different outlet, or fall back to the English edition.

**RSS where possible.** Some outlets (Tasnim is good for this) publish RSS feeds. The script checks for these first since they're more stable than scraping HTML.

**English editions as fallback.** Most major outlets have English editions (en.irna.ir, en.farsnews.ir, en.tasnimnews.com, presstv.ir). These are *curated for foreign audiences* and miss content that's only in Farsi — but they're better than nothing when the Farsi site won't load.

**Be polite.** Don't hammer the sites. The script sleeps between requests. Iranian outlets are news organizations, not data sources.

## What this skill does NOT do

- It does not declare Iranian sources more truthful than Western ones (or vice versa).
- It does not translate dense political-religious essays reliably — machine translation will mangle Mohajerani-style philosophical writing. Use machine translation for the gist; bring the Farsi original to Claude.ai for the real reading.
- It does not replace Iran-watching experts (Amwaj.media, BBC Monitoring, the Stimson Center analysts). For high-stakes work, consult them. This skill is a personal-research-grade tool.
- It does not do anything autonomously beyond fetching. The user remains in the loop.

## Output format

Always produce a `claude-ai-handoff.md` file in the output directory, structured as:

```markdown
# Farsi Press Check: [claim summary]

**Claim being checked:** [the original claim]
**Date:** [timestamp]
**Run timing:** [fetch time in the user's zone + Tehran equivalent, e.g. "2026-06-17 11:20 EDT ≈ 18:50 Tehran (Wed)"; note where it falls in the Tehran cycle — work-day/evening/weekend, before/after the night print deadline. See "Timing your run".]
**Outlets queried:** [list]
**Outlets reached:** [list of successful fetches]
**Outlets that failed:** [list]

## [Outlet 1 name] — [factional alignment]

**Headline (Farsi):** [...]
**Headline (machine translation):** [...]
**URL:** [...]

**Article excerpt (Farsi):**
[...]

**Article excerpt (machine translation):**
[...]

**Loaded terminology detected:**
[Glossary hits for this outlet — e.g. تفاهم‌نامه (non-binding MOU), فضاسازی (spin). Auto-generated.]

---

## [Outlet 2 name] — ...

[same structure]

---

## Terminology gap check

[Auto-generated. Where a Western strong word (deal/ceasefire/lift sanctions) maps to a weaker
or differently-loaded Farsi word, it's flagged here as a finding. See loaded_terms_glossary.md.]

---

## Notes for Claude.ai analysis

[Any quick observations about what was found vs. expected, factional spread, what's missing, etc. Do NOT analyze — just observe what was gathered.]
```

The user takes this file to Claude.ai. That's the handoff.

## See also

- `README.md` — Design notes and the MOU-vs-"deal" / 36-hour-lead case study
- `references/iranian_press_landscape.md` — Full outlet directory by faction
- `references/loaded_terms_glossary.md` — Farsi terms that don't survive machine translation
- `scripts/fetch_press.py` — The actual fetch implementation
