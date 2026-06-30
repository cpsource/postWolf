# Iranian Press Landscape

Iranian newspapers and news agencies are aligned with specific political factions. Reading across the spectrum is the entire value proposition of this skill.

## By faction

### Establishment / Government

These outlets reflect the position of whichever administration is in power, plus the broader state machinery.

| Outlet | URL (Farsi) | URL (English) | Notes |
|--------|-------------|---------------|-------|
| Iran Newspaper | `www.irannewspaper.ir` | — | IRNA-owned daily, official government voice |
| IRNA | `www.irna.ir` | `en.irna.ir` | State news agency, founded 1934 |
| Hamshahri | `www.hamshahrionline.ir` | — | Tehran municipality paper, large circulation |
| Tehran Times | — | `www.tehrantimes.com` | English daily, conservative-establishment lean |
| Press TV | — | `www.presstv.ir` | State-funded English TV/web, official line |

### Reformist / Pragmatist

These outlets favor engagement with the West, often critical of hardliners and the IRGC. They've been suspended multiple times by Iranian authorities, which is itself a signal of genuine independence within the system.

| Outlet | URL (Farsi) | URL (English) | Notes |
|--------|-------------|---------------|-------|
| Shargh | `www.sharghdaily.com` | — | Flagship reformist daily |
| Etemad | `www.etemadnewspaper.ir` | — | Reformist, similar to Shargh |
| Ham-Mihan | `www.hammihanonline.ir` | — | Newer reformist, Khatami/Rouhani-adjacent |
| Aftab-e Yazd | `www.aftabeyazd.ir` | — | Moderate reformist |
| Jamaran | `www.jamaran.news` | — | Khomeini-family-legacy outlet, reformist-leaning |

### IRGC-aligned / Security Establishment

These outlets reflect the Islamic Revolutionary Guard Corps and security services. They often have the most accurate operational information about military matters AND the most hardline framing.

| Outlet | URL (Farsi) | URL (English) | Notes |
|--------|-------------|---------------|-------|
| Tasnim | `www.tasnimnews.ir` | — | IRGC-aligned wire, founded 2012. **Use `.ir`** — `tasnimnews.com` DNS went dead (apex NODATA, `www`/`en` NXDOMAIN on Cloudflare/foundationdns), verified 2026-06-30. The `.com/en` English edition is gone with it; no working English mirror found. |
| Fars News | `www.farsnews.ir` | `en.farsnews.ir` | IRGC-aligned wire, also has RSS |
| Javan | `www.javanonline.ir` | — | IRGC daily newspaper, editorial voice |
| Sepah News | `www.sepahnews.com` | — | IRGC's own direct news site |
| Mashregh | `www.mashreghnews.ir` | — | Security-services-aligned, hardline-conservative |
| Defa Press | `www.defapress.ir` | — | Military/defense focus, IRGC-affiliated |

### Hardline / Clerical Establishment

These outlets reflect the Supreme Leader's office and the most conservative wing of the establishment. Kayhan in particular is editor-appointed by the Leader's office and operates as a near-official mouthpiece for that perspective.

| Outlet | URL (Farsi) | URL (English) | Notes |
|--------|-------------|---------------|-------|
| Kayhan | `www.kayhan.ir` | `kayhan.ir/en` | Editor appointed by Supreme Leader; most hardline |
| Vatan-e Emrooz | `www.vatanemrooz.ir` | — | Populist hardline, harshest framing |
| Resalat | `www.resalat-news.com` | — | Conservative clerical |
| Jomhuri-ye Eslami | `www.jomhourieslami.net` | — | Originally Khamenei-founded; recently more independent |

### Economic / Technocratic

Pragmatic, fact-and-numbers-focused. Useful counterweight to ideological framings.

| Outlet | URL (Farsi) | URL (English) | Notes |
|--------|-------------|---------------|-------|
| Donya-ye Eqtesad | `www.donya-e-eqtesad.com` | — | Iran's leading business daily |
| Iran Daily | `newspaper.irandaily.ir` | — | English-language economic coverage |

### Opposition (NOT inside Iran)

These outlets operate from outside Iran and are critical of the regime. They're useful as a counterweight to state media but should not be treated as neutral — they have their own agendas.

| Outlet | URL | Notes |
|--------|-----|-------|
| Iran International | `www.iranintl.com/en` | London-based, broadcasts in Farsi to Iran |
| BBC Persian | `www.bbc.com/persian` | UK state-funded Farsi service |
| Radio Farda | `www.radiofarda.com` | US-funded (RFE/RL) Farsi service |
| Manoto | `www.manototv.com` | Independent diaspora outlet |

## Default outlet sets (for the script)

When the user says `--outlets establishment`:
- `irannewspaper.ir`
- `irna.ir`

When the user says `--outlets reformist`:
- `sharghdaily.com`
- `etemadnewspaper.ir`

When the user says `--outlets irgc`:
- `tasnimnews.ir`  (NOT `.com` — that domain's DNS is dead; see the IRGC table note)
- `farsnews.ir`
- `javanonline.ir`

When the user says `--outlets hardline`:
- `kayhan.ir`
- `vatanemrooz.ir`

When the user says `--outlets economic`:
- `donya-e-eqtesad.com`

When the user says `--outlets opposition`:
- `iranintl.com/en`
- `bbc.com/persian`

When the user says `--outlets all` or omits the flag:
- One outlet from each of: establishment, reformist, IRGC, hardline.
  Default: `irna.ir`, `sharghdaily.com`, `tasnimnews.ir`, `kayhan.ir`.

## RSS feeds (where available)

These are more stable than scraping HTML:

- Tasnim: ~~`www.tasnimnews.com/fa/rss/feed/0/8/0/`~~ — dead with the `.com` domain; the same path on `.ir` 404s, so no working Tasnim RSS as of 2026-06-30. Scrape the `.ir` homepage instead.
- Fars: `www.farsnews.ir/rss`
- IRNA: `www.irna.ir/rss`
- Mehr: `www.mehrnews.com/rss`

## Important context

**The 88-day internet blackout** (early February 2026 — late May 2026) means many Iranian sites had reduced uptime, archive gaps, and routing instability during this period. Articles from this window may be missing or hard to retrieve. As of late May 2026 things are partially restored but not normalized.

**English editions are curated.** When fetching `en.irna.ir` versus `www.irna.ir`, expect to see different content. The English edition selects what to show foreign audiences. Always prefer Farsi originals when reachable; use English as fallback only.

**Geopolitical context for the 2026 period.** A major US-Israeli operation against Iran began February 28, 2026. As of late May 2026 a fragile ceasefire is in place with active negotiations (the "Islamabad Declaration" 60-day MOU) and intermittent strikes continuing. The Strait of Hormuz, sanctions, and the nuclear program are the central negotiation issues. The current Iranian president is Pezeshkian (reformist-leaning); the Supreme Leader is reportedly the late Khamenei's successor (the Feb 28 strikes reportedly killed Khamenei himself, per some Western reporting, though this remains contested in Iranian sources).
