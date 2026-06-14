# iranian — Farsi Press Check

A fetch-and-package skill that cross-checks a Western/US claim about Iran against what the
Iranian Farsi-language press is actually reporting, sampled across the factional spectrum
(establishment, reformist, IRGC-aligned, hardline, plus economic and opposition). It gathers
raw Farsi articles, flags rhetorically loaded terminology, and hands the material off for
conversational analysis in Claude.ai.

See `SKILL.md` for the operating instructions. This README is design notes: *why* the skill
is built the way it is.

## Why cross-factional sampling

The whole architecture is the multi-outlet, multi-faction spread. Any single Iranian outlet
is a known quantity with a known bias; the signal lives in the *divergence* between them.
When establishment, reformist, IRGC-aligned and hardline outlets all say the same thing,
that's a strong consensus. When they diverge — especially when a semi-official wire runs a
framing the official ministry voices have not yet adopted — that divergence is predictive.

## Why a loaded-terms glossary

Machine translation collapses exactly the distinctions that carry the analysis. "Deal,"
"agreement," and "understanding" are three different commitments in Farsi (توافق vs قرارداد
vs تفاهم‌نامه), and Google Translate renders all of them as "agreement." The glossary
(`references/loaded_terms_glossary.md`) and the script's automatic terminology scan exist so
those gaps surface as **findings** instead of dissolving silently. See the case study below
for why this matters in practice.

---

## Case study: the 36-hour semi-official lead (MOU vs "deal")

*This is the case that motivated building the glossary check into the skill.*

**Setup.** A Western wire reported that Iran and its counterpart had reached a **"60-day
ceasefire deal"** (the Islamabad Declaration). The natural reading: a binding, mutual
agreement to stop fighting.

**What the press check found.** Sampling across factions surfaced two things machine
translation alone would have buried:

1. **Terminology gap.** Iranian sources across the spectrum were not using توافق ("deal" /
   agreement). The semi-official IRGC-aligned wires (Tasnim, Fars) and the establishment
   outlets used **تفاهم‌نامه** — a *non-binding memorandum of understanding* — and described
   the cessation as a **توقف** (a halt), not an **آتش‌بس** (ceasefire). The Iranian framing
   was deliberately weaker than the Western "deal": a signal to the domestic audience that
   nothing binding had been conceded. Translated naively, both "تفاهم‌نامه" and "توافق" come
   out as "agreement," and the entire distinction vanishes.

2. **Sequencing / the 36-hour lead.** The MOU framing appeared on the *semi-official* wires —
   attributed to منابع آگاه ("informed sources") — roughly **36 hours before** it surfaced in
   official ministerial statements. The semi-official outlets were running a trial balloon;
   the ministry's messaging then converged on the same framing a day and a half later.

**Why it matters.** Both findings are products of the architecture, not luck:

- The **terminology gap** is only visible because the skill preserves the Farsi original and
  checks it against the glossary, rather than trusting the translation. A "deal" in English
  and a تفاهم‌نامه in Farsi are not the same event.
- The **36-hour lead** is only visible because the skill samples the *semi-official* tier
  (Tasnim/Fars) alongside the official tier (IRNA/ministry). A single-source check on the
  official outlets would have caught the framing a day and a half late. The cross-factional
  spread is what turned a same-day confirmation into an early signal.

**Lesson encoded into the skill.** Semi-official IRGC-aligned wires frequently lead
ministerial messaging on negotiation framing — treat a framing that appears there first,
attributed to anonymous "informed sources," as a likely trial balloon worth flagging *before*
it is officially confirmed. And always pin down which Farsi commitment-word was actually used
before repeating a Western "deal."

---

## Layout

- `SKILL.md` — operating instructions / workflow
- `references/iranian_press_landscape.md` — outlet directory by faction
- `references/loaded_terms_glossary.md` — terms that don't survive machine translation
- `scripts/fetch_press.py` — the fetch + package + terminology-scan implementation

## Scope and limits

Personal-research-grade. It does not adjudicate truth, does not replace Iran-watching experts
(Amwaj.media, BBC Monitoring), and does not reliably translate dense political-religious
essays — bring those to Claude.ai in the original Farsi. See the "What this skill does NOT do"
section in `SKILL.md`.
