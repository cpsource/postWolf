# Loaded-Terms Glossary

Some Farsi political terms do not survive machine translation. The translator collapses
distinctions that are *the actual story*. The canonical case: a Western source says the two
sides reached a **"deal,"** Iranian sources say **تفاهم** (a non-binding *understanding*).
Google Translate renders both as "agreement," and the gap — the single most analytically
important fact — disappears.

**Rule:** when a Western claim uses a strong word (deal, agreement, ceasefire, lift
sanctions, surrender) and the Iranian source uses a weaker or differently-loaded Farsi word,
that gap is a **finding**. Report it explicitly. Never let it dissolve into a translation.

The fetch script (`scripts/fetch_press.py`) scans fetched text against the terms below and
emits a "Loaded terminology detected" section in the handoff. This file is the human-readable
companion and the source of truth — **keep the script's `GLOSSARY` and `CLAIM_TRIGGERS`
constants in sync with the tables here.**

---

## 1. Agreement strength — the most important axis

These all get machine-translated to some flavor of "agreement / deal / understanding," but
they sit on a spectrum from "we talked" to "we are legally bound." Always pin down which one
the Iranian source actually used.

| Farsi | Translit | Neutral gloss | What it actually signals |
|-------|----------|---------------|--------------------------|
| تفاهم | tafāhom | understanding | Mutual understanding. **Non-binding.** No obligations created. |
| تفاهم‌نامه | tafāhom-nāmeh | memorandum of understanding (MOU) | A *document* recording an understanding. Still **non-binding**; deliberately weaker than a treaty. |
| توافق | tavāfoq | agreement / accord | An actual agreement on terms. Stronger than تفاهم — implies the sides *agreed*, not merely *understood each other*. |
| توافق‌نامه | tavāfoq-nāmeh | agreement document | Written توافق. |
| قرارداد | qarārdād | contract | Binding contract. Obligations + (implied) enforcement. |
| معاهده | moʿāhede | treaty | Formal, binding, usually ratified. The strongest. |
| سند | sanad | document | Neutral "document." Often paired: سند تفاهم, سند همکاری. The noun next to it carries the weight. |

**The move:** Western "deal" most naturally maps to توافق/قرارداد. If the Iranian source
actually says تفاهم‌نامه, the Iranian side is signalling *we committed to nothing binding* —
often a domestic-audience message that no concessions were locked in. Flag it.

## 2. Cessation of hostilities

| Farsi | Translit | Neutral gloss | What it actually signals |
|-------|----------|---------------|--------------------------|
| آتش‌بس | ātash-bas | ceasefire | A ceasefire proper. |
| توقف | tavaqof | halt / stoppage | A *halt* — can be unilateral, temporary, conditional. Weaker than a negotiated ceasefire. |
| وقفه | vaqfe | pause / interlude | A pause. Implies hostilities may resume. |
| ترک مخاصمه | tark-e mokhāseme | cessation of hostilities | Broader than آتش‌بس; legalistic. |
| آرامش | ārāmesh | calm / quiet | "Calm." Atmospheric, not a status. Used to downplay. |

**The move:** Western "ceasefire" vs Iranian توقف/وقفه = the Iranian source is declining to
dignify it as a mutual, durable arrangement.

## 3. Sanctions

| Farsi | Translit | Neutral gloss | What it actually signals |
|-------|----------|---------------|--------------------------|
| تحریم | tahrim | sanctions / boycott | The sanctions themselves. |
| لغو تحریم‌ها | laghv-e tahrim-hā | lifting of sanctions | **Permanent** removal. The maximal Iranian demand. |
| تعلیق تحریم‌ها | taʿliq-e tahrim-hā | suspension of sanctions | **Temporary** suspension — reversible. A much smaller concession than لغو. |
| رفع تحریم‌ها | rafʿ-e tahrim-hā | removal of sanctions | Removal; in practice often used interchangeably with لغو but technically about *effect* not *legal repeal*. |

**The move:** "Sanctions relief / lift sanctions" in Western copy collapses لغو (permanent)
and تعلیق (temporary). Which one the Iranian source uses tells you whether they think they
won a durable concession or a revocable pause.

## 4. The nuclear program

| Farsi | Translit | Neutral gloss | What it actually signals |
|-------|----------|---------------|--------------------------|
| غنی‌سازی | ghani-sāzi | enrichment | Uranium enrichment. |
| حق مسلم | haqq-e mosallam | inalienable right | "Our inalienable right [to enrich]." Non-negotiable framing. |
| تعلیق غنی‌سازی | taʿliq-e ghani-sāzi | suspension of enrichment | A major concession term. If an Iranian source uses this approvingly, that is significant. |
| توقف غنی‌سازی | tavaqof-e ghani-sāzi | halt of enrichment | Halt of enrichment. |
| برنامه صلح‌آمیز هسته‌ای | barnāme-ye solh-āmiz-e haste-ī | peaceful nuclear program | The standard Iranian self-description. |

## 5. Rhetorically loaded framing terms (pejorative / propaganda register)

These have no clean English equivalent and are *editorial signals*. Their presence tells you
how an outlet wants the reader to feel — often the opposite of the literal translation.

| Farsi | Translit | Literal | What it actually does |
|-------|----------|---------|-----------------------|
| فضاسازی | fazā-sāzi | "atmosphere-building" | **Spin / manufactured hype / a manufactured media climate.** Pejorative. "The enemy is engaged in فضاسازی" = "this is propaganda, don't believe it." A tell that the outlet is dismissing a claim. |
| جنگ روانی | jang-e ravāni | psychological war | Frames the other side's *messaging* as an attack. Dismissive. |
| پروژه | prožen / projeh | "project" | As in "this is a پروژه of the enemy" = a coordinated plot/op, not an organic event. |
| بزرگ‌نمایی | bozorg-namāyi | "magnification" | Exaggeration / blowing out of proportion. Dismissive. |
| تجاوز | tajāvoz | aggression / assault | Casts the other side as the aggressor. Choice of تجاوز vs حمله (attack, neutral) is editorial. |
| استکبار (جهانی) | estekbār(-e jahāni) | "(global) arrogance" | = the US-led West. Ideological. |
| شیطان بزرگ | sheytān-e bozorg | "Great Satan" | = the US. Maximal hostility register. |
| مقاومت | moqāvemat | "the Resistance" | The Axis of Resistance. In-group framing; approving. |
| دشمن | doshman | "the enemy" | Usually US/Israel. Its use as an unqualified noun is itself a factional tell. |
| پاسخ کوبنده | pāsokh-e koubande | "crushing response" | Threat-rhetoric register. |
| اقتدار | eqtedār | might / authority | Regime-strength framing; approving of state power. |
| نفوذ | nofuz | "infiltration" | Used to smear negotiators/reformists as foreign agents. A hardline attack term. |
| بصیرت | basirat | "insight / discernment" | Loyalty-signalling buzzword; "the discerning [loyal] public." |
| خط قرمز | khatt-e qermez | red line | Non-negotiable limit. |

## 6. Negotiation framing

| Farsi | Translit | Neutral gloss | What it actually signals |
|-------|----------|---------------|--------------------------|
| مذاکره | mozākere | negotiation | Negotiation. |
| مذاکره مستقیم | mozākere-ye mostaqim | direct negotiation | Direct talks. Iran has often refused these for domestic reasons. |
| مذاکره غیرمستقیم | mozākere-ye gheyr-e mostaqim | indirect negotiation | Indirect (via mediator). Iran frequently insists on this framing to avoid the optics of direct talks with the US. The distinction is politically load-bearing. |
| گفت‌وگو | goft-o-gu | dialogue | Softer than مذاکره. |

## 7. Source-attribution hedges

How an outlet sources a claim signals its confidence and deniability. The script does not
auto-detect these reliably, but watch for them when reading:

| Farsi | Translit | Meaning |
|-------|----------|---------|
| منابع آگاه | manābeʿ-e āgāh | "informed sources" (anonymous) |
| یک مقام مسئول | yek maqām-e masʾul | "a responsible official" (anonymous) |
| منابع نزدیک به | manābeʿ-e nazdik be | "sources close to [X]" |
| به نقل از | be naql az | "quoting / according to [named source]" |
| فاش کرد | fāsh kard | "revealed / disclosed" (claims exclusivity) |

**Semi-official tell:** when a *semi-official* IRGC-aligned wire (Tasnim, Fars) floats a
framing attributed to منابع آگاه before any ministry confirms it, that is often a trial
balloon — and frequently leads ministerial messaging by a day or more. See the README case
study.

---

## How to report a terminology gap

In the handoff's analysis notes, write it as a finding, e.g.:

> **Terminology gap:** Western source says "Iran agreed to a ceasefire deal." Tasnim and
> IRNA both use **تفاهم‌نامه** (non-binding MOU) and **توقف** (a halt), not توافق/آتش‌بس.
> The Iranian framing is deliberately weaker — signalling to the domestic audience that
> nothing binding was conceded. This gap is the story, not a translation artifact.
