# postWolf — links & publicity venues

A grab-bag of bookmarks: news pegs we can cite when pitching the
project, and venues where we can actually announce / pitch.

## News pegs (external context we can cite)

- https://it.slashdot.org/story/26/03/27/2123239/google-moves-post-quantum-encryption-timeline-up-to-2029
- https://blog.google/innovation-and-ai/technology/safety-security/cryptography-migration-timeline/

  Google pulled their post-quantum migration timeline forward to
  **2029**.  Handy anchor when explaining why *now* is the right
  moment for a working MTC + PQC-channel reference implementation,
  not in three years.

---

## Venues, ranked by leverage × fit

### Tier 1 — broad reach, directly on-topic

**Hacker News.**  `news.ycombinator.com/submit`.
Title framing: *Show HN: Post-quantum PKI + Gmail extension that
encrypts email with ML-KEM/ML-DSA*.  Pin the Gmail extension as the
draw, `factsorlie.com` as proof-of-work.  Post 07:00–11:00 US
Eastern on a weekday.  One tight paragraph + repo link; no marketing
puffery.

**Lobste.rs.**  Invitation-only community, but anyone already there
can submit.  Stricter tech audience, higher-quality comments.  Same
framing as HN.

### Tier 2 — narrow but exactly the right people

**IETF PLANTS working group list** — `plants@ietf.org`.
This is where `draft-ietf-plants-merkle-tree-certs` lives.
Announcement of form *"reference implementation of
draft-ietf-plants-merkle-tree-certs with working server + client
libraries; code at …"* will be well-received — the WG actively
wants more implementations before finalising.  Cite the Google 2029
migration timeline as the urgency.  This is the single post that
matters most long-term: it associates the author with the spec.

**CA/Browser Forum public list** — `public@cabforum.org`.
WebPKI decision-makers.  Don't drive-by market; post a technical
observation or question ("here's how we use MTC for transparency-
log-based leaf distribution; does this interact with any CABF
assumption around X?").  High signal-to-noise, low tolerance for
self-promotion.

**wolfSSL directly** — `https://www.wolfssl.com/contact-us/` or
their community forum.  postWolf is a fork of their library; they
sometimes feature third-party extensions on their blog.  Worst
case: they decline.  Best case: they link to it and we reach their
whole embedded-security mailing list.

### Tier 3 — Reddit (four angles, same project)

| Sub | Lead with |
|---|---|
| `/r/crypto`       | ML-KEM-768 + ML-DSA-87 + Merkle-log design |
| `/r/netsec`       | Gmail extension + threat model |
| `/r/privacy`      | *Gmail content never seen by Google in plaintext* |
| `/r/selfhosted`   | `kit-mqc` — one `sudo-bash` to run your own PKI |

### Tier 4 — long-form explainers (SEO + referenceable)

**dev.to** and **Medium** (cross-post the same article to both).
Title: *"Merkle Tree Certificates, explained by someone who just
implemented one"* or *"Building a post-quantum reimagining of the
X.509 PKI — what I learned"*.  1500–2500 words, working code
blocks, a `curl` or `mqc` demo the reader can paste.

**Own blog under `factsorlie.com/blog/…`.**  If we don't have
`/blog/` yet on the Apache vhost, adding it is a 15-minute job.
This becomes the canonical URL every other post links to.

### Tier 5 — niche security newsletters (low effort, decent reach)

- **tl;dr sec** — weekly security newsletter; Clint Gibler takes
  reader tips at `tldrsec.com`.
- **CryptoHack blog** — occasionally writes up novel crypto
  implementations.
- **Schneier on Security** — Bruce accepts tips via the contact
  form; features non-corporate crypto work when the writeup is
  good.
- **LWN.net** — tip form → story suggestions.  They take serious
  systems/crypto work and give it careful treatment.

### Tier 6 — Mastodon / Fediverse (zero friction)

- **`infosec.exchange`** — active security community.  One post
  with `#cryptography #PQC #postquantum`, a one-line teaser, the
  repo link, and a screenshot of the Gmail extension decoding.
- **`fosstodon.org`** — cross-post for the FOSS angle.

Cheap and compounds over time; researchers allergic to X/Twitter
hang out here.

---

## Suggested first-day rollout

1. **Write one canonical post.**  dev.to or `factsorlie.com/blog/`.
   Everyone else's link goes here.
2. **Submit to HN** as *Show HN:*, linking to (1).
3. **Post to `plants@ietf.org`** with the brief "reference
   implementation available" note.
4. **Cross-post on Mastodon + the four Reddits.**
5. **Send tips to LWN + tl;dr sec.**

If (2) gets traction we don't need the rest.  If it doesn't, the
rest gives steady compounding reach.  (3) is the only one that
matters long-term.

---

## Craft notes

- Don't lead with "post-quantum" in general-audience copy — it's a
  buzzword that's lost meaning to non-experts.  Lead with the
  *concrete thing they can do*: "right-click a Gmail message to
  encrypt it end-to-end, with the server we run as the CA."
- Do lead with "post-quantum" for crypto-specialist audiences —
  they want the algorithm names up front.
- Always link to a self-contained artifact the reader can test in
  under a minute: a `curl` against `factsorlie.com`, the
  `gmail-mqc-extension` install, a `show-tpm --verify` output.
- Never link to "read the whole monorepo"; it's a wall.

---

## Tracking (see also)

- `mtc-keymaster/README-bugsandtodo.md` §46 — standing TODO to
  actually execute a round of publicity using this document as the
  playbook.
