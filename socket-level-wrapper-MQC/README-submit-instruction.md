# Submitting the MQC draft

A runbook for getting `draft-page-mqc-protocol-NN` in front of
the IETF PLANTS working group.  Written for future-you (or the
next author) picking this up months later without remembering the
back-and-forth that produced the current draft.

## The two artifacts

Both live in this directory:

- **`draft-page-mqc-protocol-00.md`** — source of truth.  Edit
  here.  Human-readable on GitHub.  Regenerate the `.txt` whenever
  this changes.
- **`draft-page-mqc-protocol-00.txt`** — 72-column paginated
  plain-text rendering.  This is what IETF datatracker and the
  `plants@ietf.org` mailing list expect.

Bump the trailing `-NN` (currently `-00`) on every revision.  The
convention is zero-padded two-digit integers; submit your first
revision as `-00`, next as `-01`, and so on.  Don't reset the
counter; the datatracker treats `draft-page-mqc-protocol-01` as
the natural successor to `-00`.

## Two submission paths — pick one (or both)

### Path A — IETF Datatracker

The official channel.  Gives the draft a canonical URL and puts
it on the PLANTS WG's review radar automatically.

1. Create a datatracker account at
   https://datatracker.ietf.org/accounts/create/ if you don't
   already have one.  The email you register becomes the public
   author contact; see "Dedicated IETF email" below.
2. Go to https://datatracker.ietf.org/submit/.
3. Upload the `.txt` (the `.md` is not accepted; the submitter
   can also upload `.xml` produced by `kramdown-rfc` or
   `xml2rfc`, but plain text is fine).
4. Datatracker validates line width (≤72), length, and the
   standard header/footer.  This draft already satisfies those
   constraints — confirm with:
   ```
   awk 'length > 72' draft-page-mqc-protocol-NN.txt
   ```
   (no output = no overruns.)
5. Confirm the submission via the email datatracker sends to the
   submitter.  The draft is then public at
   `https://datatracker.ietf.org/doc/draft-page-mqc-protocol/`.

### Path B — plants WG mailing list, inline

The social channel.  Use this either instead of datatracker (for
a very early request-for-comment) or *in addition to* datatracker
(to actively invite review).  Subscribe first (below).

1. Compose a new message **from your dedicated IETF address** (see
   below) to `plants@ietf.org`.
2. Subject line suggestion:
   ```
   MQC: post-quantum transport with MTC peer identity
       (draft-page-mqc-protocol-00)
   ```
3. Paste the full `.txt` into the **body**, not as an attachment.
   The list strips attachments; inline text is what people read.
4. Prepend a one-paragraph context note above the draft:
   - What this is.
   - What feedback you're looking for (review, interop partners,
     nonce-construction concerns, anything specific).
   - That the reference implementation is live and linked in
     Appendix B.
5. Send.  A thread appears at
   `https://mailarchive.ietf.org/arch/browse/plants/`.

## Subscribing to plants@ietf.org

You must be subscribed (or have your message explicitly approved
by a moderator) before the list accepts your post.

### Option 1 — web form

1. Visit https://www.ietf.org/mailman/listinfo/plants
2. Scroll to the **"Subscribing to plants"** section.
3. Enter your email.  Pick a list password if you want (optional
   convenience for later unsubscribe).
4. Click **Subscribe**.
5. Click the confirmation link in the email Mailman sends you.

### Option 2 — email

Send *any* message to:
```
plants-request@ietf.org
```
with subject `subscribe`.  Reply to the confirmation message
Mailman sends back.

### Reading the archive without subscribing

The archive at
https://mailarchive.ietf.org/arch/browse/plants/ is readable
without any account.  Skim a week or two of threads before posting
— lets you match tone and avoid common newcomer friction.

## Dedicated IETF email

**Highly recommended.**  Every message to `plants@ietf.org` is
archived forever at a Google-indexed URL.  The address you post
from ends up permanently associated with the draft — on the
datatracker, in the archive, in every reply chain.  Three reasons
to use a separate mailbox:

1. Keeps your personal inbox off the public archive surface.
2. Routes IETF volume (dozens of messages/day on active lists)
   into a filter rather than your primary inbox.
3. Matches your draft's author affiliation.  The `-00` draft
   lists `factsorlie.com` as the organization; posting from
   `cal@factsorlie.com` reads as "the person running factsorlie's
   MTC deployment" rather than "random Gmail user".

Three ways to get one:

| Option | Example | Setup |
|---|---|---|
| Vanity domain mailbox | `cal@factsorlie.com` | MX record + forwarding service (ForwardEmail, ImprovMX); ~20 min |
| Gmail plus-address | `page.cal+ietf@gmail.com` | Zero setup — routes to `page.cal@gmail.com`; filter on `+ietf` |
| Second free mailbox | `cal.page.ietf@fastmail.com` | Best isolation, extra checkable inbox |

**For this project, use `cal@factsorlie.com`.**  It's already what
the author block of the draft says; the domain is already live;
the MX change is trivial.

## List etiquette

IETF mailing lists are plain-text culture.  Gmail's composer
defaults fight all three conventions — override them per-account
or use a different client.

- **Plain text only.**  No HTML.  Turn off "rich formatting".
- **Reply inline, not top-post.**  Quote the specific lines
  you're responding to with `> ` prefixes; put your response
  below each quoted block.
- **Wrap lines at 72 columns** when quoting.  Doesn't matter for
  your own prose; matters when you're quoting the draft.
- **No signatures longer than ~4 lines.**  Contact info plus
  affiliation is enough.
- **Threading matters.**  Reply to the actual message, not a new
  compose.  Gmail usually gets this right; other clients need a
  nudge.

## Pre-submission checklist

Before either path:

- [ ] Line width check on the `.txt`:
      `awk 'length > 72' draft-page-mqc-protocol-NN.txt` prints nothing.
- [ ] Date in the header (`Internet-Draft ... NN Month YYYY`)
      matches today.
- [ ] Expiration date in the header and the **Status of This
      Memo** section is today + 6 months.
- [ ] The reference implementation pointed at in Appendix B
      still builds cleanly from master: `make -f Makefile.tools clean
      && make -f Makefile.tools` finishes with zero warnings.
- [ ] `factsorlie.com` is up (the draft cites it) — `curl -sk -o
      /dev/null -w "%{http_code}\n" https://factsorlie.com/` → 200.
- [ ] New/revised sections proofread — the `.md` and the `.txt`
      agree in content.

## Post-submission

- **Expect a day or two of silence.**  The WG isn't huge.
- **First feedback is usually editorial.**  Whitespace, citation
  formats, "this paragraph belongs in a different section."  Don't
  read that as a rejection.
- **Security-critical feedback goes deep.**  If someone flags
  the nonce construction (Section 9.2) or the Ed25519-cosigner
  PQ concern (Section 12.1), take the time — those are the bits
  that make or break the draft's credibility.
- **Next revision**: bump the trailing `-NN`, regenerate the
  `.txt`, resubmit.  Datatracker enforces a minimum interval
  between revisions (typically 14 days unless it's a chair-
  requested urgent fix).

## Related

- `socket-level-wrapper-MQC/draft-page-mqc-protocol-00.md` —
  editable source.
- `socket-level-wrapper-MQC/draft-page-mqc-protocol-00.txt` —
  submittable plain text.
- `/README-links.md` — publicity playbook that routes through the
  PLANTS list as Tier 2.
- `mtc-keymaster/README-bugsandtodo.md` §46 — TODO that tracks
  actually making the submission round.
