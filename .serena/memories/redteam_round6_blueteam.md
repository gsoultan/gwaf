# Blue-team round: 0 false positives, and what it cost to keep them at 0

2026-08-15. Hardening pass against the round 4/5 findings, run to a hard
constraint: **zero false positives**. Commits `8d83669`, `8e4c3bb`, `fba3556`,
`9d0f4fd`.

| | detection | false positives |
|---|---|---|
| v0.5.2 (pre-Mythos) | 21/85 — 24.7% | 3/42 — 7.14% |
| after red-team rounds | 70/85 — 82.4% | 3/42 — 7.14% |
| **after blue-team round** | **88/95 — 92.6%** | **0/56 — 0.00%** |

Per class now: prompt 100% (23/23), shell 100%, engine 100%, nosql 100%,
ssrf 100%, multipart 100%, traversal 100%, xss 100%, ssti 88.9%, charset 87.5%,
sqli 85.7%, agentic 66.7%, deser 66.7%.

## The false positives were all one mistake

Every FP was a **sentence fragment scored as a whole imperative**. "You are now"
is an attack before "DAN" and a loyalty email before "a premium member"; "new
instructions:" heads a prompt override and a flat-pack manual. The fix is the
detector's own stated philosophy applied properly: a fragment must be **aimed at
the model** — at a persona, at what the model is, or at a constraint being
cancelled (`needsModelObject` + `modelObjects`).

Two more were the mirror image and needed the opposite default. "Show me your
instructions" bare *is* the attack; what makes it benign is a preposition handing
it a different referent ("...for assembling the desk"). So `ambiguousExfil`
defaults to attack and is disqualified by `taskQualified` — and **model
vocabulary wins**, so appending a preposition to escape ("...for the system
prompt") still blocks.

**The vocabulary is where the recall/FP trade actually lives.** `disable`,
`reset`, `admin`, `password` are excluded on purpose: they appear in ordinary
account mail ("you are now an admin", "from now on you can reset your password")
and adding them trades the FPs straight back. Configuration files and API keys do
not turn up in a loyalty email, so those are in.

## Two performance corrections, same shape as round 5's

Both were caught by measuring, not by reading:

1. **A widened phrase matcher without indexFold's two guards** (value shorter
   than the phrase cannot match; a match cannot start with fewer bytes than the
   phrase remaining) cost **+106% on BenchmarkBenignPOSTJSON**. JSON field values
   are mostly shorter than any phrase and were each walked end to end by every
   widened phrase. With the guards: 18.4µs against a 19.1µs baseline.
2. Machine noise nearly caused a false diagnosis — the first "regression" reading
   was taken right after a full test-suite run and showed 36-45%. **Always
   re-measure paired on a settled machine before believing a benchmark.**

## The anchor idea, worth reusing

A widened match cannot declare its own text to the prefilter: under flex its
words arrive as separate runs, under leet its letters arrive as digits. It
declares an **anchor** — a contiguous run that survives both widenings. Three
properties, all enforced by `TestLiteralsCoverEveryScoringPhrase`: inside the
phrase, inside one word, and (for leet) containing no leet-foldable letter.

That last one is why the leet map omits `7→t`: t, r, u and c having no digit
spelling is what keeps "truct" intact inside every leeted "instructions".
**Widening the leet map would silently bypass gwaf's own prefilter** — the
failure [[rejected_literal_hints]] documents, approached from the other side.

Phrases built from the commonest English words stay byte-exact: "you are now" has
no anchor worth declaring ("you" would nominate most of the internet), so its
whitespace variants are a documented miss rather than a silent one.

## Still open (7), each with the reason

- **utf7 long run** — `maxEntityLen` is the anti-quadratic bound.
- **CHAR(39)+CHAR(79)** — bare `char` is in "search"/"character".
- **mcp tool poisoning / markdown-image exfil / hypothetical jailbreak** — prose
  with no structural marker. Every candidate signal tested so far carries real FP
  risk, and the 0-FP bar is worth more than these three.
- **YAML bodies** — needs a parser.
- **dotted .NET/Jackson type markers** — the fix is specified in
  `typemarker.go`'s own comment: a rule of its own anchored on the quoted marker
  *name* (selective), not a dot literal here (measured: benign rule evaluation
  6 → 8). Highest-value remaining item.

Also open from round 5 and not in this corpus: **GraphQL batch arrays**
(`[{"query":…}]` evades every GraphQL rule and the introspection opt-in).

See [[redteam_round5]], [[redteam_round4]], [[prefilter_literal_selectivity]].
