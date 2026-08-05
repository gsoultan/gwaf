# Decisions and Negative Results

The most valuable memories here are the things that were **built, measured, and
rejected**. They exist so nobody rebuilds them.

## REJECTED: transducers (CONCEPT.md §3)
Fold streamable transforms into the matcher so normalized bytes are read
straight from the request with no copy.

Built. Proven correct — 38.6M differential fuzz execs, byte-for-byte identical
to the materialized oracle, identical candidate sets. **Then measured 1.3–2.0×
SLOWER in every case** and removed.

Two reasons, visible only once both paths existed:
1. The allocation it targeted **was already gone** — the materialized path
   reuses scratch and short-circuits when a transform changes nothing.
2. Per-byte pull through a function call costs more than the copy it avoids;
   materialized loops vectorize, transduced ones cannot.

Numbers: `bench/transducer-experiment.txt`.

**The meta-lesson, which matters more:** the kill criterion anticipated a
*correctness* failure. The real failure was that the **premise** had already
been satisfied by simpler means. **Test the premise, not only the
implementation.**

## SIMPLIFIED: decode lattice → conditional multi-interpretation (§4)
The lattice (NFA over ambiguous byte positions) exists to make N readings cost
~1×. But that premise only holds if values are usually ambiguous, and almost
none are. Shipped instead: one cheap `Detect` pass; a value with no ambiguity
marker has exactly one reading and costs what it did before.

Result: 76/76 evasion, 0 false positives, 1× on clean input. The lattice is
**not needed** until profiles show ambiguous traffic is common.

## REJECTED: bytecode VM (§1)
Textbook answer, and in Go usually *slower* — no computed `goto`, bounds checks
in the dispatch loop. Flat IR for storage, closures for execution.

## NOT BUILT: compile-time per-route plan pruning (§6)
The per-value form already delivers most of the benefit. Measure before adding
the machinery. (Transducer lesson.)

## No paranoia levels
PL1–PL4 is a CRS *tagging convention*, not an engine feature — and it is global
where FP tolerance is per-route. Replaced by per-rule `Confidence` +
policies. `WithParanoiaLevel(n)` survives as a CRS-compat preset.

## Rules are structs, not a fluent builder
Structs serialize, diff in review, and codegen. Builders do none of those and
add a state machine to get wrong. It is also what keeps the Go and declarative
frontends isomorphic rather than merely similar.

## Blocking by default
`gwaf.New()` with zero args blocks. Defensible only because `ruleset/core`
ships Certain/High confidence rules only. A WAF that silently protects nothing
is worse than none — the operator believes they are covered.

## SHIPPED: structural SQL detection (`detect/sqli`)
Tokenize the value and score **grammar**, not strings. Four interpolation
contexts (bare, single-quote, double-quote, backtick) so quote-breaking is
visible: "1' OR 1=1--" read literally is a number and an unterminated string;
read as interpolated inside '...', the quote *closes* the literal and the rest
is a tautology plus a truncating comment.

48/48 payload variants, 0/56 false positives on prose.

**It replaced four literal rules rather than joining them.** Rule 2002
(`unionselect` after whitespace stripping) was an active false positive: "the
union selected a new representative" collapses to "unionselected". IDs 2001-2004
are **retired, not reused** — they appear in audit logs and any exception
already written.

Signals are weighted so that weak evidence needs corroboration: a trailing
comment or an apostrophe is ordinary in real text. Danger functions require
**attachment** to surrounding SQL, which is what keeps "sleep(8h) is the
recommendation" out.

Deliberate non-detection: `1'' OR ''1''=''1`. Doubled quotes are *correct SQL
escaping* — the origin parses it as one harmless string literal. Flagging it
would mean assuming a non-standard parser and would false-positive on every
correctly-escaped value.

**Cost, stated honestly.** The detector declares broad literals (`=`, `'`, `"`)
because payloads are built from them, so prose containing those is a prefilter
candidate. "Zero rules evaluated on benign traffic" is therefore no longer
literally true; the claim was **restated**, not quietly weakened, to: rules
evaluated is a small constant independent of ruleset size, zero when the value
has no attack vocabulary. Benign POST with a 1 KiB JSON body went 6.5us -> 17.6us
because the whole body is tokenized as one value; field-level JSON parsing will
cut that and is the next real optimization.

## SHIPPED: structural XSS detection (`detect/xss`)
Harder than SQL: an HTML parser never rejects input, so a payload need not be
well formed to execute (`<svg/onload=alert(1)` works unclosed). Signals are
correspondingly narrower and the FP corpus is larger (78 entries vs 56).

**Position is the whole detector.** "onerror" in prose is a word; "onerror="
between a tag name and its `>` is a handler. Same bytes, different grammar.

53/53 payloads, 0/78 false positives. Replaced literal rules 3001-3003
(retired, not reused).

Signal design that mattered:
- `executingTags` deliberately **excludes** b/i/em/p/a/code/ul — the tags people
  actually write in comment fields. An `<a>` is dangerous via its href *scheme*,
  not via being an `<a>`.
- Event-handler detection checks the *shape* (`on` + letters) rather than an
  enumerated list; browsers keep adding events and a list is permanently behind.
- Scheme matching skips whitespace and control bytes, which is why
  `java\tscript:` and `java\x00script:` are caught.
- `SignalSchemeInAttribute` (5) is separate from `SignalScriptURI` (3): a
  scheme in an href *is* a link that runs code; a scheme mentioned in prose is a
  sentence.

Two test payloads of mine were wrong, not the code: `<img/src=x/onerror=...>`
does not execute (an unquoted attribute value runs to whitespace, so the handler
is part of the value), and the doubled-quote SQL case is correct escaping.
Verify which side is wrong before "fixing".

## SHIPPED: body field parsing (`internal/body`)
Streaming JSON and form parsers. No tree is built (encoding/json would allocate
a map per object); the document is scanned once with an explicit stack and
leaves are emitted as found. Zero allocation, 855 MB/s.

**Not just an optimization.** A JSON string is not its bytes:
`{"c":"\u003cscript\u003e"}` has no angle bracket on the wire and the origin's
parser hands the application `<script>`. Same disagreement class as
internal/interpret, through a different door — the escape is not a reading to
guess at, it is a decoding the origin will certainly perform.

Object **keys** are emitted too, and `TargetArgNames` was added to the core
rule target lists. Before that, nothing inspected argument names at all — a
payload in a JSON key was invisible.

The grammar is **strict on purpose**: leading zeros, bare fractions, and raw
control characters in strings are rejected because JSON rejects them. A parser
looser than the origin's inspects documents that will never be processed, and
gives an attacker a shape the two sides read differently. The fuzz harness
checks acceptance against `encoding/json` (27M execs) precisely for this.

**Allocation trap worth remembering.** Wiring the parser in cost 120 allocs/op
from `string(name)` per field and `[]byte(key)` conversions. Fixed by: keys
stored in the arena as spans, `engine.Value.Key` becoming `[]byte`,
`Target.MatchesBytes`, and separate string/bytes record paths. Also discovered
`Value.Target.Name` was dead — rule matching compares the *rule's* target name
against the value's key, so the per-value name was never read.

## SHIPPED: multipart parsing (`internal/body/multipart.go`)
**This is the CVE-2026-21876 regression test.** That flaw (CVSS 9.3, Jan 2026)
broke CRS across ModSecurity v2, v3, *and* Coraza because the multipart charset
was captured once and evaluated once — only the **final** part was really
checked. gwaf emits every part; `TestMultipartEveryPartIsInspected` places the
payload at each position in turn and requires detection at all of them.

Also inspected, because each is attacker-controlled and was previously invisible:
- **Filenames** (traversal, double extension) — emitted as `<name>.filename`
- **Field names**
- **Each part's Content-Type and charset**

**Rule 1005 (encoded NUL) is the interesting one.** `shell.php%00.jpg` passes a
suffix check that sees `.jpg`, and a C-backed handler truncates and saves
`shell.php`. The payload is the *disagreement between readings*, so the NUL is
what to detect — not the extension, which is legitimate on its own. Matched
**before** percent-decoding on purpose: decoded, a NUL is indistinguishable from
the NULs filling ordinary binary uploads; encoded, it has no legitimate use.

**Stated coverage decision:** file part content is inspected up to 8 KiB.
Tokenizing the rest of a multi-megabyte upload as SQL costs real time and finds
nothing; payloads that matter live in the first few KB. Content scanning beyond
that belongs out of band (antivirus), which is the embedder's job per the
stateless boundary.

Delimiters only count at a line start, so a body containing the boundary string
mid-line is not split there — otherwise the parts gwaf sees and the parts the
origin sees would differ. Bare LF is accepted because lenient origins accept it.

## SHIPPED: net/http middleware (`middleware`)
Integration profile A: `middleware.HTTP(waf)(mux)`. In the **core module**
because net/http is stdlib; framework adapters (chi, echo, gin) need their own
deps and therefore their own modules.

Both documented traps are handled **and tested**, because both fail silently:
- **Body double-read** — read once into a buffer, restore `r.Body` and
  `ContentLength`. Without it the handler gets an empty body and it looks like
  an application bug.
- **ResponseWriter interface loss** — the wrapper implements `Unwrap()` for
  `http.ResponseController` *and* delegates Flusher/Hijacker/Pusher/ReaderFrom
  for code that type-asserts. Losing these silently breaks SSE, WebSocket
  upgrades, and sendfile weeks after the middleware was added.

Deliberate choices:
- **Not `url.ParseQuery`** — it drops pairs it considers malformed, and a pair
  an attacker deliberately malformed is the one worth inspecting.
- **`r.RequestURI` over `r.URL`** — parsing normalizes, and a normalized view
  can differ from what the origin receives.
- **Host is added explicitly** — it lives on the struct, not in Header, so it
  would otherwise never be inspected despite reaching routing and cache keys.
- **Response inspection is opt-in** — buffering defeats streaming and delays
  time-to-first-byte. Oversized responses pass through intact rather than being
  truncated.
- **Default block response says nothing** — telling a client which rule fired
  is telling an attacker what to work around.

## FIXED: the `make deps` check was wrong
It walked import paths and excluded `^golang.org/x/`. Importing net/http broke
it, because the standard library **vendors** packages under
`vendor/golang.org/x/net/...` which look third-party and are not. Now checks
both `go list -m` (the declaration) and `.Standard` on the package walk (what
actually links). Stronger than before.

## SHIPPED: `gwaf calibrate` — and it reports its own limits
Confidence is now measured against `testdata/corpus/benign.jsonl` and gated in
CI. This was the largest doc/code gap in the project: cited as a build gate in
CLAUDE.md and as "the highest-leverage accuracy idea" in CONCEPT.md §8, while
being a claim rather than a tool.

**The part worth remembering is the honesty check.** 71 benign requests can only
observe false-positive rates above 1.4% (1 in 71). A `Certain` claim means 1 in
10,000. So a clean run today proves the rule did not match those 71 requests —
*not* that its rate is below the ceiling. The tool prints exactly that, names
which tiers it cannot validate, and says how many requests each would need.

Without that warning a green calibration run is a rubber stamp, and someone
would eventually "fix" a failure by loosening a ceiling. **Grow the corpus;
never loosen the ceiling.**

Counting unit: a rule is counted **once per request**, not once per matching
value. Four matching arguments in one request is one false positive to the
operator who has to deal with it.

`calibrate.NewWAF` exists because three settings are easy to get wrong by hand:
detection-only (so a blocking rule does not hide later matches), lowest minimum
confidence (so every tier is compiled in, not just what a production policy
runs), and unmetered fuel.

Also added `Transaction.Matches()` — every rule that fired, not just the
terminal one. Calibration needs the full set, and so does any control plane
explaining a decision (the "no UI but expose everything" corollary).
