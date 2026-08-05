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

## The calibration gate found a real false positive on its first real run
Grew the corpus from 71 to **1,330 distinct requests** built from gateon's real
API surface — UI fetch paths, protobuf field names, Connect method names, real
query parameters (`page`, `pageSize`, `search`), realistic header sets.

**Provenance is stated, not implied.** The *shapes* are real; the *values* are
plausible, not observed. gateon has no production access logs. That is why the
corpus is produced by a reviewable generator (`testdata/corpus/gen`) rather than
a hand-typed blob — a reviewer can check the model against the real surface.

**The finding.** gateon stores WAF rules as SecLang directives, so its own admin
API legitimately POSTs strings containing `<script` inside a regex. The
structural XSS detector fired. A firewall that stops an operator from saving a
WAF rule mentioning `<script` is the classic "WAF blocks the security team"
failure, and it would have shipped.

**Fixed the detector, not the ceiling.** A tag name alone is not a tag: to be
markup an element must be *completed* by `>` or *elaborated* by a `name=value`
attribute. Text that merely names a tag is neither.

First attempt was too loose — I counted any bare word after the tag name as an
attribute, and the words *inside* the SecLang directive satisfied it. An
attribute needs `name=value`.

**Deliberately over-represent admin-console traffic.** A gateway's own config
API is the hardest benign traffic a firewall ever sees: file paths, regexes, TLS
material, CIDR blocks, SecLang. If a ruleset produces false positives anywhere,
it produces them there first — and it did.

**Power is still bounded.** 1,330 requests validate `High` (1 in 1,000) but not
`Certain` (1 in 10,000). Only production traffic closes that, and `gwaf
calibrate` says so on every run.

## Protocol traffic: preflight and gRPC (asked by the adopter, not predicted)
gateon reported that **Coraza blocks CORS preflight**. Probed gwaf empirically
rather than reasoning about it.

**Preflight passes, by construction.** The CRS rules that break it — a narrowed
method allowlist, "missing Accept header" (920300), "POST without
Content-Length" (920180) — are protocol-conformance rules gwaf never had. There
is now a test so none arrive by accident. A blocked preflight is the worst
failure to diagnose: the browser reports only an opaque CORS error with no
mention of a firewall.

**gRPC exposed a real bug: 1.2% of random protobuf bodies were blocked.** One
request in eighty-three, no attacker involved. Two causes:
- Rule 4901's `$(` is **two bytes**; in a few hundred random bytes it appears
  about 1 in 130.
- The SQL tokenizer finds tautologies in random bytes.

**Root cause: binary data was being inspected as text.** Fixed by extracting
**printable runs** (≥8 bytes) from binary content and inspecting those, so
framing bytes are never presented as a sentence. `IsBinary` sniffs content
rather than trusting the declared Content-Type, which is attacker-controlled.

Also fixed the underlying precision bug: **`$(` alone is not evidence** at
Certain confidence — it is jQuery, a Makefile, a pasted shell snippet. Command
substitution is dangerous when it substitutes a *command*, so the literals now
name one (`$(cat`, `$(curl`, `` `whoami ``...).

Result: **1.2% → 0.00%** on 3,000 random bodies, detection unchanged at 76/76,
and payloads inside protobuf string fields (6/6) and JPEG polyglots still caught.

**This also affected uploads** — every multipart file part has 8 KiB inspected,
and 8 KiB of JPEG is 8 KiB of chances. Same fix covers it.

Corpus now 1,435 requests including preflight and gRPC framing, so this is
measured every run rather than remembered.

## WebSocket/SSE tokens and base64 uploads (adopter question, three findings)
Asked how gwaf handles WebSocket/SSE with long tokens in **query parameters**
(browsers cannot set headers on those APIs, so it is the only option) and
base64 file content in JSON/protobuf fields. Probed rather than reasoned.

**1. A real bypass.** Values over `MaxValueLen` were **silently truncated**. Pad
64 KiB, append payload, gwaf reported `no_match` — "analysed and clean" — while
the origin read the whole value. docs/PERFORMANCE.md §4 forbids exactly this
("half-inspection is indistinguishable from a bypass") and the code was doing
it. Now: oversize is a **decision** under FailMode, never truncation. Default
raised 64 KiB → 2 MiB so real base64 uploads fit, since base64 expands 4/3 and
the ceiling has to exceed `MaxBodySize`, not sit under it.

**2. Base64 cost 913× more than it should.** A 700 KiB base64 field burned
**20M fuel** (62% of the default budget) and 20ms, because detectors were
tokenizing encoded binary as prose. Base64 is encoded binary that happens to be
printable. Skipping it is a coverage hole — the origin decodes it, and a
base64-encoded web shell is a real technique — so it is **decoded** and the
decoded content inspected. 20,026,548 → 21,926 fuel. Same principle as
everything else: inspect what the origin will act on.

**3. A missing rule.** A base64-encoded PHP web shell was the 1 of 6 payloads
missed — gwaf had no rule for PHP code in a request. Added 4004 at **High**, not
Certain: a code-sharing site or CMS template editor legitimately carries PHP
source, and those should scope an exception rather than lower the tier globally.

WebSocket upgrade, SSE, and long tokens (up to 87 KiB, both base64 alphabets)
all pass. 0/1500 false positives on base64 JSON bodies, 0/1500 on base64 query
tokens.

## Transport shapes (adopter list): compression was a total bypass
Probed the full list — chunked, HTTP/1.1/2/3, GraphQL subscriptions, gzip,
brotli, XML/SOAP, gRPC. Most held. Three real gaps.

**1. Compression was a COMPLETE bypass.** gzip/deflate a payload and gwaf saw
nothing; the identical payload plain was blocked. There is no grammar in a
DEFLATE stream, so every detector found nothing and the request was reported
clean while the origin decompressed and acted on it. **The entire firewall,
disabled by one header.**

Fixed: decompress before anything else, using stdlib only (`compress/gzip`,
`flate`, `zlib`) so zero dependencies holds. gzip is also **sniffed** by magic
number, because an origin that sniffs decompresses a body whose header says
nothing — same multi-interpretation reasoning as everywhere else.

Bounded against decompression bombs (8 KiB → 8 MiB rejected). **Brotli cannot be
decoded** without a third-party library the core module will not carry, so it is
`ReasonUndecidable`, never passed through — passing it would restore the exact
bypass.

**2. Request smuggling was never built.** CONCEPT.md §11 specified desync
detection; a probe showed a CL.TE conflict passing cleanly. Now checked *before
any rule runs*, because ambiguous framing means gwaf may be inspecting a
different request than the origin will process. **`ReasonDesync` is the one
reason FailOpen does not soften**: an ambiguously framed request is potentially
*two* requests, the second of which no firewall has seen.

**3. The body-mirror mechanism was selecting by TAG.** Adding the XXE rule with
an `xxe` tag produced no body counterpart — nothing failed, the rule simply was
not there. Now mirrors by what a rule *reads* (`readsArgs`), removing the class
of mistake. That also silently fixed traversal rules, which had the same gap:
`..%2f..%2f` in a JSON body was uninspected.

Added rule 4005 for XML entity declarations (XXE + billion laughs). SOAP, plain
XML, DOCTYPE-without-entities, GraphQL queries/subscriptions/introspection, and
all four protocol versions pass.

## SHIPPED: response phase — and a no-op I had shipped
`WithResponseInspection` **buffered the entire response and inspected nothing**.
`Transaction` had no `ProcessResponseHeaders`/`ProcessResponseBody` at all — the
phases existed in `types`, the engine could evaluate them, and there was no
public API to drive them. So the option cost streaming and time-to-first-byte
and returned nothing. Not a missing feature: a cost with no benefit.

**gwaf never buffers** (ownership test). `WriteResponseBody` accepts chunks the
embedder chooses to give; give it nothing and it reports it saw nothing rather
than that the response was clean. The middleware offers buffering **opt-in**,
because an integration layer may make one reasonable choice and the core may not.

Header phase runs **before the first byte is written** — the only moment a
leaking response can still be stopped. Body phase catches what was in the body
all along.

Rules 6001-6003 (private key, stack trace, database error), all **High not
Certain**: a paste bin, an error-tracking API, and a database console each
legitimately return one of them.

Response mirrors are **generated** (`withResponsePhase`), symmetric with
`withBodyPhase`, for the same reason — the validator rejected hand-written
rules targeting RESPONSE_BODY at the header phase, which is the class of
mistake generation removes.

## DX: Decision is loggable in one line
`slog.LogValuer` + `String()`. The first thing any embedder does with a Decision
is log it. Includes `interpretation`, because a payload found only under an
alternative decoding is the most confusing thing to see in a log — the bytes on
the wire look harmless and the firewall appears to have malfunctioned.

## FINDING: 76/76 was a decoding score, not a detection score
The evasion corpus was organised by **technique** only — 17 encoding classes
(case, whitespace, percent, double, overlong UTF-8, NUL, UTF-7, entities...)
applied almost entirely to SQLi and XSS payloads. It reported 100% while five
attack classes had **zero cases**, and 0/0 does not appear in a percentage.

Probing by hand found: SSTI 0/8, NoSQL 0/5, LDAP 0/3, shell 10/14.

The corpus is now **class × technique**, and `declaredClasses` fails the build
when a class gwaf claims to detect has too few cases. A gap has to be visible in
CI rather than found by probing the firewall by hand.

## SHIPPED: detect/nosqli — the attack is a key, not a value
Nothing dangerous appears in any *value* of `{"password":{"$ne":null}}`. The
payload is a key in a position that expected a scalar, so a value-scanning
detector finds nothing. `ARGS_NAMES` + `KindKey` already existed, so the
detector reads a *name* and the prefilter gates on operator tokens normally —
no engine change was needed.

Enumerating the *grammar's keywords* is bounded (the vendor publishes them),
unlike enumerating payload variants. Collisions resolved toward benign:
`$comment` (JSON Schema), and the whole OData `$filter`/`$search`/`$top` family
— a published standard with a large installed base. Losing recall on a
low-value operator beats blocking every OData client.

Two rules, because evidence is not equally certain and a rule carries one
confidence: `$where`/`$function` (code execution in the DB) is **Certain**;
`$ne`/`$gt` is **High**, because a few frameworks expose Mongo operators as
their published filter DSL. Splitting also narrows the eval rule's literals from
50 to 4 — a far more selective automaton.

## Three bugs the NoSQL rule exposed, none of them in the detector
1. **`mirrorToBody` widened every mirrored rule.** It assigned a fixed target
   list, so a name-only rule silently gained value inspection at phase 2 —
   which blocked `{"note":"use $ne to negate"}`. Invisible while every rule
   reads everything. Now derives targets from what the original read.
2. **`readsArgs` ignored `ARGS_NAMES`.** A name-reading rule got no body
   counterpart, so it would catch `?password[$ne]=1` and miss the far more
   common `{"password":{"$ne":null}}`.
3. **ID band collision.** 2501 + `bodyPhaseOffset` (900) = 3401, inside the XSS
   band — an ID an operator would look up as XSS. Now enforced by
   `TestMirrorIDsStayInBand`, not by remembering.

## FINDING: Content-Type was trusted, and that was a total bypass for key attacks
`json.NewDecoder(r.Body).Decode(&v)` — the ordinary Go idiom — never reads
Content-Type. Neither does Express with `type:'*/*'` or Flask with `force=True`.
gwaf did: a JSON body labelled `text/plain` was never parsed, so object keys
were never inspected.

Value-position payloads still matched against the raw body, which is exactly why
nothing failed for so long — the corpus had no key-position attack in it until
NoSQL detection arrived.

`SniffJSON` is now an *additional* reading, same reasoning as `SniffGzip`. Also
applied when the declared type is form-encoded, since a form body never starts
with `{`.

## Query parsing moved from middleware into SetRequestLine
`SetRequestLine` recorded the target but never parsed its query string; only the
`net/http` middleware called `AddArgument`. Rules reading argument *values* also
read `REQUEST_URI`, so they caught query payloads anyway — but rules reading
argument *names* saw nothing unless the embedder happened to parse it. The
NoSQL rules would have been inert for every non-middleware embedder.

Pairs are split but **not decoded**: decoding belongs to the transform chain and
`internal/interpret`, which evaluate every plausible reading. Decoding at parse
time would commit to one, which is the shape of CVE-2026-21876.

## SHIPPED: detect/ssti — delimiters are not the attack
`{{ user.name }}` is Vue, Angular, Handlebars, Jinja, and Liquid. `${var.region}`
is Terraform. `${{ matrix.os }}` is GitHub Actions. A detector keying on `{{`
blocks every CMS, docs tool, and issue tracker — and is most wrong precisely
where template content is the application's whole point.

So `SignalTemplateContext` is weighted **zero**. The verdict comes from what is
*evaluated* inside: Python dunder traversal, app-object access, JVM class
access, Ruby execution, Smarty/Velocity directives. Ships at **High**, because
an app whose users author templates legitimately will send `{{ config.x }}`.

`{{7*7}}` scores 2 and cannot fire alone — `{{ 2*count }}` is a real template.
`self` was dropped from the app-object list: `#{self.name}` is idiomatic Ruby.

## SHIPPED: detect/shelli — position, not presence
The literal command list missed four techniques that contain no literal to
match: glob obfuscation (`/???/c?t`), encode-and-pipe (`echo …|base64 -d|sh`),
fetch-and-pipe (`curl …|sh`), substring expansion (`${PATH:0:1}`). It was also
an active FP: `` `id` `` was a literal, so "use the `id` field" was blocked.

Command names are ordinary English — id, less, who, find, sort, head, at, env —
so the list is only consulted in **command position**, right after a separator.
"first; second; third" is prose; "1.1.1.1; cat /etc/passwd" is not. Tokens are
unquoted first, so `c'a't` and `c\at` read as `cat`.

**Documented limit:** a bare backtick substitution is not reported. `` `id` ``
is command substitution and also Markdown inline code, and blocking it makes the
firewall an obstacle to whoever documents the system. `$(id)` has no such benign
reading and is reported.

## Two bugs in shelli, both found by harnesses rather than review
1. **Literals `/` and `{` broke the zero-rules SLO.** Every request path has a
   `/` and every JSON body opens with `{`, so both made all benign traffic a
   candidate. Fixed structurally: brace expansion is read as a command position
   (drops `{`), and interpreter paths are named specifically (drops `/`).
2. **`globToken` returned early at a separator, skipping its own validation.**
   An ordinary Accept header — `…;q=0.9,image/avif,*/*;q=0.8` — scored as a
   glob command. Restructured to a single validated exit.
3. **Fuzz found `0/nC`**: detected as an interpreter path with no literal
   covering it, so the prefilter would have dropped it. Interpreter paths are
   now matched case-sensitively, which is also simply correct — `/bin/SH` does
   not resolve on a case-sensitive filesystem.

## Open: BenignPOSTJSON is 18.5us against a 15us SLO
Pre-existing, not a regression (HEAD measured 18.7us before this work). Recorded
so it is not mistaken for new.

## SHIPPED: detect/ldapi — unbalanced structure, not keywords
An LDAP filter is a fully parenthesised prefix expression, so the payload closes
the clause it was substituted into and opens one that is already satisfied. What
identifies it is *unbalanced parentheses plus a filter operator in filter
position* — not any attribute name. Enumerating attributes would be the SQL
keyword-list mistake again: the schema is site-specific, the grammar is not.

Parentheses, "&", "|", and "*" are each ordinary alone — "Smith & Sons (Ltd)",
"thanks :)", "search*" — so nothing fires alone except a NUL byte.

**The fuzz harness corrected the weights.** With imbalance at 3 and always-true
at 2, "*)" scored 5 with no declared literal covering it, so the prefilter would
have dropped it and the rule could never have fired on it. Reweighted to 2/2/3/5
so reaching the threshold *always* requires an injected clause or a NUL — which
is what makes the literal set exhaustive. TestThresholdRequiresAnInjectedClause
now states that property directly, because a future reweighting would otherwise
break the prefilter silently.

## SHIPPED: Explain, and a documented API that could not exist
docs/INTEGRATION.md specified `waf.Explain(txID)`. That API **cannot exist**:
looking a transaction up by ID means the WAF remembers transactions, which is
cross-request state and the first ownership test. The explanation now travels
with the `Decision` the caller already holds.

`MatchedBytes` is **copied**, not a view into the transaction arena. The arena
is recycled on Close, so a borrowed slice would report a *different* request's
bytes with total confidence — worse than no explanation. TestExplainSurvivesClose
churns the pool to prove it.

## SHIPPED: rules.Exception, and why the narrow form is the short one
A tuning API where the blunt instrument is easier to type produces blunt
instruments. Exceptions are conjunctive: every field set must match, every field
left zero matches anything, so `{RuleID: 7002}` looks as wide as it is and the
narrow form is the specific one. An exception with nothing set is **refused** —
it would disable every rule everywhere.

`NarrowestException()` computes the tightest suppression for a finding that
already happened, so the correct fix is the one an operator copies rather than
derives. Under time pressure the exception a human writes is the rule-wide one.

**Two bugs found by writing the tests:**
1. **A suppressed hit still contributed its score**, so the request blocked one
   rule later with a message naming a rule the operator never excepted — the
   most confusing possible outcome of adding an exception. `applyExceptions`
   removes the score with the hit.
2. **Generated mirrors have different IDs**, so an exception on the authored
   rule did not cover its body-phase counterpart. Added `Rule.DerivedFrom`: the
   mirror *is* the same detection at another phase, so the relationship is
   recorded rather than inferred, and `NarrowestException` suggests the authored
   ID so the exception covers every phase.

## SHIPPED: multi-module — middleware and examples split out
CLAUDE.md §3 has always marked `middleware/` as a separate module; it was inside
the core module. Nothing there needs a third-party package today — net/http is
stdlib — **and that is exactly why the split had to happen before it does**.
Once gin, echo, and fiber adapters sit alongside it, one module puts all four in
the graph of every embedder who wants one, and the zero-dependency invariant is
already lost.

`examples/` became a module too, because it imports the integrations and a
library must never depend on its own integrations. Side benefit: the examples
now resolve gwaf exactly the way an embedder does, so an example that compiles
is evidence the public API is usable from outside.

The Makefile walks `MODULES` for vet/lint/test/race. A split that CI does not
check is worse than no split — the invariant only *appears* to hold.

## SHIPPED: transform-prefix reuse (internal/engine/stages.go)
Chain grouping applied a chain once per group; the redundancy left was *between*
groups. The core chains are [lowercase], [url_decode],
[url_decode lowercase normalize_path], [url_decode lowercase remove_whitespace]
— eight transform applications per value where five suffice, and 32% of the
profile on a benign 1 KiB JSON body.

Groups are now sorted so shared prefixes are adjacent, and each chain depth
keeps its own buffer so an intermediate result survives for the next chain to
resume from. Ping-ponging two buffers cannot do this — that is the whole reason
for the staging array.

The group/reading loops were **inverted** (readings outside, groups inside)
because reuse is only valid within one reading's bytes. Both orders evaluate the
same (rule, reading) pairs; for benign traffic there is exactly one reading, so
nothing changes semantically at all.

**Measured, interleaved A/B, minimum of 6 runs:** benign GET −14.5%, benign POST
JSON −11.0%. Detection identical (127/127, 0/124), zero allocations preserved,
ruleset scaling still flat.

*Methodology note:* the first attempt reported benign GET +36.9% and
RulesetScaling/100 +136% — nonsense for a change that strictly removes work. The
machine had gone busy mid-run (1554 ns → 7719 ns within one sample set). A
change that cannot cost work and appears to cost 136% is a measurement problem,
not a result. Interleaving A/B and taking minima fixed it.

## The 15us SLO is not met, and is now recorded as such
Benign POST with a 1 KiB JSON body: ~17us against a 15us target. It has never
been met — the previous bench/baseline.txt recorded 30.3us and did not flag it.

Eval is ~80% of the profile with the Aho-Corasick scan the largest component.
Making each rule cheaper has run out of room; the remaining route is **per-route
plan pruning** (CONCEPT.md §6, PLAN.md M3.3), which evaluates fewer rules rather
than cheaper ones.

Recorded in CLAUDE.md §2, bench/baseline.txt, and PLAN.md rather than quietly
rebaselined. A benchmark file that ratchets to whatever the code currently does
is not a gate.

## SHIPPED: corpus 1,435 -> 10,386 across 11 archetypes, and it found five FPs
The calibration tool had been saying this itself: "cannot validate a claim at
certain -- needs ~10001 benign requests." 24 rules claimed Certain and the
corpus could not measure the tier at all. It was also 100% gateon-derived with
values that were *plausible rather than observed*.

Now 10,386 distinct requests across gateon, commerce, cms, graphql, grpcweb,
odata, jsonapi, saas, webhooks, mobile, and cicd. Each archetype was chosen to
be **adversarial to a specific detector**, not to be representative of the web.
Power is 0.0096% (1 in 10,386): the Certain tier is validatable for the first
time.

The generator is per-archetype files so a reviewer can see which surface each
models. Dedup key is (method, target, body, args) — **headers are not in it**,
so header-only variants collapse and inflate nothing.

### It found five false positives immediately

1. **detect/shelli on REQUEST_URI: 20.4%, 800/3923.** A category error. A query
   string uses '&' as *its own* separator, so "?q=x&sort=price" reads as a
   command boundary followed by "sort" — and sort, head, find, id, env, host,
   last, less, more, and w are all ordinary parameter names. Every faceted
   search was blocked. A raw URI is a different language that merely shares
   punctuation; only argument *values* get interpolated into a shell.
2. **detect/shelli on stored command lines.** A CI pipeline API receives
   "cat VERSION | tr -d" in a `run` field because running it is the product.
   Fixed by a real discriminator: injection means a *separator* introduced a
   command into a field that already held something else, so when the **first
   token is itself a command or an interpreter path**, the value is a stored
   command line and its internal separators stop being evidence. Loses nothing:
   an injected payload virtually never begins with a bare command name, and a
   value that is only "cat /etc/passwd" still reports via the sensitive path.
   Rule also dropped Certain -> High.
3. **detect/ldapi on balanced filters.** "(&(uid=*)(!(accountStatus=disabled)))"
   is a directory-sync config an admin saved. ")(" is how a well-formed filter
   separates clauses; only an *unbalanced* one escapes. Always-true dropped
   2 -> 1 so it can no longer complete the threshold by itself.
4. **XSS via the HTML-entity reading.** "Use the <code>&lt;script&gt;</code>
   tag" is how every documentation page writes about script tags, and decoding
   the entities turned correct escaping into a block — the ruleset was punishing
   people for doing the right thing. The entity reading is now skipped when the
   value **already contains raw markup**, because that combination is a
   deliberate author rather than an encoding trick. Uniformly entity-encoded
   payloads (all four evasion cases) still enumerate.
5. **Encoded traversal on a media path.** My own corpus entry was mislabelled:
   "../" arriving in a media endpoint's path parameter is the LFI vector, not
   benign traffic. Removed the entry rather than loosening the rule.

Two corpus entries were corrected rather than the rules loosened, and both are
documented in place with the reasoning — a corpus entry can be wrong, and saying
so is different from moving a ceiling.

### The general lesson
Four of these five were invisible to a single-application corpus. #1 in
particular would have blocked roughly one in five requests of any faceted search
on the internet, and gateon never triggered it because gateon uses
page/pageSize/q as parameter names. **A detector can only be shown safe against
traffic shapes it has actually met.**

## SHIPPED: plan pruning — the 15us SLO is met, after never having been
Benign POST with a 1 KiB JSON body: **16.4us -> 13.0us**, target 15us. Benign
GET 1.5us -> 0.74us. Ruleset scaling 354ns -> 240ns, still flat 10 -> 10,000.
Detection identical, allocations still zero. **Every SLO in CLAUDE.md §2 now
passes.**

It had never passed. bench/baseline.txt recorded 30.3us at one point without
flagging it.

**I was wrong about the route.** I had said per-route plan pruning would close
it — but the SLO benchmark calls `gwaf.New()` with no schema, so route pruning
cannot touch it. Profiling first is what caught that. What closed it was
pruning the plan by *what the value is*, not by what route it arrived on.

### Target pruning (largest, ~20%)
`ChainGroup.targets` is a bitmask of the target kinds its rules read. A value
whose kind no rule in the group names is skipped **before** the transform and
the automaton scan, rather than after the operator call.

Exact, not heuristic: `targetMatches` requires an explicit kind match and an
empty target list matches nothing, so a group that never names a kind cannot
produce a hit for it.

It matters most where the values are most numerous. A JSON body emits every
object key as its own ARGS_NAMES value, and only the two NoSQL rules read that
target — so every key was being transformed and scanned by all four chain groups
to reach a verdict three of them could never have reached.

### Phase pruning (~7%)
When every rule in the body phase is a generated counterpart evaluating
identically to its original, a value the header phase already saw cannot produce
a new finding. `Rule.DerivedFrom` plus an equality check on operator and chain
proves it at compile time; the engine then walks only values that arrived with
the body. Without it the request line, every header, and every query argument
were transformed and scanned a second time to reach the same verdict.

Checked rather than assumed: it stops holding the moment an embedder authors a
body-phase rule of their own, which is why `allMirrors` verifies the operator
and chain rather than trusting the ID relationship.

## Benchmark methodology, again
The first A/B of prefix reuse reported nonsense (+136% for a change that
strictly removes work) because the machine went busy mid-run. Interleaving A/B
and taking minima is the method that works here. Recorded because I have now
been caught by it twice.

## FINDING: gRPC hid a payload in three wrappers, two of them unhandled
Probing gRPC compatibility found two live bypasses. Binary framing already
worked; the other two layers did not.

**grpc-web-text.** Browsers that cannot send binary framing base64-encode the
*entire body*. Base64 is printable, so IsBinary said "not binary"; it has no
grammar, so nothing matched. The payload was simply invisible. Base64 decoding
existed but only per *parsed field* — and here there are no fields, the whole
body is one run. `minBase64Run` is 64 so that a token inside a field is not
mistaken for encoded content; a whole body that is nothing but base64 alphabet
is not a token, so `IsBase64Body` uses a floor of 8 (the smallest gRPC frame).

**Per-frame compression.** gRPC compresses *per message*, inside the frame,
named by `grpc-encoding`. That is a different mechanism from Content-Encoding
and invisible to it, so the decompression added earlier never saw it. Same
bypass class, same shape: DEFLATE has no grammar, nothing matches, the origin
decompresses and acts on the payload.

`internal/body/grpc.go` unframes and decompresses. `IsGRPCFramed` is strict on
purpose — every frame well formed, last ending exactly at the body's end —
because a loose check would slice payloads out of the middle of a JPEG and
inspect the pieces as messages. An undecodable codec (snappy, zstd) sets
`undecodable` and reaches `undecodableBody()`, never passing silently.

### The regression this caused, and why it is instructive
Unframing reintroduced the **1.2% chance-match failure at 1.85%**, and the cause
was subtle: stripping the frame header removes its first byte, the compression
flag, which is **zero for an uncompressed message**. That NUL was what made
`IsBinary` fire on the whole frame. Without it, a 256-byte protobuf payload
containing no NUL of its own reads as *text* and goes to the detectors whole.

So the original protection had been resting on an accident. The fix decides by
*type* rather than by content: an unframed gRPC message is protobuf unless it
sniffs as JSON (Connect frames JSON in streaming mode), and `IsBinary` is not
consulted for frame payloads at all.

The test that caught it asserts a ceiling of **zero**, which is why a 1.85%
regression failed loudly instead of looking like noise.

### Buffer aliasing, caught by reading rather than running
The first version passed `tx.inflateBuf` as the frame scratch. A
Content-Encoding-compressed body is decompressed *into* that buffer and then
arrives at the unframer as its input — so it would have overwritten itself
mid-parse. Separate `tx.frameBuf` now. Found while the Bash tooling was
unavailable and the only option was re-reading the diff.

18.7M fuzz executions against `UnframeGRPC` with forged lengths, no panic.
Detection 132/132, false positives 0/124, all SLOs still met.

## FIXED: a public extension point that was impossible to implement
`Operator.Cost()` returned `budget.Fuel` from `internal/budget`. Go's
internal-package rule is keyed on **import path**, so every first-party detector
satisfied the interface and a vendor at their own module path could not:

    myOp does not implement rules.Operator (missing method Cost)
    use of internal package .../internal/budget not allowed

`Operator` is one of the five interfaces CLAUDE.md §4 calls "the most expensive
API surface in the project -- third parties implement them, so post-v1.0 they
are frozen hard." It had never been implementable, and **no test in the tree
could have seen that**, because everything in the tree is on the permitted side
of the rule. My own seclang regex operator compiled for exactly that reason.

`Fuel`, the cost constants, and the default ceiling moved to `types/` — which is
where public value types belong and is frozen under semver alongside the root
package. `internal/budget` keeps `Meter` (a third party needs to *declare* a
cost, never run the accounting) and aliases `Fuel = types.Fuel`, so the two
names denote one type and in-tree code kept compiling.

Cost constants are exported too, deliberately: an operator returning a number
picked out of the air would make the DoS-bound arithmetic wrong in a way nothing
would catch.

### The enforcement matters more than the fix
`test/extension` is a module declaring itself **`example.com/gwafvendor`**. It
implements Operator, Transform, and Action from a foreign path with
compile-time assertions. If any of the three grows a method returning an
unexported type, it stops compiling.

That is the general lesson: **a broken extension point that every in-tree
implementation satisfies is invisible to any test living in the tree.** The
module path *is* the test.

Its tests also check two things a vendor would otherwise discover in production:
a vendor operator declaring literals is prefiltered like any other (zero rules
evaluated on benign traffic), and its declared cost is charged against the fuel
budget.

### Scope note
Only **three** of the five documented extension points exist as interfaces today.
`Detector` and `Resolver` are named in CLAUDE.md §3 and docs/RULES.md §4 but are
not defined in code. Worth either defining them or correcting the count before
v1.0 — claiming five and shipping three is the same class of gap as claiming a
tier the corpus cannot measure.

Also created CHANGELOG.md, which CLAUDE.md §4 required for breaking changes and
which did not exist.

## SHIPPED: rules.Resolver — the scope line finally has an implementation
CLAUDE.md §1 says "out-of-scope signals arrive as Resolver inputs — gwaf
*consumes* a reputation score, it never *maintains* one." That sentence had no
implementation: rules could only ever match bytes gwaf read off the wire, so an
embedder computing a bot score had nowhere to put it.

`types.TargetResolved` + `rules.Resolver` + `Transaction.AddResolver`.

**Per transaction, not per WAF**, because a resolver almost always closes over
data specific to one request and a WAF is shared by every goroutine.

**Called only when a rule reads it**, which is why it is an interface rather
than a setter: a signal is usually out of gwaf's scope *because* obtaining it is
expensive — a reputation lookup, a fingerprint, a database read — so paying for
it when nothing reads it would undo the reason for keeping it out. Compile-time
`Ruleset.NeedsResolver(phase, name)` decides. Called at most once per request.

### A design error the tests caught
First version recorded the per-value key ("score") while `Target.Name` names the
*resolver* ("reputation"), so the two never matched and the signal never reached
a rule. Fixed by qualifying keys — `reputation.score`, `reputation.asn` — with a
segment-boundary prefix match, so a rule reads either grain:

    {Kind: TargetResolved, Name: "reputation"}      // every value
    {Kind: TargetResolved, Name: "reputation.asn"}  // one of them

Boundary-anchored on purpose: "rep" must not select "reputation.asn". A partial
name silently widening a rule to a collection its author never meant is the
quiet class of mistake this package exists to prevent.

## CORRECTED: four extension points, not five
`Detector` was documented as a fifth, "plugging into the L1 semantic tier rather
than the rule tier". **There is no such tier.** The engine dispatches through
`Operator.Eval` and nothing else (`internal/engine/eval.go`), and all six
first-party detectors expose `Operator() rules.Operator`.

Verified before deciding rather than assumed. Defining a `Detector` interface
would have been building a second path to the same dispatch — describing an
architecture nobody built. A third party writing a semantic detector implements
`Operator`, exactly as sqli/xss/shelli/ssti/nosqli/ldapi do.

Claiming five and shipping four is the same class of gap as claiming a
confidence tier the corpus cannot measure: the doc was the thing that was wrong.
