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

## SHIPPED: protobuf wire parsing + schema/grpc
### The premise, verified before building
Printable-run extraction drops runs below `minTextRun` (8). That floor is right
for a JPEG and wrong for a document made of fields. Measured:

    "1' OR 1=1"  (9 bytes)  detected
    "'OR 1=1"    (7 bytes)  MISSED

Both are SQL injection. The second was invisible only because a heuristic for
unstructured binary was applied to a structured document.

`internal/body/protobuf.go` parses the wire format with **no descriptor** — it
is self-describing enough to walk — and emits length-delimited fields under
their number path ("3", "4.1"). Varints and fixed-width fields are numbers and
are skipped: no sequence of digits is an injection.

**The one ambiguity:** wire type 2 does not distinguish a string from a nested
message. Both readings are taken when both are plausible (parses cleanly →
recurse; not binary → also emit), which is the rule internal/interpret follows
for ambiguous encodings.

Zero allocations, 367ns/op, linear scaling to 64 KiB.

### schema/grpc
Compiles a FileDescriptorSet (what `protoc --descriptor_set_out` already emits)
into `schema.Operation`, one per RPC, path `/pkg.Service/Method`. Fields are
named by number path so they match exactly what the wire parser emits — that
alignment is the whole trick, and it means the core never needs a descriptor.

int32/bool/enum → provably inert, skipped entirely. **bytes is deliberately NOT
inert**: the declared type says nothing about the content, and an upload, a
sub-document, and a base64 blob all arrive as bytes.

Strict mode matters more here than for JSON, because proto3 *preserves* unknown
fields by design — a service will accept and forward a field nobody declared.

### Two mistakes, both mine, both caught by tooling
1. **My test helper encoded a protobuf tag as a single byte.** Field 99's tag is
   794, which truncates to 26 — field 3, a field the schema declares. So a
   strict-mode test "passed" an undeclared field that was never undeclared. The
   helper was wrong, not the implementation.
2. **`go vet` caught `append(x)` with no values** in a test. Caught only because
   the full gate runs vet across every module.

### A fuzzing lesson worth keeping
`FuzzParseProtobuf` appeared to hang: workers froze at 0 exec/sec. It was **not**
a parser hang — all corpus entries replay in 0.28s, and a 10-second per-exec
timeout never fired across 39.1M executions.

The real bug was in the harness: **`t.Fatal` called from inside the parser's
emit callback**. `t.Fatal` is `runtime.Goexit`, and unwinding out of a recursive
callback wedges a fuzz worker instead of reporting a failure. Collect findings
in the callback and assert after it returns.

The residual 0/sec readings are fuzzer bookkeeping plus machine contention —
the same noise that produced a nonsense +136% benchmark earlier in this session.

## FINDING: the SLO table was written in percentiles and nothing measured one
CLAUDE.md §2 states p50 and p99 targets. docs/PERFORMANCE.md claimed "reported
every run: p50, p99, p99.9". **Neither was true.** `go test -bench` reports a
*mean*, so three SLOs were unverified as written and **p99 < 100µs was
unverified entirely**.

Same class of gap as claiming a confidence tier the corpus cannot measure: the
document asserted a measurement that did not exist.

`latency_test.go` measures 200,000 samples per workload and reports
p50/p90/p99/p99.9/max, asserting the CLAUDE.md bounds. First real numbers:

    benign GET            p50 875ns   p99 1.0us
    benign GET + query    p50 2.96us  p99 3.38us
    benign POST 1KiB JSON p50 13.2us  p99 15.8us   (target 15us p50, 100us p99)
    blocked SQLi          p50 709ns   p99 875ns

**Blocking is faster than allowing** — a blocked request stops at the first
terminal rule and never reaches the body phase.

Maxima are 19-208us and move wildly between runs while p50 moves <1%: that is
GC, not gwaf, which allocates nothing on these paths. Reported rather than
trimmed, because a benchmark that subtracts GC measures a program nobody runs.

Per-transaction footprint also had no measurement. Now: **2.3 B/tx allocated,
heap growth −37 KB over 20,000 transactions** (it shrinks).

### The gate caught the mistake in the fix
`TestLatencyDistribution` failed under `make check` because `-race` slows the
request path by an order of magnitude. A latency bound measured under race
instrumentation describes a build nobody deploys. The repo already had
`raceEnabled` for exactly this reason (the zero-allocation SLO); reused it.

## SHIPPED: docs/BENCHMARKS.md + `make bench-publish`
Prints commit, Go version, host, and CPU before any number, because a benchmark
without provenance is a number nobody can disagree with — and a number nobody
can disagree with is not evidence.

§5 is "What these numbers do not show" and is the part that matters: one machine
and one architecture, a synthetic corpus, **no comparison against another WAF**,
sampling overhead included, no multi-hour run. A comparison where only one side
was tuned is worse than none, so none is published.

## SHIPPED: detect/graphql — abuse with no payload
Verified before building: a 200-deep query, a 2,000-alias amplification, full
introspection, and a circular fragment **all passed gwaf untouched**. There is
nothing in any of them a string matcher could object to — the document is valid,
the field names are real, and the cost is in its *shape*.

In scope despite looking like rate limiting: every property is computed from one
document in isolation, no memory and no identity, which is exactly the scope
line. "How many requests has this client sent" is the embedder's; "how much work
does this one request demand" is not.

The scanner respects strings and comments rather than counting braces — one
argument value `"{{{{{{"` would otherwise register as six levels — and skips
argument lists, so `first: 10` is not a selection.

## The decision that mattered: introspection is opt-in
My first version put an introspection rule in the **core** ruleset. An existing
test caught it immediately: the benign corpus contains introspection queries,
because that is how GraphiQL, Apollo Studio, and every code generator discover a
schema.

Blocking it by default would break them on the day somebody adopted gwaf — the
"gets switched off within a week" failure the core ruleset exists to avoid.
CLAUDE.md §1: *rules that need tuning belong in an optional bundle, not here.*

So `graphql.IntrospectionRule(id)` is exported and an embedder opts in with one
line. The structural limits stay in core, because a document past its depth
limit is abusive whoever sent it. Introspection is deliberately **not** in the
evasion corpus either — an entry there would assert the opposite.

## A silent edit that the probe caught
Adding `Transforms: []rules.Transform{transform.URLDecode}` to the introspection
rule **did not apply**: gofmt had realigned the struct fields, so my search
string no longer matched and the replace was a no-op. Nothing failed — the rule
simply had an empty chain.

It only showed as a *GET* failure, because a POST body arrives already decoded
and the GET form carries the whole document percent-encoded in the query string.
Without a chain the detector reads `%7B__schema%7D` as one long identifier and
every structural count comes back zero.

**Lesson: a scripted edit that does not match is a silent no-op.** Verify by
reading the file back, not by the absence of an error.

## SHIPPED: gwaf-seclang report|convert
The in-repo half of adoption. `report` first, deliberately: the number worth
knowing before a migration is not how many rules arrive but which ones do not,
and why. A conversion that silently drops a third of a ruleset is worse than
none, because the operator believes they migrated.

`convert` emits **Go source**, not a runtime .conf loader. The point of
migrating is to stop having a second configuration language: generated Go is
compiler-checked, `git diff`-able, reviewable, and costed by `gwaf lint`, and a
typo in a target name is a build failure rather than a rule that silently never
fires. That is the "typed, compile-checked config" axis.

Output goes through `go/format`, which orders imports *and* fails on invalid Go
— so a converter bug is an error at conversion time rather than a build failure
in somebody else's repository with a file they did not write.

An operator with no source rendering is an **error**, not an omission: emitting
code that does not compile would be the converter's version of silently
weakening a rule.

## The same silent-no-op mistake, twice in one session
A scripted string replace failed to match because **gofmt had realigned the
code** between writing it and editing it. First time it left the GraphQL
introspection rule with no transform chain (invisible except over GET). Second
time it left a stale test assertion.

**Use the Edit tool for anchored edits — it errors on mismatch. A python
`str.replace` that does not match is a silent no-op.**

## Item 5 (adoption) is where I stopped, on purpose
The gateon `wafengine` adapter and shadow mode mean modifying a *different
repository*. That is an outward-facing change the user has to authorise, and
they have already corrected me once for drifting gateon-specific. The in-repo
enabler is done; the cross-repo step is theirs to start.

## FOUND BY EXAMPLE: two defects no unit test could see

Writing `examples/customrules` — a runnable program using every extension point
the way a user would — found two bugs the whole test suite had missed. Both were
invisible for the same structural reason: **the tests were written by the people
who knew the internals**, so they never used the API the way the documentation
describes it.

1. **`op.Func(...).WithLiterals(...)` did not compile.** `Func` returned the
   `rules.Operator` interface, so the method on the concrete type was
   unreachable; every in-tree caller happened to assert to a hinter first. It is
   the exact form documented in RULES.md §5 since the file was written. Fixed by
   returning `*op.FuncOperator` (breaking, recorded in CHANGELOG).

2. **A `Resolver` never fired when a rule read one value from a collection.**
   The compile-time index was keyed on the full target name, so a rule targeting
   `reputation.asn` looked up `"reputation.asn"` while resolvers register under
   `"reputation"`. The rule silently never matched. Fixed with `resolverSegment`;
   regression test in `test/extension`.

**The lesson, which generalizes:** `test/extension` proved the interfaces are
*implementable* from a foreign import path. It could not prove they are
*usable*, because it was written to exercise the interfaces rather than to solve
a problem. An example written to solve a problem found both in one afternoon.

**Examples are tests.** `examples/customrules` has a `main_test.go` that runs it
and asserts every documented row, so a change that breaks the API's advertised
shape fails the build rather than rotting a README.

## FINDING: 139/139 was honest, and the class list was the thing with the hole

An attack simulation of current real-world payloads (PHP wrappers, PHPGGC
gadgets, Log4Shell, Spring4Shell, SSRF, prototype pollution) measured **40/62**
against a ruleset reporting **139/139, 100%**. Both numbers were correct.

`declaredClasses` exists because "a technique-only corpus cannot see a missing
attack class" — 76/76 once measured canonicalization rather than coverage. The
identical failure had reappeared **one level up**: the corpus could not see a
missing class because the *class list itself* omitted it. A class absent from
both is invisible twice over.

**Rule going forward: name the class in `declaredClasses` first, watch the build
fail for want of cases, then write them.** Now 169/169 across 17 classes.

### Two "misses" were correct behaviour, already decided and measured
The simulation flagged both; the code was right and the simulation was wrong.
Re-fixing either would have reintroduced a documented false positive.
- **Backtick command substitution** — `` `id` `` is Markdown inline code.
  `$(id)` has no benign reading and *is* reported.
- **`{{7*7}}`** — scores 2, below threshold, because `{{ 2*count }}` is a real
  template. `SignalTemplateContext` is weighted zero on purpose.
- **Bare `javascript:`** — scores 3; a scheme in prose is a sentence. In an
  `href` it scores 5 and blocks.

The simulation now carries a `skip` field recording *why* each is deliberate, so
the next person to run it does not "fix" them either.

### Three catches were coincidences, which only stripping the payload revealed
`system('cat /etc/passwd')` blocked on the `/etc/passwd` literal, not on PHP;
`system('id')` passed. A Laravel gadget blocked on `;` in `id;uname`; the same
gadget with `phpinfo` passed. **A rule that fires on a coincidence is not
coverage** — check what *else* was in the payload before believing a green row.

### The corpus gained an `adjacent` archetype
Every other archetype models an application and happens to exercise the
ruleset. This one is the reverse: each request exists because a specific rule
could plausibly match it. It removed `ldap://` and `jar:` from the SSRF scheme
rule and `${env:` from the Log4j rule — all three matched nothing in the 10,386
requests that existed, which proved only that the corpus had never seen an
identity integration or a Java build. Zero-FP against traffic you never
collected is not a measurement.

### Cost of seven new rules: nothing measurable
766ns benign GET / 0 allocs, 13.4us POST JSON, ruleset scaling flat at ~231ns
from 10 to 10,000 rules. Prefilter grew to 225 literals / 3,095 states. This is
the compiler thesis paying out: rules are compile-time input, not runtime work.

### SSRF is in scope, but only lexically
Passes all five ownership tests — the target is a literal in the value, no
memory needed. But gwaf must **never resolve a hostname**: DNS is a network call
and test 3 puts it with the embedder. So DNS rebinding is explicitly not covered
and is documented as such rather than left as an implied promise.

## SHIPPED: broad real-world simulation — and the schema tier it justified

Simulated WordPress, malware droppers, CVE exploitation, nginx/Apache/cPanel,
Go, Java, DDoS, AMP/host spoofing, and gambling abuse. **37/87 in-scope at the
start, 53/87 after ten new rules, 0 false positives throughout.** 16 cases were
tagged out-of-scope up front (rate limiting, connection lifecycle, authorization,
identity correlation) rather than counted as misses.

### The finding that mattered: not every gap is a missing rule
A stake of `-5000` is a valid number. `"BTC"` is a valid string. `/cpanel` is a
valid path. No signature describes them because nothing is wrong with the bytes
— only with what they mean to *this* application. That is the schema tier, and
building the simulation is what forced three real gaps in it:

1. **`Field.Min`/`Max` did not exist.** Type validation answers the wrong
   question: "is this a number" accepts a bet that pays out the house's money.
2. **`Field.Required` was dead.** Documented as enforcing presence;
   `ViolationMissing` was declared and never assigned anywhere.
3. **No closed-world mode.** `Schema.Closed()` now rejects unmatched routes,
   which answers product-path reconnaissance without naming a single product.

### The latency gate caught a regression review did not
`IDConfigTraversal` used `pathChain` on `argTargets`. pathChain previously ran
only on the request URI, so this added a (chain x target) combination and every
body field got materialised a second time. **13.4us -> 16.5us, breaking the 15us
SLO.** Switching to decodeChain fixed it with no loss: the payload has no
whitespace and NormalizePath would collapse the `../` being looked for.

Then `CRLFHeaderRule` was moved **out of core to opt-in**, also on measurement:
it is the only rule needing a chain that keeps line breaks, and that private
chain cost 15.4us vs 13.7us. **A rule may not spend 8% of the budget on requests
it cannot match.** Transform chains are the expensive axis, not literals —
12 chains vs 10 was worth more than 90 extra literals.

### Three bugs found by writing the tests, not the code
- A literal written as `"new java.lang.processbuilder"` matched nothing, because
  decodeChain strips whitespace and the value arrives as one run. The corpus
  case caught it; review had not.
- `WithRuleset` **accumulates onto the default set** rather than replacing it,
  so the `append(core.Default(), extra)` form I had written into three doc
  comments fails with a duplicate-ID error. Anyone copying it would have hit it.
- The RFI literal hint was `http://`, which appears in a large share of ordinary
  JSON bodies, making the rule a prefilter candidate on traffic with no chance
  of matching. The script extension is the rarer half of the same conjunction.

### Scope calls held rather than papered over
Host/X-Forwarded-Host spoofing needs to know the legitimate host (embedder).
Open redirects need to know which parameter is a redirect target (schema).
Go template `{{.Env}}` is the same delimiter tradeoff already settled for Jinja
— and the benign corpus carries `{{ .Name }}` to prove it.

## SHIPPED: file upload, both halves (driven by a real compromise)

An adopter reported attackers writing files into their WordPress. Simulated the
full chain: 16 upload evasions plus 4 requests for what had already landed.

**The upload half was already strong — 14/16 — and for a reason worth keeping:
the detectors read file *content*, so every filename trick failed.** Double
extension, `shell.php\x00.jpg`, uppercase `.PHP`, trailing dot, trailing space,
`.phar`, `.phtml`, a plugin zip, and a `nopriv` AJAX upload were all blocked by
"PHP code in request value" on the body. Filename-extension filtering is the
thing every upload filter does and the thing every bypass defeats; reading the
content is why gwaf did not need one.

### The gap was the second half, and it is the one that matters post-breach
A file that arrived before gwaf was deployed, through a plugin it does not sit
in front of, or with stolen credentials, is already on disk. Blocking uploads
does nothing about it. **Requesting it is the step that turns a file into code,
and that request gwaf can always see.** Rule 1010.

**Scope discipline that made it shippable:** the rule is a script under an
*upload directory*, not "a PHP file". Every WordPress plugin is a PHP file under
wp-content/plugins and some are reached directly, so the broad form would block
WordPress itself. The broad form exists as `WordPressHardeningRule`, opt-in,
with the trade stated.

### Also: .htaccess as the upload-filter bypass
Blocked `.php`? Upload a `.htaccess` with `AddType application/x-httpd-php .jpg`
and then upload the shell as an image. Both files individually pass; together
they are RCE. Rule 4015 matches the *directives*, not the filename, because the
filename is the part an upload handler may rewrite and the content is the part
that has to survive to work. High rather than Certain: a hosting control panel
manages .htaccess for customers, and that is its payload rather than an attack.

## FOUND: both security scanners were effectively off

Asked to make security scanning a standing rule, and checking first found the
rule was already written and not enforced.

**staticcheck had never run.** `lint` probed with `command -v staticcheck`, and
make's PATH is not the developer's, so it missed the binary sitting in
`GOPATH/bin` and printed `staticcheck not installed; skipping` next to a passing
gate — for the life of the project. **An analyser that quietly opts out is worse
than one nobody wired up, because the green tick says it ran.** Now resolved via
`GOPATH/bin` and a hard failure when absent. (All ten modules were clean, so
nothing was hiding — but that was luck, not a control.)

**govulncheck scanned only the root module — the one module with zero
third-party dependencies by design.** It was scanning the single place a
dependency CVE cannot exist, while every module an adopter actually pulls in was
skipped. Scanning all ten immediately found the gin adapter pinning
`golang.org/x/net@v0.25.0` (12 known vulnerabilities, fixed in v0.55.0) and
`x/text@v0.15.0`. echo and fiber carried the same class. Bumped; 12/3/4 imported
vulnerabilities went to 0/0/0, core still zero third-party.

**`make check` now includes `vuln`.** It was a separate target somebody had to
remember, which for security infrastructure is the same as not having it.

### The generalisation, now in CLAUDE.md §4 and §6
A gate that skips when a tool is missing reports success it did not earn. If a
check cannot run, that is a failure, not a warning. And "imported but not
called" vulnerabilities matter here specifically, because gwaf ships adapters —
an adopter inherits our transitive pins whether or not we call the bad path.

## REJECTED: backtick concatenation heuristic for command injection

A pentest harness (test/pentest) confirmed `localhost`id`` reaches the backend:
detect/shelli deliberately does not flag a bare command word in backticks,
because ``id`` is also how Markdown writes inline code ("use the `id` field"),
and blocking it blocks documentation. Invocation forms (``cat /etc/passwd``,
``id;whoami``, `$(id)`, `;id`) are all caught.

Proposed fix: flag the bare word when the opening backtick is **concatenated to
preceding data** (`isWordByte(src[i-1])`), on the theory that prose is
space-delimited and an injection is appended to the value already there. Built
it, then measured the false-positive cost against a realistic benign corpus.

**Result: 9/9 false positives.** `sh`id``, `t`ls``, `config`env`` (JS tagged
template literals) and `the`id`column`, `a`node`server`, `see`less`output`
(minified inline code) all tripped. The reason is structural, not tunable:
`localhost`id`` (attack) and `config`env`` (benign) are the *same shape*
`word`command``, and the command set overlaps ordinary vocabulary heavily —
id, env, head, tail, more, less, node, php, ps. Only field context — is this a
place backticks are legitimate? — separates them, and gwaf is stateless and
field-agnostic by design, so it cannot have that context.

**There is no FP-safe structural heuristic here.** The bare-word backtick
tradeoff is fundamental, not merely conservative. Locked by
detect/shelli TestConcatenatedBacktickStaysUnflagged, which fails if the
heuristic is re-added. If this ever needs revisiting, it belongs to the embedder
(who knows the field) via a per-route policy, not to core detection.

## FIXED: three gaps the pentest harness found (all handled by gwaf)

The cve/java/nodejs/golang/xss/malscript phases surfaced three real gaps. All
three are now closed; each fix was measured cost-neutral against the SLO.

### 1. Nested constructor.prototype pollution in JSON bodies
Flat `__proto__` was caught; `{"constructor":{"prototype":{...}}}` was not,
because the JSON parser emits each nesting level as a separate ARGS_NAMES value
(`constructor`, `prototype`, `isAdmin`) so none contains the literal
`constructor.prototype`. A query string already flattens to
`constructor.prototype`, which is why the query form was caught and the JSON form
diverged.

Fix: `Transaction.recordArgName` additionally records the *full dotted path* for
a nested key — but **only when the key is a positional primitive** (`prototype`,
`__proto__`, `constructor`). The first attempt joined every key and measured a
**28% regression** on benign JSON (the parent repeats for every child, inflating
the bytes every rule scans), caught by a paired before/after benchmark. Gating
on the three primitive names via length-checked compares made it free for
ordinary keys. NoSQL is unaffected — it scans a name for `$` anywhere.

### 2. HTML-entity-encoded scheme in an XSS href
`java&Tab;script:` and `javascript&colon;` evaded: `matchesSchemeFolded` skipped
raw control bytes but not their entity forms. Added `decodeCharRef` (numeric
`&#58;`/`&#x3a;` plus the named refs that obfuscate a scheme: tab, newline,
colon, sol), so the matcher decodes a reference and treats a control/space code
point as skippable and any other as a folded scheme byte. Fuzz clean at 16M
execs; benign `&amp;`, querystring `&`, and `&colon;` in prose all still pass.

### 3. Apache double-percent-encode traversal (CVE-2021-42013)
`%%32%65` is a malformed escape a strict decoder leaves alone and a permissive
one (Apache) collapses to `%2e` then `.`. `interpret.Detect` marked
`ClassDoubleEncoded` only on `%25`; added `%%` as a second trigger, so the
doubly-decoded reading is produced and rule 1004 sees `../`.

**Scope note that mattered:** against a *Go* origin this payload never reaches
gwaf — net/http returns 400 for the malformed encoding first. So the pentest
harness does not send it through the Go target (that would measure net/http);
it is gated directly in the evasion corpus, where gwaf sees the raw bytes as a
proxy in front of Apache would. A 400 is a defense, just not gwaf's — counting
it as a gwaf miss would have been dishonest.

### The meta-lesson
Two of the three were found only because the harness ran real payloads through
the full net/http path, not the detector in isolation. The nested-pollution and
entity-scheme gaps were genuine; the Apache one was half measurement-artifact
(net/http 400) and half real (gwaf-as-proxy), and separating those two halves is
what kept the fix and the harness both honest.

## SHIPPED: proxy/ — the reference reverse proxy (tier 3)

gwaf could not protect a PHP, Node, or WordPress app, because a library protects
only the process that imports it. `proxy/` closes that: ~325 lines, own module,
pure glue over gwaf + middleware, no detection logic, no rules, no config file
it discovers, no plugin system, no metrics endpoint. Under the ~500 LOC cap.

**Verified end to end with the real binary**, not just tests: health 200 without
the upstream up, benign forwarded to the backend, and SQLi / `wp-content/uploads
/shell.php` / Log4Shell-in-User-Agent all 403.

### staticcheck caught a security bug, not just a lint warning
`httputil.ReverseProxy.Director` is deprecated in Go 1.26 (SA1019). The fix is
not cosmetic: `Rewrite` + `SetXForwarded()` **overwrites** client-supplied
`X-Forwarded-For`, while the Director idiom *appends* to it — which lets a client
forge its own address into the upstream's logs and access rules. This is the
first finding from wiring staticcheck properly (it had been silently skipped for
the life of the project), and it landed on the first new module added after.

### Why a separate module, and why the cap
The module boundary makes tier 3 enforceable: the proxy cannot reach gwaf's
internals even by accident, and an embedder importing gwaf never inherits
httputil or these flags. The LOC cap is the tripwire — a config format, a plugin
system, or a metrics endpoint appearing here means the *library* is missing an
API, and the fix goes there. A PR adding non-glue code to proxy/ is a design bug
report against gwaf.

### It also de-risks the gateon embedding
The proxy and gateon are two drivers over the same tier-1 API. The proxy is the
cheap embedder; gateon is the expensive one. Any API gap surfaces here at ~325
LOC of cost rather than deep in another repo — the same forcing function that
made examples/customrules find two API bugs no unit test caught.

## SHIPPED: prompt injection, shadow-API discovery, audit, telemetry, examples

Four items executed together, each gated. Research-driven rather than guessed:
the OWASP LLM Top 10 2026 (7,714 incidents) still ranks prompt injection #1 and
adds System Prompt Leakage; the API-security literature names shadow APIs as the
most common gap; and standalone WAF has consolidated into WAAP, which validates
gwaf-as-engine + gateon-as-platform rather than growing gwaf into a platform.

### detect/promptinjection: structure, not vocabulary
Same design as detect/ssti and for the same reason. An imperative aimed at the
model scores; a sentence describing one does not. `SignalPromptContext` is
weighted **zero** so prose about prompt injection — every bug report, tutorial,
and this decision entry — cannot fire. Ships High, not Certain: a red-team
console or prompt library produces true matches that are not attacks.

**The end-to-end test caught what unit tests could not.** Wired with decodeChain
every multi-word phrase silently stopped matching, because that chain strips
whitespace and "ignore all previous instructions" arrives as one run of letters.
Uses URLDecode only. This is the third time this session that a whitespace-
stripping chain broke a multi-word literal (java.lang.processbuilder was the
first). **Rule of thumb: a multi-word literal and decodeChain are incompatible.**

### Shadow-API discovery: report the bit, refuse the inventory
`Transaction.UndeclaredRoute` returns one bool about one request. Aggregating is
memory and memory is the embedder's (ownership test 1) — a WAF keeping a running
endpoint inventory needs eviction, cardinality caps, and persistence, which is a
database growing inside a request filter. Reporting works in **both** open and
closed schemas, so the signal survives the switch to enforcement.

### audit/ and telemetry/: the "no UI" corollary, delivered
No dashboard, but every datum a dashboard needs is reachable. audit renders the
narrowest exception as data so a false positive is a scoped fix. telemetry keeps
counters with no unbounded label cardinality, because that is how a metrics
endpoint becomes the outage. **Neither imports OTel** — an exporter is a
dependency the embedder did not choose (ownership test 5); Sink is one method.

### Examples found three wrong claims in one sitting
Zero runnable examples existed despite §2b making them binding. Writing nine
found: a `rules.ResolverFunc` that does not exist (Resolver is an interface with
iter.Seq2), `Reason` rendering as "schema_violation" not "schema", and an example
double-adding a query parameter because SetRequestLine already parses one.

**And they surfaced an honest measurement**: a benign request with *any* query
string evaluates exactly 1 rule, not 0. Pre-existing, verified by stashing. The
"0 rules evaluated" claim is true of the no-query case and rounds the other down;
the example now states both numbers rather than the flattering one.

## SHIPPED: go-ftw conformance — and the number is 31.5%

Built test/conformance (own module; YAML needs a dependency core will not carry)
and ran the real OWASP CRS corpus: 323 files, 5,066 stages.

**Result: 1598/5066 (31.5%), 31 skipped.** That is the honest headline and it is
far below every number gwaf publishes about itself. It is also the point of the
exercise — every other figure is measured against a corpus gwaf wrote.

### The split is what matters
- **3,416 missed detections**
- **52 false positives** (about 1%)

So the gap is *coverage*, not *precision*. gwaf blocks less than CRS expects; it
does not block things it shouldn't.

### Three qualifications, none of which rescue the number
1. Some families are out of scope by design: session fixation (943) needs
   cross-request state; method/protocol enforcement (911/920) is the schema tier.
2. **~70 RESPONSE-95x misses are the runner's fault, not gwaf's** — it drives
   request phases only, so response-phase rules never got a chance. Fixable.
3. Some CRS "attacks" are application-bug triggers rather than injection:
   `2.2250738585072011e-308` is the PHP float DoS, `4294967296` an overflow
   probe. gwaf does not have those rules by choice.

### The finding worth acting on: DBMS-specific function-call injection
Sampling missed 942 cases shows one clear class gwaf does not detect — a bare
call to a dangerous built-in, with no UNION, no OR 1=1, no keyword:

    lo_import('/etc' || '/pass' || 'wd')        PostgreSQL file read
    sqlite_compileoption_used(id)               SQLite fingerprinting
    starts_with(password,'a')::int              PostgreSQL boolean extraction
    jsonb_pretty(json_build_object(1,password)) PostgreSQL JSON exfiltration
    FIND_IN_SET('22', Category)                 MySQL

gwaf reads SQL *grammar*, which is why it beats signature lists on encoding
evasion — and this is the flip side: a bare call to a dangerous built-in is
grammatically ordinary. CRS covers it by naming hundreds of functions, which is
the enumeration gwaf avoids everywhere else, so **the fix is a design question,
not a list to paste in.** Highest-value open detection work.

### Runner decisions
- **In-process, not over a socket.** A socket test measures the socket too — a
  400 from net/http reads as "gwaf missed it" when gwaf never saw it, which this
  project already hit for real with CVE-2021-42013.
- **Skips are excluded from the denominator, never counted as passes**, enforced
  by a test. A suite that skips half its cases and reports 100% is lying.
- **The benign controls are proven to assert something**: a block-everything
  configuration must fail the suite, or the FP half is decoration.
- Two modes kept apart — detection parity (IDs ignored) vs seclang bridge
  fidelity (exact CRS IDs) — because reporting one and implying the other is how
  a conformance number becomes marketing.

## SHIPPED: SQL function-call detection, response-phase conformance, extreme phases

### The two-tier danger function, which is the design answer to enumeration
CRS conformance found gwaf missing DBMS function-call injection —
`lo_import('/etc'||'/pass'||'wd')`, `sqlite_compileoption_used(id)`,
`utl_http.request(...)`. The mechanism already existed (`SignalDangerFunction`);
what was wrong was `attachedToSQL`, which requires surrounding SQL. These
payloads *are* the whole parameter value, substituted into the origin's WHERE
clause, so there is no boolean connector to attach to.

**Split into two tiers rather than pasting CRS's list:**
- `osAccessFuncs` — functions that leave the database (filesystem, command,
  network, build introspection). Fire **without** attachment, because no
  parameter value legitimately contains `pg_read_file(`.
- `dangerFuncs` — dangerous only in context (`substring`, `char`, `sleep`).
  Still require attachment, which is what keeps "use substring(0,5)" out.

Plus `isPackagedDangerCall` for Oracle's `package.function(` form, which the
tokenizer splits on the dot so the package is never the token before `(`.

### Two false positives the pentest harness found that the corpus could not
Both were **transport-shaped**: the value alone was clean, the URI form fired.

1. **`?q=sleep(8h) is the recommendation`** blocked. `attachedToSQL` walked back
   from `sleep` and found the `=` of the *query string*, treating a parameter
   assignment as SQL context. Fixed with `isQueryAssignment` (`?name=` / `&name=`).
2. **`?q=see ../shared/q3.pdf`** blocked by rule 1001. `curl --data-urlencode`
   correctly encodes `/` as `%2F`, producing `..%2f` — which the rule matched as
   evasion. **But `..%2f` is what every browser form and JS client produces**,
   while `%2e%2e` is not: no encoder escapes a literal `.`. Dropped `..%2f` and
   `..%5c`; kept the encoded-dot forms.

**Why the corpus missed both:** it carried the same prose in a *JSON body*,
where no URL encoding happens. The `adjacent` archetype now carries the encoded
query-value shape. **Lesson: a value and the URI it arrives in are different
inputs, and a corpus that only tests one is testing half the surface.**

### The cost, stated
Narrowing rule 1001 traded **21 CRS conformance stages** (1623 -> 1602) for
eliminating an FP class that affects every URL-encoded form field. That is the
right trade — a false positive on ordinary prose is worse than missing a
traversal that the decoded-value rules still catch — but it is a trade, not a
free win.

### Response phases in the conformance runner
The runner drove request phases only, so ~70 RESPONSE-95x misses were its fault.
It now honours the CRS reflect convention (`{"body":"..."}` echoed back) and
drives status/headers/body. Verified working — a SQL-error leak blocks. The
number moved only +2, which is the useful part: **the remaining RESPONSE misses
are genuine coverage gaps, not runner artifacts.**

### A conformance reporting correction
"52 false positives" was **wrong**. CRS `no_expect_ids: [932230]` asserts that
*one rule* does not fire, not that nothing does — several of those payloads carry
a real shell command. Reading it as "must pass" filed correct blocks as FPs. The
runner now classifies them separately: **3 true false positives, 50 ambiguous**.

## SHIPPED: latency profiling, CRS Java coverage, and the head-to-head

### P0 latency: measured first, and the profile redirected the work
Profile put `Automaton.Scan` at 31.7% and `stages.apply` at 30.2%. Split the
scan's root path into its own tight spin — benign traffic spends nearly every
byte at the root, and it was paying two `state == 0` branches per byte.
**Measured paired: GET -4.9%, POST JSON -2.2%.** Real, smaller than the profile
suggested, because it removes branch overhead rather than bytes scanned.

**Ruled out, so nobody repeats it:** the four chain groups cannot be merged.
`[lowercase]` exists because rules 1001 and 1005 must match *before* decoding —
an encoded traversal sequence is the signal, so decoding first destroys it.
Merging automata across groups fails because each group scans different bytes.
`growTo` is already a cap check. **Further gains need fewer bytes scanned
(schema Inert on real traffic), not a faster loop.**

### P1 CRS Java: one vocabulary, 176 stages
944240 is built entirely on ysoserial's Commons-Collections gadget names —
`clonetransformer`, `forclosure`, `invokertransformer`. Adding them took
conformance **31.6% -> 35.1%** with zero new false positives. Named individually
rather than by a `runtime.` prefix, because that prefix is an ordinary JSON
field name.

### P2 head-to-head: the number I nearly published wrong
Built `test/headtohead` — gwaf and Coraza+CRS, same corpus, same process.

**First run said Coraza had an 87% false-positive rate. That was my harness.**
The corpus records carry only the headers gwaf cares about, so replayed requests
had no Host, User-Agent, or Accept, and CRS correctly fired 920280 "Request
Missing a Host Header". A request with no Host is malformed under HTTP/1.1.
Supplying real browser headers took it to 36.4%; loading the official
`crs-setup.conf.example` instead of hand-written SecActions left it unchanged,
which is what confirmed the remainder is Coraza's behaviour rather than mine.

**Publishing 87% would have been exactly the dishonest comparison the file
exists to prevent. A number about a competitor gets verified before it ships.**

Final, both published because each corpus is one engine's home turf:
- CRS regression corpus (CRS's turf): **coraza 80.6% vs gwaf 20.0% detection**
- 10,433 ordinary API requests (gwaf's turf): **gwaf 0.06% vs untuned CRS 36.4%
  false positives**

Coraza winning detection on its own test suite is fair and is stated plainly.
gwaf winning FP on its own calibration corpus is close to tautological and is
stated just as plainly. The caveats travel in the test output itself so the
numbers cannot be quoted bare.

## MEASURED: why converting CRS to gwaf is blocked, and by exactly what

Asked "why not convert the CRS ruleset to gwaf". The tooling already exists
(`gwaf-seclang convert` emits Go source), so the question is empirical.

**The blocker is not hundreds of edge cases. It is two features.**

Aggregating every untranslatable directive across all 27 CRS rule files:

    235  variable "TX"      -- ModSecurity's transaction/anomaly-score variable
    145  variable "XML"     -- XPath inspection of XML bodies
      3  MULTIPART_PART_HEADERS
      2  REQBODY_PROCESSOR
      1 each  UNIQUE_ID, REQUEST_BASENAME, QUERY_STRING, ARGS_GET_NAMES

380 of ~580 skipped directives are TX and XML. The last three were pure
omissions in the mapping table and are now fixed (105 -> 107 rules), which
confirms the tail is thin and the head is two items.

**TX is the interesting one.** CRS's architecture is: every rule adds to
`tx.anomaly_score`, and rule 949110 blocks when the total crosses a threshold.
gwaf already has that shape — `rules.Score` and `WithThreshold` — so TX is
mappable rather than alien. It is the single highest-leverage piece of bridge
work, worth roughly 235 directives.

**XML (145)** needs an XML variable with XPath over the body. gwaf already
parses XML bodies for XXE, so the parse exists and the addressing does not.

### But conversion does not fix precision, and that is the real finding
Converting changes the *format*, not the rules. The measured cost of running CRS
under gwaf is 51.3% false positives against gwaf's own 0.06%, so importing more
of CRS imports more of its imprecision.

What conversion *does* unlock that the runtime bridge cannot: **calibration**.
Converted rules are Go values, so `gwaf calibrate` measures each one against the
benign corpus and the ones that exceed their tier's ceiling can be demoted or
dropped. That is the path to "CRS breadth at gwaf's false-positive rate" —
convert, calibrate, keep what survives — and it is a curation exercise, not an
import.

## SHIPPED: paranoia gates are interpreted, not translated

"Make sure all CRS converts" is not achievable, and the analysis of why is more
useful than the attempt. Full skip breakdown across all 27 CRS rule files:

    386 variable has no gwaf equivalent   (TX 235, XML 145)
     55 unknown/unsupported directive
     55 chained SecRule
     29 counting a collection (&ARGS)
     20 variable exclusions (!ARGS:x)
     12 @pmFromFile
      7 unconditional actions
      5 encoding validation
      6 transformations

**Several of these are deliberate architecture, not gaps.** A chain is a
conjunction across variables and importing only the head would be *more
permissive than the original* — refusing is correctness. Variable exclusions
belong in rules.Exception where they are visible and tunable. Unconditional
actions are cross-request state, which is the embedder's. Encoding validation is
gwaf's canonicalization tier and runs before rules rather than as one. **100%
conversion would mean abandoning those decisions.**

### What was fixed: 184 of the 235 TX directives
200 of them are `SecRule TX:DETECTION_PARANOIA_LEVEL "@lt N" skipAfter:MARKER` —
CRS expressing paranoia as *runtime control flow*. gwaf expresses the same idea
as a compile-time confidence tier, so the gate is now **interpreted rather than
translated**: the compiler reads the level, and every rule up to the marker
arrives at `ConfidenceFromParanoiaLevel(N)` instead of a flat default.

Variable failures 386 -> 202. Reporting those as untranslatable was accurate and
useless: they are not detection, and gwaf already implements what they do.

### Detection went DOWN, and that is the correct outcome
gwaf+CRS 57.6% -> 47.8%. Before, every imported rule arrived as High and ran;
now PL2/PL3/PL4 rules arrive as Medium/Low/Heuristic and are filtered by the
default minimum confidence — which is what CRS at PL1 does too. **The old number
was inflated by running rules CRS itself would not have run.** A lower honest
number beat a higher wrong one.

### Still open, in order of leverage
- **XML (145)** — needs an XML variable with XPath. gwaf already parses XML
  bodies for XXE, so the parse exists and the addressing does not.
- **@pmFromFile (12)** and **transformations (6)** — small and mechanical.
- The rest is deliberate and should stay unconverted.

## SHIPPED: XML mapped, and the false-positive story inverted

`XML:/*` and `XML://@*` are 145 of CRS's directives and essentially all of its
XML usage — and neither is general XPath. Both are substrings of the request
body, which gwaf already inspects for an XML content type (verified: SQL
injection inside an element blocks on the body rule). Mapped to REQUEST_BODY as
a superset that can widen a match but never miss one.

**Bridge 107 -> 192 rules. Variable failures 202 -> 57.**

### The number that changed the conclusion
gwaf+CRS false positives went **51.3% -> 9.87%**, with detection *up* to 49.6%.
(Corrected later to **7.56%** — see the REQUEST_LINE entry below; 9.87% was
inflated by a bridge bug of ours, not by CRS.)

The cause is the previous commit, not this one: with paranoia gates interpreted,
a rule CRS placed behind PL2 arrives as Medium and is filtered exactly as CRS at
PL1 would filter it. **Most of CRS's apparent imprecision under gwaf was rules
being run that CRS itself would never have run.** The earlier 51.3% was an
artefact of a flat, untiered import — a measurement of my bridge, not of CRS.

So the trade is now real rather than obviously bad: gwaf+CRS gives roughly 60%
of Coraza's detection at about a quarter of its false positives. Still an opt-in
bundle, not a default, but a defensible choice for a deployment wanting breadth.

### What is left, and why it stops here
57 variable failures, 55 unknown directives, 55 chains, 29 collection counts, 25
t:utf8toUnicode, 20 exclusions. The chains, exclusions, unconditional actions and
encoding validation are deliberate architecture — converting them would mean
being more permissive than the original or importing cross-request state. The
honest ceiling is short of 100% and that is a design outcome, not a defect.

## SHIPPED: transform.EscapeDecode, and the "fix one, reveal the next" effect

Bridge 192 -> 212 rules. Three increments, each smaller than the last:

- **utf8toUnicode + htmlEntityDecode (33)** — accepted and *dropped*, because
  gwaf already evaluates both as readings (ClassOverlongUTF8, ClassHTMLEntity).
  A transform rewrites once and matches the result, which is the
  single-interpretation model CVE-2026-21876 exploited; applying it as well would
  narrow the rule to that one reading. Dropping is the faithful translation.
- **removeNulls (3)** — same argument via ClassNullTruncate.
- **jsDecode + escapeSeqDecode (35)** — a real new transform,
  `transform.EscapeDecode`.

**Deliberately NOT dropped: cmdLine and replaceComments.** gwaf covers those at
the *detector* tier (shelli unquoting, sqli comment structure), which does
nothing for an imported CRS regex — silently dropping them would make the
imported rule narrower with no compensation. The distinction between "covered by
canonicalization" (safe to drop) and "covered by our own detector" (not safe) is
the rule to apply to the rest.

### Why a transform and not a reading
A backslash escape is *unambiguous* — "\x41" is "A" to every consumer. Readings
exist for ambiguity the WAF cannot resolve. Making this a reading would add a
decode pass to every value in every request to serve the rules that ask for it;
as a transform it costs only where requested. With latency already thin that
distinction decided it.

### Two bugs in my own first cut, both found by the test I wrote
1. Truncated `\x` decoded to `x`, contradicting the doc comment two lines above
   that said malformed escapes are kept verbatim.
2. `\a` decoded to BEL (C semantics). JavaScript has no `\a` and drops the
   backslash, and jsDecode is 28 of the 35 directives — so `c\at` must decode to
   `cat`, the evasion actually being written, not to a bell character nobody
   sent.

### The pattern worth remembering
The transform switch returns on the *first* unsupported name, so each fix
reveals the next one hiding behind it: utf8toUnicode(25) hid jsDecode(28) hid
cmdLine(8). A "25 directives" estimate was really "25 visible directives".

## SHIPPED: zero false positives, by shape rather than by exception

Goal was "increase detection and make the false positive 0%". Both, measured:
**271/271 evasion (was 244), 0/10,473 benign (was 6/10,433 = 0.06%)**. Pentest
suite 189/189 blocked, 0/62 FP.

**The six false positives were all rule 1008, and the fix was a discriminator,
not a tolerance.** A backup artifact is a copy of a file the app serves, so it
keeps its source extension — `wp-config.php.bak`, `index.php~`. A storage product
serving `quarterly-notes.bak` has no source extension in front, because that is
what the user named their file. Requiring the *doubled* extension removed all six
without losing a single corpus case. `.sql` has no extension to double, so dumps
are decided by directory (`/backup/`, `/dumps/`) instead.

**Rule 4017 is the same insight inverted, and it is the one an adopter needed.**
`shell.php.jpg` is a source extension followed by a *harmless* one: the upload
filter reads `.jpg`, Apache resolves `.php`. Two guards were needed before it was
safe, and the corpus supplied both: a numeric tail is a version (`libssl.so.1.1`)
and an executable *final* extension is not a disguise (`db.inc.php`).

### The corpus found a false positive that had been shipping
`data:image/png;base64,…` scored as command injection — `;` is a separator and
`base64` is in the command list because `echo …|base64 -d|sh` is real. **Any app
accepting an inline image was being blocked, and no test covered it.** Fixed
structurally: `;` after a *registered* IANA top-level type, followed by an actual
parameter (`name=` or `base64` before a comma), is a media-type separator. Both
halves are required, because `uploads/img.png;cat /etc/passwd` and
`text/plain;cat /etc/passwd` must both still fire — and they do.

### Prefilter literals must encode the requirement, not the substring
Registering bare `.php`/`.sh`/`.so` for rule 4017 cost **3.4% on benign POST
JSON** — those appear in ordinary bodies, so the operator ran constantly for
nothing. Registering `.php.`, `.php;`, `.php/`… (extension *with* delimiter, the
thing the operator actually requires) took it back to 0.9%, inside noise. More
literals, fewer candidates. This is what CLAUDE.md §2's "declares its required
literals" is for.

### Three new operators, all allocation-free
`lower := make([]byte, len(v))` was in each draft. Replaced with `indexOfFold` /
`hasSuffixFold` / `matchFoldSkipping`, which fold one byte at a time during the
compare. Benign GET stays 0 allocs.

### Confirmed still-correct rejections (do not "fix" these)
Probing 35 out-of-corpus attacks left 7 misses, and **every one is by design**:
`#{7*7}` and `@(1+2)` are the score-2 delimiter tradeoff; `X-Forwarded-Host`
needs to know the legitimate host (embedder); loopback SSRF is deliberately
opt-in; mass assignment is the schema tier's job; a lone `TE: chunked` is legal
HTTP. Two of the 35 were bogus test cases of mine.

## FIXED: REQUEST_LINE was the URI, so CRS 920100 fired on every request

An adopter sent a real request that their current WAF false-positives on, and
asked whether gwaf blocks it. gwaf passed it on every method and shape with
**score 0**. Running it through the CRS bridge to explain *their* false positive
instead found one of ours.

`REQUEST_LINE` mapped to `TargetRequestURI`. An earlier fix had moved it off
`REQUEST_BODY` (which made CRS fail to load at all) and stopped there. **CRS
920100 is a negated match — `!@rx` against the full `METHOD URI PROTOCOL`
form — so handing it a URI meant the regex could never match, the negation
always fired, and every request through the bridge scored 3 for "Invalid HTTP
Request Line".**

Now `types.TargetRequestLine`, built from the three parts with single spaces
(RFC 9112's only legal form — a rule asserting the line is well-formed must not
be handed a line *we* malformed).

**Corrected measurement: gwaf+CRS on the benign corpus is 7.56%, not the 9.87%
recorded above.** 920100 never blocked alone, but +3 on every request pushed
borderline ones over the threshold. gwaf core is 0.00% on the same corpus.

### The compiler already knew this was unnecessary work
Building the line for every request cost ~50 bytes of extra prefilter scan and
pushed benign POST p50 from 14.9µs to 15.04µs, past its budget. Only SecLang
imports read REQUEST_LINE; the core ruleset has none. Added `Ruleset.Reads(kind)`
— a union of the per-group target masks that already existed — and the
transaction now skips building a value nothing will look at. p50 back to 14.9µs.
**A target an embedder's ruleset never reads should cost that embedder nothing.**

### Three wrong test harnesses in a row on one fix
Worth recording because the pattern repeats: (1) the test regex omitted CRS's
`(?i)`, so it required a lowercase method and "fired" on everything — identical
symptom to the bug; (2) the assertion used `Blocked()`, but 920100 is a scoring
rule that never reaches the threshold alone, so it passed for both a working rule
and a silenced one; (3) the FP sweep passed an empty method for corpus entries
that omit the field, building a genuinely malformed line and blaming gwaf for
catching it. **Each time the harness was the broken side.**

## Rejected: base64 as an interpretation class (2026-08-09)

Real payloads arrive base64-wrapped — elFinder's `target=l1_ZXRjL3Bhc3N3ZA` is
`etc/passwd` to the code that opens the file. The architecturally right home is
`internal/interpret`, as a reading rather than a transform, so every rule sees
the decoded form. It was built that way, with a bail-early run scan, a
prefix-separator retry for `l1_`-style namespacing, and a decode gate requiring
the output to be four-fifths printable and to carry a separator so that session
identifiers and hex digests earned no reading.

It works and it is not payable:

- **benign GET +31%**, benign POST +2.8%, attack +1.5%
- **`TestSLOZeroAllocations` fails** — the decode allocates
- **`TestCoreRulesetIsClean` fails** — new calibration false positives

The cause is structural rather than a tuning miss. Every other ambiguity class
announces itself with a lead byte — a percent, a backslash, a plus — and
`Detect`'s table rejects almost every byte of real traffic in one lookup. Base64
is entirely alphanumeric, so it cannot use that table at all. Worse, `/` and `-`
are alphabet characters, so **every URL path is a base64 run**: `/api/v1/orders/12345`
clears any run-length floor, and the decode gate then runs on it. The floor
cannot fix this, because real payloads are short — `ZXRjL3Bhc3N3ZA==` is sixteen
characters, so a floor high enough to exclude paths excludes the attacks too.

**A reading needs a cheap negative test, and base64 does not have one.** If this
is revisited, the anchor has to come from somewhere other than the value's own
bytes — a parameter name the application documents as encoded, or a schema that
declares the field base64 — which is knowledge the embedder has and the engine
does not. That is the same shape as the off-origin and type-marker rules, and it
is probably where this belongs.

## Rejected: route-aware confidence for the sensitive-file rule (2026-08-09)

The idea was to encode "this route is a file editor" in the rule so that
`/wp-admin/theme-editor.php?file=functions.php` passes structurally, instead of
every WordPress deployment needing a profile exception for it. With
`EvalContext.RequestURI` now available it was cheap to build.

It was built and then measured, and **the false positive it was written to fix
does not exist**. The default ruleset already passes all three editor routes,
because `functions.php` and `akismet/akismet.php` were never on the
sensitive-file list — the list is `etc/passwd`, `win.ini`, `.ssh/id_rsa` and
their kind, and nothing an editor edits is on it. The wrapper exempted nothing
and its tests passed for that reason rather than because it worked.

Deleted rather than shipped. **A route-aware rule that exempts nothing is an
abstraction with a story attached**, and the story was mine rather than the
corpus's.

The technique is still sound where an FP is actually measured — the remaining
ones are content fields (a comment quoting PHP, a post quoting SQL), and those
are deployment knowledge, which is what `ruleset/profiles` is for. Before
reaching for this again, find the blocked benign request first.

## Sized and dropped: body-anchored type markers for dotted class names (2026-08-09)

TypeMarkerRule covers PHP namespaces and documents the dotted Java/.NET forms
(`"@type": "java.lang.Class"`) as out of scope, because a dot is useless as a
prefilter literal. The documented follow-up was a second rule anchored on the
marker *name* in the raw body, where `"@type"` is itself selective.

Before building it, the corpus was counted. Across 2,455 payload-bearing CVE
exploits there are **three** occurrences of any type marker at all: one `@type`
and two `__type`. The rule would be worth at most three cases out of 182 RCE
misses.

**The follow-up documented in Literals is correct and not worth building.**
Anyone reaching for it should count first; the note in typemarker.go now points
here.

## Where the RCE gap actually is (2026-08-09)

gwaf sits at 76% against CRS's 83.5% on RCE, 182 misses. Sampling them, the
large buckets are not detector-signal problems:

  * multipart bodies -- plugin and .jar uploads, `stream.url` parts
  * SOAP/XML bodies -- several .asmx endpoints carrying the payload in XML

with smaller groups for `cmd=` parameters, `;id;` separators, expression
language `${...}`, and base64 blobs. That points at **body-format coverage**
rather than at the semantic detectors, which is a different kind of work from
everything done this session: the detectors are not failing to recognise these
payloads, they are not being handed them.

Next step is to confirm that by checking what internal/body parses for
multipart and XML, and whether those parsers are reached for the content types
these CVEs use -- not by adding signals.

**Correction, same day: that diagnosis was wrong, and it was wrong because it
was eyeballed.** It came from reading about twenty-eight lines of printed miss
output and noticing multipart and SOAP in them. Tested properly -- six real
corpus payloads of exactly those shapes, replayed through gwaf.New() -- five of
six block, including both arbitrary-file-upload multiparts (rule 1010
ScriptInUpload and rule 4919 PHP). The samples were drawn from the corpus rather
than from the miss list, which is the mistake: at 76% RCE most cases are caught,
so any sample that is not *specifically the misses* is mostly caught cases.

internal/body does have a real limit -- DetectContent handles JSON, +json and
form-urlencoded, and everything else including XML falls back to whole-body
inspection rather than parsed fields -- but whole-body inspection is not zero
coverage, and it is not established that this is where the RCE gap lives.

**The RCE gap is still unlocated.** Anyone picking it up should start by dumping
the actual miss list for class=rce from the current build and classifying all of
it, not a sample of it. The tooling for that is the throwaway probe pattern used
all session; it needs to write JSON rather than print, so the classification can
be counted instead of read.

## The RCE gap, finally located (2026-08-09)

Done the way the correction above demanded: every miss dumped to JSON from the
current build, classified by counting rather than by reading. 306 misses across
the payload-bearing corpus, **86 of them RCE**:

      31  other
      18  other JSON body
      15  command in a cmd= parameter
      10  base64 blob
       7  multipart body
       2  JSON type-marker gadget
       1 each  backtick, separator+command, XML/SOAP

Two things follow, and the second is the useful one.

**There is no big tractable bucket.** 49 of 86 are undifferentiated JSON bodies
and "other". Multipart and XML -- the shapes an earlier entry blamed -- are 8
between them. Anyone expecting one fix to close this gap should stop expecting
that.

**The cmd= bucket is not a detector problem, and it is smaller than it looks.**
Of the 15, only six are commands: `cmd=id` twice, `cmd=echo abc123`,
`cmd=nslookup oast...` twice, `cmd=mkdir`. The other nine are the
application's own API verbs -- `cmd=mkfile`, `cmd=resize`, `cmd=cgi_user_add`,
`cmd=SC_Get_Info`, `Command=sysCommand` -- and blocking a bare word in a cmd=
parameter would break elFinder and every router CGI in the corpus.

Tested directly, `detect/shelli` already gets all fifteen right:

    AnalyzeIn("id", true)            detected, score 5
    AnalyzeIn("echo abc123", true)   detected, score 5
    AnalyzeIn("nslookup ...", true)  detected, score 5
    AnalyzeIn("mkfile", true)        not detected
    AnalyzeIn("resize", true)        not detected
    AnalyzeIn("cgi_user_add", true)  not detected

So the detector is right and the request is still not blocked. **The rule never
reaches the detector.** The likely cause is the prefilter: shelli's literals are
shell metacharacters, and `cmd=id` contains none, so the rule is never a
candidate and commandSink never gets consulted. That is the same shape as the
type-marker limitation -- a rule whose evidence is the *parameter name* cannot
be selected by an automaton over *values*.

Confirm that before building anything. If it holds, the question is not "what
signal is missing" but "how does a key-anchored rule get scheduled without
becoming unconditional", and that is an engine question with a latency budget
attached, not a detector question. `mkdir` is separately absent from the command
list and is a one-word fix worth about one case.

## An inert rule measured as a detected rate (off-origin redirect / SSRF)

v0.4.1 correctly made the off-origin rules require `gwaf.WithOrigins` -- the fix
for a bypass that compared a destination against the attacker-supplied `Host`
header. **No measurement harness was updated.** `test/headtohead/nuclei_test.go`
and the evasion corpus both built their WAFs without origins, so rule 1013 and
`core.SSRFParamRule` compiled, linted, and could not fire. The `tuned` config
explicitly opted into `SSRFParamRule` and then published its detection rate.
`gwaf.New` printed the inert warning into the test log on every run; nothing
read it.

Re-measured with origins declared: **redirect 13/60 -> 55/60** (Coraza+CRS
3/60), **SSRF 5/63 -> 44/63** (14/63), tuned overall **85.9% -> 89.5%**. The
CHANGELOG's older "redirect 82.5%" was from before the origins requirement; the
collapse to 21.7% was never noticed because nothing re-ran.

**The lesson is not "declare origins in tests."** It is that a configuration
precondition silently converts detection into a no-op, and only the engine knows.
Hence `(*gwaf.WAF).Diagnostics()`, and the evasion corpus asserting it is empty
*before* reporting a rate -- a miss must not be misconfiguration in disguise.

## Literals: more specific is a bypass, not an optimisation

`offOriginOp.Literals` returned `"://"` and colon-prefixed backslash forms. Its
own doc comment stated the correct invariant -- "two adjacent slash-or-backslash
bytes" -- and listed `"//host"` as a matched form. The colon reads as a
tightening of the same claim and is not one: it excludes every scheme-omitted
destination. `redirect_to=//evil.tld/` navigates off-origin in every browser and
`absoluteHostOf` parses it; the prefilter simply never nominated the rule, so
correct code was unreachable.

Measured before changing the ceiling it broke: the same six benign values were
counted under both literal sets and nomination counts were **identical**
(10,8,5,8,1,8), because a benign absolute URL contains `://` too. So the
`maxEvaluated` 6->10 raise is attributable to adding URL-carrying benign cases,
not to widening the literals. Check that separation before raising any bound --
a raised ceiling is the easiest place to hide a real regression.

## Opt-in rules got no body-phase counterpart (second occurrence)

`withBodyPhase` runs inside `core.Default()`. A rule added via `WithRuleset` is
compiled exactly as declared, so an argument rule at `PhaseRequestHeaders` sees
the query string and never a form or JSON body. `SSRFParamRule`'s own godoc
one-liner therefore built a rule that could not inspect the bodies webhook and
import endpoints are made of -- the precise endpoints it exists for.

This is the same bug recorded at `bodyPhaseOffset` (two of ten injection rules
mirrored by hand; a payload blocked in a query string sailed through in JSON).
Generating the pair fixed it for core and left embedders on the old footing.
Now exported as `core.WithBodyPhase(set)`, and `Diagnostics` names a rule that
needed a counterpart and did not get one.

**Confirmed still-correct rejection:** `SSRFParamRule` stays opt-in. With
origins *and* body coverage it blocks webhook registration on the benign corpus
-- the original measurement was right, and declaring origins does not rescue it,
because `hooks.example.com` is genuinely somewhere else. The head-to-head models
the real answer: a scoped exception on the one route.

## Splitting is multi-interpretation too (the ';' query bypass)

`?cmd=;whoami` was not detected. `addQueryArguments` split pairs on ';' as well
as '&', so the value ";whoami" never existed. shelli scores it 5 against a
threshold of 5 and blocks the identical payload in a form body, in a JSON body,
and percent-encoded -- **only the rawest spelling got through, which is why
every hand-written test passed.** Found by research-directed probing (WAFFLED,
arXiv 2503.10846, on WAF/origin parser discrepancies), not by the corpus.

Splitting on ';' was deliberate and half right. The half it missed: committing
to that reading *discards* the '&'-only reading, which is what Go's net/url
(rejects ';' since 1.17) and PHP (arg_separator.input defaults to '&') actually
do. gwaf split where the origin did not.

**The invariant is broader than it was written.** "Canonicalization is
multi-interpretation" was applied to decoding and not to *deciding what the
values are*. Both readings are recorded now; a query with no ';' costs one
IndexByte per pair and produces no extra arguments.

Note the body parser (`internal/body/form.go`) splits on '&' only, so gwaf was
internally inconsistent -- the query used the minority reading and the body the
majority one.

## Read the misses; do not imagine them

RCE was the largest gap against CRS (287/378 vs 316/378). Adding
`GWAF_DUMP_MISSES=<class>` to the head-to-head and reading the 88 requests made
the shape obvious in one run: nine were Node.js, and **no detector could have
caught any of them** -- a JavaScript payload stays in JavaScript syntax, so it
carries no shell grammar for shelli, no template syntax for ssti, no PHP for
phpi. Rule 4021 came straight out of that, worth +10 RCE and taking tuned
detection to 90.0% against CRS's 89.7%, FPs unchanged at 0/12 vs 4/12.

The general lesson: a per-class score tells you a gap exists and nothing about
what it is. Every improvement made without reading the misses is a guess, and
the corpus is right there.

## Confirmed still-correct rejections (do not "fix" these)

- **Bare backtick `` `whoami` `` scores 0 and must.** Probing found it and it
  looked like a gap; it is `TestBacktickLimitIsDeliberate` plus a recorded
  measurement -- the concatenation heuristic false-positived on 9/9 realistic
  benign values, because "localhost`id`" and a JS tagged template are the same
  shape. Checked before changing anything, which is the only reason a week was
  not spent on it.
- **`SSRFParamRule` stays opt-in** even with origins *and* body coverage: it
  blocks webhook registration on the benign corpus, exactly as first measured.

## gwaf is immune to payload padding, and now says so

The 2026 literature's loudest technique is burying the payload past the
inspection window; it works because AWS (8-64 KiB), F5 (64 KiB) and others
truncate and forward. gwaf returns `ReasonLimit` on an oversize body and blocks
under the default `FailClosed`. True by construction, untested until
`TestPayloadPaddingIsNotABypass` -- which also pins that a payload at 500 KiB
depth is still *detected*, so depth is not a hiding place either.

**A differentiator that rests on a property rather than a rule still needs a
test, or it is one refactor from being a regression nobody notices.**

## Bounded work must be a window, not a prefix (the padding bypass)

**Six of seven detector classes were bypassable by padding.** Every semantic
detector bounded analysis with `maxScan` and applied it as `src = src[:maxScan]`.
The reasoning beside each is sound -- signals are local to one command, one tag,
one header -- but **locality justifies a bounded window, not a bounded prefix.**
The payload never needed to be longer than the bound, only to sit past it.

Measured: phpi/javaser/ldapi (8 KiB) missed at 16 KiB of padding;
shelli/xss/ssti (64 KiB) missed at 128 KiB. Only sqli, which has no such
constant, was unaffected.

The bitter part: `transaction.go`'s `noteOversize` already states the rule --
"Inspecting the first 64 KiB of a value and reporting the request as clean is a
bypass with a padding step" -- and refuses to do it at the transaction layer.
Every detector then did it one level down. **A principle enforced at one layer
is not enforced.**

Fixed with `internal/scan.Windows`: overlapping windows, overlap sized
proportionally (window/8, clamped 1-4 KiB) because a flat 4 KiB on an 8 KiB
window meant scanning every byte twice for a guarantee needing tens of bytes.

`graphql` and `nosqli` deliberately excluded: GraphQL scores *global* structure
(a window is not a document), and nosqli reads names that `MaxKeyLen` bounds at
256 -- four times under its own 1 KiB limit.

**Cost accepted and documented:** BenchmarkBenignLargeBody 11.5ms -> 18.1ms on a
1 MiB body, because ~99% of that body was previously not inspected. Not an
efficiency regression -- the removal of a shortcut that was a bypass. Verified
benign 1 MiB bodies still pass, so the cost is time, not false positives.

## Framing is an axis the payload corpus cannot see

Two real bypasses this cycle were found by holding the payload *constant* and
varying how the request was framed -- something a corpus of hundreds of attack
payloads cannot do, because it varies the payload instead. `discrepancy_test.go`
is that axis: one payload, every framing an origin might honour.

Found this way: the ';' query separator, and a multipart body labelled
urlencoded (WAFFLED: >90% of sites accept the two interchangeably; gwaf handled
the mirror direction via SniffJSON and had nothing for this one).

**Rule for the file:** a new framing goes in *before* the fix, so the miss is on
record. It must never fail because a detector got weaker -- the payload is a
command injection scoring 5 against a threshold of 5 precisely so a failure
means framing, not detection.

## Fuzz the thing you just shipped, or the invariant is only a comment

`SniffMultipart` and `scan.Windows` were shipped without fuzz targets in the
same session that added them -- against CLAUDE.md's own "non-negotiable" rule
for parsers taking attacker input.

`FuzzWindowsCovers` found a real imprecision **on its first run**: `overlapFor`
could return an overlap larger than the window itself for small windows. No
window can hold a run longer than it is, so the claim was incoherent, and the
step fell through to a fallback that advanced but guaranteed nothing.

The fix was to state the guarantee exactly rather than loosen the test:
**a run of at most `overlapFor(window)` bytes always appears intact in some
window** -- provable, since a run of length L survives iff step <= window-L and
step is window-overlap. The temptation was to skip the failing case as an
unreasonable input; that would have left a package whose central promise was
approximate.

## Framing audit round 2: 12 of 13 held, one did not

Probed: JSON duplicate keys (both orders), JSON5 comments, trailing comma,
single quotes, deep nesting, query+body same name, chunked, duplicate
Content-Length, nested multipart, duplicate part name. All handled.

**Miss: RFC 5987 `filename*`.** `headerParam` requires `=` after the parameter
name and `filename*` is followed by `*`, so the extended form was extracted by
nobody. The origin percent-decodes it per the grammar; gwaf had never seen those
bytes. Now decoded and emitted *alongside* plain `filename` -- RFC 6266 prefers
the extended form, plenty of code reads whichever it looked for first, and both
are attacker-supplied.

`discrepancy_test.go` is now 29 framings. The hit rate on this axis across two
rounds is 3 real bypasses; the payload corpus found none of them.

## Reading the XSS misses closed a 31-request gap in one pass

Dumping the 45 XSS misses showed two thirds were **JavaScript reflected into a
script context** -- no HTML at all, so detect/xss (which reads tags, attributes,
schemes) could not see any of them. Same shape as the Node.js finding: a payload
that stays inside one language no detector reads is outside all of them.

Rule 3012. XSS went 962/1007 -> **993/1007**, exactly level with CRS; tuned
detection 90.0% -> 91.4%. Zero false positives on the 10,473-request calibration
corpus.

**Three narrowings, all from measurement:**

1. A call alone is not the signal. "alert(" is in every article about XSS. It
   needs injection evidence beside it: a handler assignment, a terminator
   (`;`, `}`, `)`) immediately before, or a call on document.domain/cookie.
2. **Quotes are not terminators.** A bare quote before a call *opens* a string
   rather than escaping one, so `&quot;alert(1)&quot; is the classic payload`
   matched under the HTML-entity reading. Removed `'`, `"`, `{`, `,`, `+`;
   nothing the corpus carries needed them.
3. **A `;` closing a character reference is not a statement terminator.**
   `&lt;script&gt;alert(1)` matched -- right verdict, wrong reading -- and it
   also destroyed the correct `Interpretation()`, which is how it was caught.

## Chain x target is the expensive axis, rediscovered the hard way

Rule 3012 needs a chain that keeps whitespace (RemoveWhitespace welds
"xss onfocus=" into "xssonfocus=" and the boundary before "on" is the whole
signal). Written with `Targets: argTargets` that cost **~17% of the benign POST
budget** -- a new (chain x target) combination for every collection, every value
materialised again.

Scoped to `{TargetArgs}` it shares rule 1013's existing combination and costs
**2.1%, zero allocations**. This is the same measurement that moved
CRLFHeaderRule out of core, arrived at independently.

**Also: benchmark on a settled machine or measure paired.** Mid-session readings
showed 51% GET / 53% POST regressions and a phantom 1 B/op allocation. HEAD
measured 926ns for benign GET earlier and 1353ns at the same moment, so the
machine had moved, not the code. Six paired samples gave the real answer.

## SQLi: two gaps, and a tokenizer trap worth remembering

Reading the 18 SQLi misses gave two real gaps (the rest were harness
URL-encoding, not detector gaps -- `union all select` and `CASE WHEN EXP` are
both caught when sent as arguments).

**1. COPY ... TO PROGRAM.** PostgreSQL's INTO OUTFILE. The trap: `from` is a
keyword to the sqli tokenizer and `to` is **not**. A check written in the
obvious place -- inside `case tkKeyword` -- catches `from program` and silently
misses `to program`, which is the direction an attacker uses. Placed before the
switch so it sees identifiers too. Added `FuzzLiteralsAreExhaustive` to sqli
(shelli/ssti/nosqli had one, sqli did not) because adding a signal is exactly
when that contract breaks.

**2. A whole statement in a SQL-sink parameter** (`sql=select …`). detect/sqli
looks for *injection* -- data becoming SQL partway through -- and a value that
is a complete statement breaks nothing, so every grammar signal is legitimately
absent. Same distinction shelli draws for a value that is a command line from
its first byte.

**Opt-in, and the corpus is the argument:** the benign set carries
`{"query":"select revenue where region = 'EU'"}` as "a report DSL". `query`,
`q`, `search`, `filter` are all excluded from the sink names for that reason.
Ownership test.

SQLi 65/83 -> 69/83, level with CRS. Tuned 91.4% -> 91.6%, FPs still 0/12.

## RemoveWhitespace is the recurring trap for boundary-anchored rules

Third time this session. decodeChain strips whitespace, so:

- `xss onfocus=` becomes `xssonfocus=` (rule 3012, handler boundary destroyed)
- `DROP TABLE users` becomes `droptableusers` (rule 2011, verb boundary destroyed)

**Any rule whose signal is a word boundary cannot use decodeChain.** The fix
both times was `[]rules.Transform{transform.URLDecode, transform.Lowercase}` on
`{TargetArgs}` -- a prefix of decodeChain already materialised for rule 1013, so
it costs nothing *provided the targets stay narrow*. On `argTargets` the same
chain cost ~17% of the benign POST budget.

## LFI: the key-anchored pattern, third application

Same shape as SSRFParamRule and SQLSinkRule, and by now clearly the most
productive rule design in the codebase: **the parameter name carries half the
evidence.**

Core traversal rules require *two* levels (`../..`) because one is genuinely
ambiguous in a value. Eighteen of the 45 LFI misses were a single level, and
every one was in a parameter whose *name* said "path" -- `filePath=../conf/…`,
`fpath=…`, `lang=../`. One `../` is ambiguous in a value and is not in a
parameter called filePath.

LFI 629/674 -> **647/674, past CRS's 643**. Tuned 91.6% -> 92.4%.

**`file://` moved out of the SSRF scheme rule's exclusion list.** 11002 omitted
it saying "the local-file case is already covered by the traversal and
sensitive-file rules" -- and `"source":"file:///etc/"` has no traversal and
names no sensitive file. It walked through three times. **A justification that
names another rule as the cover should be checked against the corpus; this one
was wrong for four years of nobody looking.**

The FP concern behind the original exclusion was real and is answered by
*scoping*, not by dropping the check: the benign corpus holds three
`jar:file:///opt/build/app.jar!/META-INF/MANIFEST.MF` under an `artifact` key,
which is not a path sink.

## The scoreboard, and what the loop has been worth

Reading miss lists (GWAF_DUMP_MISSES) across four classes:

    rce   287 -> 297     rule 4021 (Node.js)
    xss   962 -> 993     rule 3012 (JS context)     -- ties CRS
    sqli   65 -> 69      COPY TO PROGRAM + 2011     -- ties CRS
    lfi   629 -> 647     rule 1017 (path sink)      -- beats CRS

Tuned detection 85.9% -> 92.4% against CRS's 89.7%, FPs unchanged at 0/12
against 4/12 throughout. **Every one of these came from reading the misses
rather than imagining attacks**, and in each case the fix was a payload class
that stayed inside one language or one parameter shape no detector was reading.

## REJECTED: dense transition rows for depth-1 automaton states

Built and measured: **4.3% slower** (18014ns vs 17268ns, paired, best-of-6).
The idea was sound on paper -- `child()` was 8.6% of a benign request, almost
all of it a linear scan at the states one byte below the root, which is where
ordinary English lands constantly ("s" starts select, "u" starts union).

It lost for two reasons that only a measurement shows: the extra `nd.dense >= 0`
branch runs on *every* child() call including the ones that stay sparse, and
`node` grew from 24 to 28 bytes, thinning the node array's cache density.

**The package comment already said this** -- "nodes have few children in
practice, which makes a short linear scan over contiguous bytes faster and more
cache-friendly than a binary search or a map". It was right. The root's dense
table is worth it; a second tier is not.

## Parallel arrays cost more than the work they bookkeep

`stages.apply` wrote `val[i]` and `changed[i]` on every transform step of every
chain. As parallel slices each store lands on a different cache line: the
profile put the pair at **180ms of apply's 780ms flat** -- more than every
transform's Apply() combined. Merged into one `[]stageState`. **-2.1%**.

Line-level profiling was what found it (`pprof -list`). The top-level view said
"apply is 29% cum" and stopped there; the line view said two assignment
statements were the single largest item in it.

## The key-anchored rule problem, finally answered

decisions.md carried this as an open engine question: "a rule whose evidence is
the *parameter name* cannot be selected by an automaton over *values*... how
does a key-anchored rule get scheduled without becoming unconditional, and that
is an engine question with a latency budget attached".

**The engine already had the answer.** `EvalContext.Siblings`. A rule targets
ARGS_NAMES and declares the sink *names* as its literals, so the automaton
nominates it by matching the name; the operator then reads `SiblingValue(Key)`.
No unconditional rule, no broad value literals, and it costs nothing on a
request with no parameter of that name.

shelli scored `cmd=id` correctly all along -- 5, exactly at threshold, in sink
mode. Four corpus exploits walked through a *correct detector* that was never
handed the value. **When a detector is right and the request still passes, look
at scheduling before touching the detector.**

## Red-team pass: composing attacks, not replaying them

The evasion corpus and head-to-head replay payloads somebody else wrote. A
session of *composing* requests -- "what would I try next" -- found four
bypasses in 24 attempts, three real. `redteam_test.go` is now that suite.

1. **base64 web shell under the decode floor.** `minBase64Run` is 64 characters
   and `<?php system($_GET['c']); ?>` encodes to 40. Every payload of that size
   was invisible. **Length was a proxy for "is this real content" and the
   decoded bytes answer that directly**: 18 random bytes are all-printable
   about one time in ten billion, so requiring a fully printable decode
   separates encoded text from encoded identifiers far more sharply than
   counting characters. Cost +2.0% on benign POST, measured paired, accepted.

2. **`cmd[]=id`.** shelli's `isCommandSinkParam` did not strip the PHP array
   suffix that `core.matchesParam` strips for every other sink rule. A
   difference in notation, not in what the application does.

3. **`filename="a.php\x00.jpg"`.** Rule 1005 matches `%00` *before* decoding,
   and its reasoning is right for values in general -- a decoded NUL is
   indistinguishable from the NULs filling binary upload content. It is wrong
   for file names, and the encoded spelling is the one that does **not** work in
   a multipart header, which is not percent-decoded. gwaf was catching the
   spelling that fails and missing the one that works.

   **The fix needed the right target, not just the right rule.** A file name
   containing a NUL *is* binary by IsBinary's reckoning, so the argument view
   arrives as "a.php" and ".jpg" -- printable runs with the evidence removed
   between them. Only `TargetFileNames`, recorded before that split, still has
   the byte. The compiler then caught that FILES_NAMES does not exist before the
   body phase, by name.

## OPEN: duplicate parameters are never evaluated joined

`?q=1'+UNION&q=+SELECT+pw--` passes. Neither value is an attack alone; the
injection exists only under the comma-joining ASP.NET and some other stacks
apply to repeated names.

Deliberately not built. It is a real design decision -- which separator,
recorded where, and at what cost to the zero-allocation argument path (finding
duplicates naively is O(n^2) in MaxArgs=1000) -- and half-building it into a
security library is worse than tracking it. Documented in redteam_test.go's
header rather than added as a failing case.

## Red-team round two: limits held, encoding chains did not

Twenty composed attacks against limits, nested encodings, normalization, path
confusion and headers. **Two got through, and only one was a vulnerability.**

Everything else held, which is worth recording as much as the failures:
payload past MaxArgs / MaxParts / MaxFields / MaxDepth all fail closed; a
UTF-7 charset on a *later* multipart part is caught (the CVE-2026-21876 vector
itself); fullwidth and \u-escaped payloads, `/api/..;/admin`, `%2e%2e`, double
slashes, and payloads in X-Filter / User-Agent / Referer are all blocked.

**Real: base64(base64(shell)).** One decode left printable base64 that was
recorded and never looked at again. Now unwrapped to maxBase64Depth=2. The
bound is the point -- each layer is a full decode and scan, so unbounded
iteration lets an attacker choose how much work the firewall does. Cost +0.4%.

Note the fix's own bug, caught by re-running the suite: the recursion was added
to the long-form decode path only, and the double-encoded value is 56 characters
-- the *short* path. **The spelling the red team used was the one the fix
missed.**

## NOT a vulnerability: gzip(gzip(x)) declared once

gwaf decompresses once and sees gzip bytes. **The origin also decompresses once
and sees gzip bytes.** The payload never executes, so there is no disagreement
to exploit. Teaching gwaf to unwrap a layer nobody declared would invent a
reading no origin performs -- the mirror image of every bug this file records --
and would open a decompression-bomb surface, since nested gzip is the cheapest
way to build one.

`Content-Encoding: gzip, gzip` *is* blocked, because there the origin does
unwrap twice. **The rule throughout: follow the readings the origin performs,
and no others.** Multi-interpretation is not "try everything"; a reading nobody
performs is cost and false positives, not coverage.

## The literals contract was enforced on detectors, not on rules

`FuzzLiteralsAreExhaustive` covered 7 of 10 detectors and **0 core rules** --
and the rules are where it was actually broken. `offOriginOp` declared "://"
while matching the protocol-relative "//host"; that took an afternoon of
hand-probing to find. `ruleset/core/literals_test.go` now fuzzes every rule's
operator against its own declared literals and finds that shape in seconds.

**It found two violations on its first run.**

### 1. Rule 4010 could report on a value carrying none of its literals

The value-anchored shelli operator consulted `ctx.Key` and lifted the
stored-command-line suppression for sink names -- so it could report on
`cmd=id`, which contains no separator and no interpreter path. **A rule that can
only fire on values the automaton drops is not a rule.** Removed; `SinkOperator`
now covers the key-anchored case by keying on the name the automaton *can*
match.

### 2. The Medium tier's literals were the default tier's

shelli's `Literals()` reasoned that "the weak signals never fire alone and
always need a separator alongside". True at threshold 5. The Medium tier runs
`OperatorAt(3)`, where a weak signal weighing 3 reaches the bar **alone** -- so
rule 5912 could report on a bare `/etc/passwd` whose literals it did not
declare.

The harness that should have caught this **existed and tested `Operator()`** --
the one threshold where the reasoning holds. *A contract checked on one instance
of a configurable thing is not checked.* Literals are threshold-aware now, and
shelli's harness covers both.

## detect/xss: SignalScriptBreakout was unreachable

The new xss harness found `0;A(/*` reported with no covering literal. Every
breakout path requires a call -- an identifier then `(` -- and `(` was not
declared, so the whole signal was dropped by the prefilter before the detector
ran. That is why the XSS misses looked the way they did: a working signal the
automaton never scheduled.

Declaring `(` cost **no measurable latency** (16.85us vs 17.0us), no false
positives on either corpus, and two extra candidates on benign values containing
a parenthesis.

**maxEvaluated has now been raised three times** (6 -> 10 -> 12 -> 14), each for
a different legitimate cause. The trend is the finding: that number grows with
the ruleset, which is exactly what it cannot distinguish from a prefilter
regression. `TestRuleEvaluationDoesNotScaleWithRuleset` measures the shape of
the curve rather than a point on it and does not degrade; prefer it.

## Plan item "RCE is encoding work" was wrong, and measuring said so

The prediction was that the remaining RCE misses were an encoding layer: XML
field extraction and `\uXXXX` outside JSON. **Both already worked.** Probing
found XML element text, XML attributes and SOAP envelopes all extracted and
inspected (5/5), and `<script>` in a query and `UN...`
in a form body both blocked.

The real gap was a whole class with no detector: **process-spawning APIs.**
Java was read structurally by javaser and Node had 4021; PHP, Python, R and
Groovy had nothing. `system('ver')`, `passthru('id')`, `os.system('id')`,
`subprocess.check_output(...)`, `system(paste('id'))` and `"id".execute()` were
all undetected, four of them live corpus exploits.

**Probe before building, even when the plan is your own.** The encoding work
would have been a week spent on something that already worked.

## The tier line was already drawn, and a test held it

Rule 4023's first draft blocked `system('id')` at High.
`TestMediumTierIsOptInAndReachable` failed, naming the payload as "an executing
call with no surrounding PHP... a shape ordinary data takes, which is exactly
why the default declines to block it".

That decision was already made and measured, so the rule was split along it
rather than relitigated: an API naming one thing (`passthru(`, `os.system(`,
`subprocess.run(`) is High and default; a word that also means something else
(`system(`, `exec(`, `spawn(`) is Medium behind WithMinConfidence, paired with
the quoted command or nested call a real invocation carries.

**A module name is never the signal -- again.** The first draft listed
`subprocess.` and `child_process` in the *self-evidencing* tier, which matched a
Python docs link and a sentence about shelling out. Rule 4021's own
documentation says exactly this, and the benign cases written *for 4021* are
what caught it. The subprocess API is listed by call now; child_process is left
to 4021, which pairs it properly.

## Language-specific red team: 17 of 24 through on the first run

The generic rounds were thinning (3/24, then 1/20). Switching to the evasions a
*PHP or JavaScript specialist* reaches for reopened the seam completely.

The JavaScript half was **one idea spelled ten ways**: Function('…'),
[]['constructor']['constructor'](…), globalThis['eval'](…), setTimeout with a
string, eval(atob(…)), window['ale'+'rt'](1). None carries HTML for detect/xss,
a breakout for 3012, or a module name for 4021 -- each of those is right about
the question it asks, and none asks **"is this value turning a string into
code"**. Rule 4024 asks it.

The PHP half added invoke-by-name: `call_user_func('system','id')`,
`array_map('system',['id'])`. Rule 4023 looks for "system(" and these never
write it -- the name travels as a string and something else applies the parens.
Paired with an invoker, because {"type":"system"} is ordinary JSON.

Also added to 3012: `import('data:`, tagged-template calls (alert`1` survives a
filter looking for "alert("), and cookie/localStorage read paired with a network
sink.

17 -> 7 bypasses, zero false positives, no latency change.

## OPEN, and deliberately not rule-shaped: constant folding

Five of the remaining six are one problem:

    sy.'stem'('id')                     PHP concatenation
    ('sys'.'tem')('id')                 PHP concatenation
    "\x73\x79\x73\x74\x65\x6d"('id')    PHP hex escapes in a quoted string
    window['ale'+'rt'](1)               JavaScript concatenation
    $f='system';$f('id');               PHP variable function

Every one builds an identifier the language assembles before it runs. **A
literal list for these is the regex bag this project is defined against** --
there are infinitely many spellings of "system".

The principled answer is a **constant-folding interpretation**: fold adjacent
string literals joined by "." or "+", resolve \xNN and \NNN inside quotes, and
evaluate that reading alongside utf7 and double-encoding. It belongs in
`internal/interpret`, **not** a transform chain -- chains are the expensive axis
(decisions.md: 12 chains vs 10 cost more than 90 extra literals) and an
interpretation is not.

Designed and tracked rather than built, because it is a layer rather than a rule
and deserves its own measurement.

## Constant folding shipped as an interpretation, not a transform

`ClassStringConcat` in internal/interpret folds adjacent string literals joined
by "." or "+" and resolves \xNN and \NNN escapes inside quotes, producing a
reading evaluated alongside utf7 and double-encoding.

**Why an interpretation and not a transform:** chains are the expensive axis
(12 vs 10 cost more than 90 extra literals). An interpretation is on the reading
axis, which is bounded by MaxReadings and only produced when Detect claims the
class.

**Two design details that mattered:**

1. **Only *joined* runs lose their quotes.** The first version stripped quotes
   from every literal, so `'sys'.'tem'('id')` folded to `system(id)` and deleted
   the quoted-argument evidence rule 4023 reads. An isolated literal keeps its
   quotes; only a concatenation loses them.
2. **Escapes are claimed on the backslash, not the quote.** Scanning forward
   from each quote for an escape cost 3.5% of the benign path; a backslash is
   already a lead byte and the check is two comparisons. An escape outside
   quotes yields a reading identical to verbatim, which Set.Build drops.

Folding exposed a new shape the rules did not cover: **indirect invocation** --
`(system)(`, `"system"(`, `window[alert](`. Added to rule 4024. Nobody writes
those benignly, and it is also how a payload evades a matcher looking for
"system(" without any folding at all.

Net +2% on benign POST JSON.

## maxEvaluated is a fraction now, because the count was measuring the ruleset

Raised three times (6 -> 10 -> 12 -> 14) and a fourth was due. **A test that has
to be relaxed every time the product improves is measuring the product's size,
not its behaviour.**

Restated as a proportion: a benign value nominates fewer than one rule in five,
and *that* does not grow when the ruleset does. A genuine prefilter failure --
a benign value nominating most of the ruleset -- still trips it immediately.
Observed worst case is about one in seven.
