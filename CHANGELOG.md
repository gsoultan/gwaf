# Changelog

Pre-v1.0, breaking changes are allowed and every one is recorded here
(CLAUDE.md §4). After v1.0 the root package and `types/` are frozen under
semver, and the four extension interfaces are frozen hard.

## Unreleased

### Security

- **Six of seven detector classes could be bypassed by padding.** Every semantic
  detector bounded its work with a constant named `maxScan` and applied it by
  truncating — `src = src[:maxScan]`. The reasoning written beside each one is
  sound and still true: signals are local to one command, one tag, one header.
  But locality justifies a bounded **window**, not a bounded **prefix**. The
  payload never needed to be longer than the bound; it only needed to sit past
  it.

  Measured, with the payload after N bytes of ordinary text:

  | detector | bound | missed at |
  |---|---|---|
  | `phpi`, `javaser`, `ldapi` | 8 KiB | 16 KiB |
  | `shelli`, `xss`, `ssti` | 64 KiB | 128 KiB |

  Only `sqli` — the one detector with no such constant — was unaffected.

  This is the technique the 2026 literature calls the WAF blind spot, and the
  answer gwaf already had for it was one layer too high. `noteOversize` in
  `transaction.go` states the rule exactly: *"Inspecting the first 64 KiB of a
  value and reporting the request as clean is a bypass with a padding step."*
  The transaction layer refused to do it and every detector did it anyway.

  Fixed by `internal/scan`, which walks the value in overlapping windows so the
  per-window bound that made the detectors affordable is kept while the whole
  value is covered. Overlap is sized proportionally — a signal cannot straddle a
  boundary, since the longest any detector reports is measured in tens of bytes
  against a 1–4 KiB overlap. `TestPaddingPositionDoesNotHide` pins 14 payload
  classes at six padding depths.

  `graphql` and `nosqli` are deliberately left alone: GraphQL scores *global*
  document structure, where a window is not a document, and the NoSQL detector
  reads parameter names, which `MaxKeyLen` already bounds at 256 bytes — four
  times under its own limit.

  **Cost, stated plainly.** `BenchmarkBenignLargeBody` goes from 11.5 ms to
  18.1 ms on a 1 MiB body — 58% slower, because roughly 99% of that body was
  previously not inspected at all. That is not an efficiency regression; it is
  the removal of a shortcut that was a bypass. Benign 1 MiB bodies are still
  allowed, verified, so the cost is time rather than false positives. The
  committed `bench/baseline.txt` figure (7.8 ms) predates this and was recorded
  on different hardware — the same benchmark measured 11.5 ms on this machine
  before the change — so it is left in place rather than silently rewritten.

- **RFC 5987's `filename*` parameter was never read.** `headerParam` requires
  the parameter name to be followed by `=`, and `filename*` is followed by `*`,
  so `filename*=UTF-8''%3Bwhoami` was extracted by no one. The origin
  percent-decodes it — the grammar says the value is encoded, so every origin
  that reads the parameter at all decodes it — and gwaf had never seen those
  bytes. It is now decoded and emitted *alongside* the plain `filename` rather
  than replacing it, because RFC 6266 prefers the extended form while a great
  deal of code reads whichever it looked for first, and both are
  attacker-supplied.

- **A multipart body labelled `application/x-www-form-urlencoded` was not read
  as multipart.** The WAFFLED field survey found over 90% of live sites accept
  the two interchangeably, so for most origins that request *is* multipart and
  gwaf was reading one flat urlencoded pair the origin never sees. The mirror
  image was already handled, because `SniffJSON` is applied on the form path;
  this direction had nothing. `body.SniffMultipart` derives the boundary from
  the body — the header being the thing not believed — and requires a legal
  RFC 2046 boundary plus a real part header, so a diff, a PGP block, a YAML
  document or a CLI transcript beginning with `--` does not qualify.

- **A command injection in the most obvious place it can appear walked through.**
  `?cmd=;whoami` was not detected. The query parser split pairs on `;` as well as
  `&`, so the pair became `cmd=` plus a stray `whoami` and the value `;whoami`
  never existed for the shell detector to score — which it does, at 5 against a
  threshold of 5. The same payload was blocked in a form body, in a JSON body,
  and with the semicolon percent-encoded. Only the rawest spelling got through,
  which is why every hand-written test passed.

  Splitting on `;` was deliberate and half right: some origins do accept it. The
  half it missed is that committing to that reading **discards the other one**,
  and the other one is what most origins do — Go's `net/url` has rejected `;`
  since 1.17 and PHP's `arg_separator.input` defaults to `&` alone. So for the
  common origin gwaf split where the origin did not.

  Both readings are now recorded. This is the CVE-2026-21876 shape one layer up
  from where the same function already guarded against it: its own comment says
  decoding here "would pick a single interpretation and throw the others away",
  and splitting was doing exactly that. **Canonicalization is
  multi-interpretation includes deciding what the values are, not only what they
  decode to.**

- **Payload padding is not a bypass, and now there is a test that says so.**
  Burying a payload past the inspection window is the technique the 2026
  literature is loudest about, and it works against most of the market because
  most of the market truncates — AWS inspects the first 8–64 KiB depending on
  the resource, F5 the first 64, and forwards the rest uninspected. gwaf does
  not truncate: an oversize body is `ReasonLimit`, blocked under the default
  `FailClosed`. That was already true by construction and had no test, which is
  how a property becomes a regression. `TestPayloadPaddingIsNotABypass` pins all
  three halves, including that a payload at 500 KiB depth is still detected and
  that `FailOpen` admits the request while still reporting `ReasonLimit`.

- **The off-origin rules could not match a protocol-relative destination.**
  `offOriginOp.Literals` returned `"://"` and the colon-prefixed backslash
  forms, while its own doc comment said the invariant was "two adjacent
  slash-or-backslash bytes" and listed `"//host"` among the forms it matched.
  The narrower claim reads like a tightening of the same statement and is not
  one: it excludes every destination the scheme is omitted from.
  `redirect_to=//evil.tld/` navigates off-origin in every browser, `absoluteHostOf`
  parses it correctly, and the prefilter never nominated the rule — so the
  handling was right and unreachable. Now `"//"`, `/\`, `\/`, `\\`. Measured:
  no change to nominations on benign traffic, because a benign absolute URL
  contains `://` and was always a candidate.

  **Literals are the one place where being more specific is a bypass rather than
  an optimisation.** Three corpus cases fail without this fix.

### Fixed

- **A urlencoded body with no `=` was shown to value-reading rules as empty.**
  `ParseForm`'s own comment said such a token is "worth inspecting either way"
  and the code then emitted it with an empty value, so only rules targeting
  `ARGS_NAMES` ever saw it. `POST /` with `<script>alert(1)</script>` — one
  nameless parameter — was therefore invisible to the XSS rules, while the same
  bytes with *no* `Content-Type` were caught, because that path falls back to
  inspecting the raw body. The token is now emitted as both name and value,
  since which of the two it is depends on a parser gwaf does not run.

- **Every corpus measurement in the repository ran with the off-origin redirect
  and SSRF rules inert.** v0.4.1 correctly made them require `WithOrigins` —
  the fix for a bypass that read the attacker-supplied `Host` header — and no
  harness was updated, so `test/headtohead` and the evasion corpus measured two
  rules that could not fire. The `tuned` configuration explicitly opted into
  `core.SSRFParamRule` and then reported its detection rate. `gwaf.New` had been
  printing the warning into the test log both times; nothing read it.

  Re-measured against nuclei-templates with origins declared: **redirect 13/60 →
  55/60** (Coraza + CRS: 3/60), **SSRF 5/63 → 44/63** (14/63). With the
  separator fix and rule 4021 alongside it, tuned detection goes **85.9% →
  90.0%**, ahead of Coraza + CRS's 89.7% for the first time, with false
  positives unchanged at 0/12 against their 4/12. README is updated. The evasion
  corpus now declares a `redirect` and an `offssrf` class with 18 attack cases
  and 11 benign counterparts, so this cannot go quiet again.

- **Opt-in rules never got a request-body counterpart.** `withBodyPhase` runs
  inside `core.Default()`, so a rule added through `WithRuleset` is compiled
  exactly as declared — at the header phase, seeing the query string and never a
  form or JSON body. The one-liner in `SSRFParamRule`'s own godoc therefore
  built a rule that could not inspect the bodies webhook and import endpoints
  are made of. Exported as **`core.WithBodyPhase(set)`**; every opt-in rule's
  documented example now uses it.

  This is the second time this exact bug has shipped. The first is recorded at
  `core.go`'s `bodyPhaseOffset`: two of ten injection rules were mirrored by
  hand, so a payload blocked in a query string sailed through in a JSON body.
  Generating the pair fixed it for core rules and left embedders on the old
  footing.

### Added

- **Rule 3012, JavaScript injected into a script context** — and with it XSS goes
  from 962/1007 to **993/1007**, exactly level with Coraza + CRS, taking tuned
  detection to **91.4%** against their 89.7%.

  Found the same way rule 4021 was: by dumping the 45 XSS misses and reading
  them. Two thirds were a payload reflected *inside a script*, where there is no
  HTML for `detect/xss` to read — the attacker does not need a tag, only to end
  the statement they landed in and start their own:

      min=1026553;alert(document.domain)//772    break out of a numeric literal
      x=};alert(1)//                             close a block
      p=";alert(document.domain);"               close a string
      loginMode=alert(document.domain)           land in an expression already
      backurl=1 onmouseover=alert(1) y=          assign a handler, no tag at all

  A call alone is **not** the signal: "alert(" is in every article about XSS, and
  matching it blocks the people fixing the bug. The call needs injection
  evidence beside it — a handler assignment, a terminator (`;`, `}`, `)`)
  immediately before, or a call on `document.domain`/`document.cookie`.

  Two narrowings came from measurement rather than caution. Quotes were in the
  terminator set and had to leave: a bare quote before a call opens a string
  rather than escaping one, so `&quot;alert(1)&quot; is the classic payload`
  matched under the HTML-entity reading. And a `;` closing a character reference
  is not a statement terminator — `&lt;script&gt;alert(1)` tripped the rule for
  the right verdict by the wrong reading, which also cost the correct
  `Interpretation()`.

  Scoped to `TargetArgs` rather than `argTargets`, and that is a latency
  decision: the chain it needs over every collection added a (chain × target)
  combination worth ~17% of the benign POST budget. Scoped, it shares rule
  1013's existing combination and costs 2.1% with zero allocations. This is the
  measurement that moved `CRLFHeaderRule` out of core, rediscovered.

- **Fuzz targets for `SniffMultipart` and `scan.Windows`**, both shipped in this
  same cycle without them. `SniffMultipart` parses attacker-controlled bytes to
  derive a boundary it then hands to the multipart parser, which makes it a
  parser taking hostile input and non-negotiably fuzzed (CLAUDE.md §4);
  `scan.Windows` now runs over every value in every detector, where its failure
  modes are a hang or a silent coverage hole.

  `FuzzWindowsCovers` found a real imprecision on its first run. `overlapFor`
  could return an overlap **larger than the window** for small windows, which is
  an incoherent claim — no window holds a run longer than itself — and the step
  then fell through to a fallback that advanced but guaranteed nothing. The
  guarantee is now exact and stated as such: *a run of at most
  `overlapFor(window)` bytes always appears intact in some window*, which is
  provable (a run of length L survives iff step ≤ window−L, and step is
  window−overlap). 27.5M executions clean afterwards; `FuzzSniffMultipart` 6.5M.

- **Rule 4021, JavaScript process execution.** Found by reading misses rather
  than by imagining attacks: the head-to-head's RCE class was gwaf's largest gap
  against CRS, and dumping the missed requests showed nine of them were Node.js
  and that no detector could have caught any. `detect/shelli` reads shell
  grammar and there is none in
  `require('child_process').execSync('curl …')` — no separator, no command in
  command position, just a JavaScript call whose argument happens to be a shell
  string. `ssti` reads template syntax, `phpi` reads PHP. A payload that never
  leaves JavaScript was outside all of them.

  The module name alone is **not** the signal. "child_process" is ordinary
  content on any site that discusses Node, so the rule requires the capability
  *and* an execution sink — the same narrowing that keeps `IDScriptURI` from
  blocking every article about XSS. Sandbox escapes (`constructor._load`,
  `process.binding(`) are self-evidencing and need no pairing. Six benign cases
  covering prose, imports, issue titles and docs links are in the corpus.

- **`gwaf tune`** — reads a benign corpus and prints the *narrowest* exceptions
  that would have prevented each measured false positive, as compile-checked Go.

  Everyone tunes a WAF by hand, and doing it by hand is why tuning goes wrong:
  the path of least resistance from a blocked legitimate request is to disable
  the rule, because that is one line and always works. The output is Go for a
  human to paste, never applied automatically — an exception is a hole in a
  firewall, and one punched during a build is a hole nobody reviewed. It refuses
  to widen: when the samples disagree on a path or key, no single scope is
  correct, and it says so rather than emitting a rule-wide exception that would
  be indistinguishable from switching the rule off. `calibrate.Sample` gained
  `Path` to make the scoping possible.

- **`GWAF_DUMP_MISSES=<class|all>`** in the head-to-head harness. A per-class
  score says RCE is 287/378 and stops; every improvement after that is a guess
  about which 91 requests those are, when the corpus is right there. Rule 4021
  came directly out of the first run of this.

- **`(*gwaf.WAF).Diagnostics() []Diagnostic`** — the rules that compiled, linted
  clean, and still cannot decide anything: an off-origin rule with no origins,
  an argument rule with no body counterpart. Both failures above were invisible
  because this did not exist; a log line is not an API, and a control plane
  building a coverage view has to be able to ask (CLAUDE.md §2b). `New` still
  logs the first one. The evasion corpus asserts the list is empty before it
  reports a detection rate, so a miss can no longer be misconfiguration wearing
  a miss's clothes.

## v0.4.2

### Added

- **An inert rule now says so.** v0.4.1 made the off-origin redirect and SSRF
  rules report nothing when no origins are declared — the safe direction, and
  the fix for a bypass that read the attacker-supplied `Host` header. The
  failure mode that creates is a user one: an embedder upgrading from v0.4.0
  keeps a ruleset that compiles, passes its tests, and quietly stops covering a
  whole OWASP category. `gwaf.New` now warns once, naming the rule and the fix.
  **Losing coverage must never be quieter than gaining it.**

- **A trust model for the extension interfaces** (`docs/RULES.md` §4, and the
  `rules.EvalContext` godoc). `Target`, `Key` and `Origins` are trustworthy;
  `Method`, `RequestURI`, `Host` and `Siblings` are attacker-controlled. The
  rule is about direction: attacker context used to *convict* is sound, used to
  *acquit* is a bypass. That distinction was the whole content of the v0.4.1
  vulnerability and existed only in a commit message.

- **The head-to-head comparison in the README**, with the reproduce command.
  Against Coraza v3.7.0 + CRS v4.25.0 on 2,455 exploit requests from
  nuclei-templates: detection 89.2% against 89.7%, **zero false positives
  against four**, 178 µs against 1,677 µs. The two harness bugs that produced
  flattering nonsense before they were caught are documented beside the numbers.

- **Falsifiable v1.0 criteria** (`docs/ROADMAP.md`). Three external adopters
  with at least one profile C, three consecutive releases without an extension
  interface change, the trust table unchanged across them, the CVE process
  exercised once for real, and a baseline measured on hardware that is not one
  laptop. Deliberately no detection-rate target: detection is already at parity,
  and chasing another point optimises the one column where the competition is a
  tie.

### Fixed

- **`SplitPathRule` rebuilt a 27-literal operator once per sibling per request.**
  `rules.Operator` is documented as safe for concurrent use precisely so one
  instance can be shared, and this ignored it in the one place it mattered:
  evaluating one value against four siblings cost 88 allocations and 6.6 KB on a
  path whose SLO is zero. Built once now — **2,714 ns and 88 allocs becomes
  247 ns and 1**, with the benign path at 29 ns and zero. Both pinned by
  benchmarks rather than asserted.

- The same nested call passed a `nil` `EvalContext`, silently depending on the
  callee ignoring it. A key-aware implementation would have turned that into a
  panic on the request path rather than a compile error.

## v0.4.1

### Security

- **Fixed a bypass in `core.OffOriginURLRule`, shipped in v0.4.0
  (`ruleset/core/offorigin.go`).** The rule decided whether a destination
  pointed somewhere else by comparing it against the request's `Host` header —
  and an attacker supplies that header as freely as the destination. `Host:
  evil.tld` with `redirect_to=https://evil.tld/` compared same-origin and
  passed.

  The technique is Host-header spoofing, and the lesson generalises past this
  rule: **a verdict that depends on attacker-supplied data is not a verdict.**
  The rule's entire justification for shipping enabled was that it could finally
  tell an OAuth callback from an open redirect; that justification was revocable
  by the request being judged.

  Exploitability is limited for classic open-redirect phishing, because the
  victim's browser sets `Host`, not the attacker. The real damage is silent
  false negatives wherever `Host` is not what the rule assumed — proxy rewrites,
  port variants, multi-tenant vhosts — and `core.SSRFParamRule`, which shares
  the comparison and *is* reached by requests the attacker sends directly.

  Regression test: `TestOffOriginURLTrustsConfigurationNotTheRequest`, which
  asserts the fix by setting `Host` to the attacker's own domain.

### Added

- **`gwaf.WithOrigins(hosts...)`** — the hostnames this application answers on.
  The off-origin redirect and SSRF rules compare against these and no longer read
  `Host` at all. Subdomains of a declared origin are accepted; ports are ignored.

### Changed

- **The off-origin rules report nothing when no origins are declared.** Without
  something trustworthy to compare against, no destination can be shown foreign,
  and silently trusting `Host` would give a guarantee the request can revoke.
  Embedders wanting redirect and SSRF coverage must now call `WithOrigins` —
  a deliberate trade of coverage-by-default for a guarantee that holds.

## v0.4.0

### Added

- **`SECURITY.md`** — the reporting channel, the scope, and the disclosure
  timeline. It was the last unchecked v1.0 prerequisite in CLAUDE.md §4, and it
  commits to the thing that actually matters: every fixed bypass ships a
  regression test in the evasion corpus, because one fixed without a test is one
  that comes back.

- **`rules.EvalContext` carries `Method`, `RequestURI` and `Host`.** Additive to
  a frozen extension point, and deliberate: without the request's own origin a
  rule cannot tell `redirect_uri=https://app.example.com/cb` arriving at
  app.example.com from the same bytes arriving anywhere else, and has to choose
  between missing open redirects and blocking OAuth. Bytes, not strings, because
  three allocations per transaction would cost the zero-allocation benign case.

- **`core.OffOriginURLRule` ships in `core.Default()` and is same-origin
  aware.** A destination on the site's own registrable domain passes; a foreign
  one fires. Redirect detection 20.6% → 87.3%, against CRS's 4.8%.

- **`core.SSRFParamRule(id)`** — the server-side-fetch half of the same
  comparison, opt-in. Enabling it by default blocked a webhook registration and
  a WordPress comment author's website field, which are ordinary operations:
  handing an application a foreign URL to fetch is the feature.

- **`ruleset/profiles`** — `WordPress()`, `Drupal()`, `Laravel()`,
  `IssueTracker()`. Scoped exceptions with a rule, a path, a target, a field and
  a rationale on every entry. On the WordPress corpus they take false positives
  from 2/56 to 0/56 and detection from 606 to 605 — one case, because an attack
  landing in an excepted field is what excepting a field means.

- **`gwaf.WithExceptions(...)`** applies a profile in one call.

- **`detect/shelli.Detector.AnalyzeIn`** — lifts the stored-command-line
  suppression when the parameter names a shell sink. `cmd=echo -n X|md5sum` is a
  CVE because of the parameter it arrived in; `cmd=list` still scores nothing.

- **`test/headtohead` runs the nuclei-templates corpus** over both engines as
  live HTTP middleware, reporting detection, false positives and latency from
  one run. `make nuclei`; the extractor is checked in and the corpus is not.

- **`core.TypeMarkerRule`** and **`core.SplitPathRule`**, both in the default
  set. The first reads a polymorphic type marker (`__class`, `@type`) naming a
  class, which is the JSON form of object injection and has no serialization
  grammar for the existing rules to read. The second reports a sensitive file
  assembled from two parameters — `path=/etc/&target=passwd` is a real CVE, and
  the payload is in no single value.

- **`rules.EvalContext.Siblings`** and **`SiblingValue`** — a read-only view of
  the request's other arguments, for the payload that per-argument inspection is
  structurally blind to rather than merely weak at.

- **`detect/xss` statement-context breakout.** A payload landing in a numeric
  context has no quote to break out of: `1026553;alert(1)//772` closes a
  statement, and `19753";}alert(1);function test(){"` closes a string, a block,
  and then puts both back.

### Changed

- `md5sum` and `sha1sum` are command names. `sha256sum` and `timeout` are not:
  the calibration corpus found both in real GitLab CI steps, and they took rule
  4910 from under its 0.1% ceiling to 0.296% on 10,473 benign requests.

### Performance

Benign GET +1.3%, attack path +1.6%, benign POST JSON +6.3%. The last is over
the 5% gate and is taken deliberately rather than silently: isolating it showed
2.8% is the context plumbing and the rest is one more rule in the default set,
the zero-allocation GET path is unaffected, allocations stay at zero, and the
trade is a fourfold improvement in a whole OWASP category.

## v0.3.0

### Added

- **`transform.HexEscapeDecode`** — `\xHH` and `\uHHHH` only, every other
  backslash sequence byte-for-byte. It exists because `EscapeDecode` cannot be
  used on a path: the full JavaScript reading drops the backslash from an
  unrecognised escape, so `..\..\windows\win.ini` would flatten into one
  segment and every Windows traversal rule would stop matching. The split is the
  ambiguity boundary, not a compromise — `\x2f` is `/` to every consumer that
  reads escapes, while `\.` genuinely forks between a JS string and a Windows
  path, and gwaf answers a fork with a reading rather than a rewrite.

- **`core.OffOriginURLRule(id)`** — opt-in, not in `core.Default()`. An absolute
  URL in a parameter whose name says the application will follow it. Open
  redirect and SSRF are the same request-side signal; only the dereferencer
  differs. It is opt-in because a cross-origin destination is exactly what OAuth
  and payment returns send, and separating that from an attack needs the
  allow-list of trusted destinations, which is the embedder's.

- **`detect/xss` script-context breakout** — `"-alert(1)-"` and
  `1);alert(1);/*` open no tag, so every markup scan was blind to them by
  construction. The trailing comment or quote-rebalance is required, which is
  what keeps ordinary code samples out.

- **`detect/sqli` subquery signal** — a parenthesised `SELECT` grafted onto a
  boolean connector or comparison. Blind and error-based injection carries no
  tautology, no `UNION` adjacency and no comment, so
  `2 AND (SELECT 2*(IF((SELECT ...))))` scored **zero**.

- **`detect/phpi` danger-statement and backtick signals** — a call with a
  non-empty argument list and a `;` terminator convicts alone, while a bare
  `eval()` stays corroborating because a security blog writes that sentence.
  Backticks are PHP's shell-execution operator and were unread.

### Changed

- **The semantic detectors share one chain (`textChain`), now including
  `EscapeDecode`.** A payload arriving as JSON text inside a parameter is
  written `\u003cscript>`, which contains no `<` at all — every structural scan
  was blind by construction rather than by weakness. Giving XSS a private
  two-transform chain instead cost 2.8µs on the benign-POST benchmark, because a
  chain nobody else shares is materialised separately over every value of every
  request.

- **`pathChain` gained `HexEscapeDecode`.** `..\u002f..\u002fetc\u002fpasswd`
  reached no traversal rule, because a path with no separators normalises to
  itself.

- **`indexByteIn` is `bytes.IndexByte`.** It is the no-op check every escape
  transform runs before touching anything, so it executes over every value of
  every request; the hand-rolled loop cost 7% of benign GET once a second escape
  transform joined the path chain. The whole change lands at +4.67% there,
  inside the 5% gate, with allocations still zero.

- **Rule 4007 requires a class name.** It is named for object injection and
  matched plain arrays too, so WordPress's options API blocked on every plugin
  settings save. `unserialize()` on an array of scalars instantiates nothing, so
  no magic method fires and there is no gadget to reach. An object nested inside
  an array is still found.

- **`detect/xss` breakout walks the whole attribute list.** Stopping at the
  first attribute after a quote-break missed every payload that pads the handler
  behind something harmless — `" autofocus onfocus=alert(1)` and
  `" style=position:fixed onmouseover=alert(1)`, both real WordPress plugin
  CVEs.

- **The sensitive-file list dropped its leading slashes and grew.** Most real
  LFI never walks: it hands a parameter the whole path, and exploitation writes
  `etc/passwd` as often as `/etc/passwd`.

### Measured

Against 2,775 real exploit requests extracted from `projectdiscovery/nuclei-templates`
and replayed over HTTP through both engines as middleware, with Coraza v3.7.0 +
CRS v4.25.0 as the control:

| Corpus | gwaf | Coraza + CRS |
|---|---|---|
| WordPress/PHP CVEs (654) | **93.0%** | 89.9% |
| All-technology CVEs (2,775) | 81.5% | 82.3% |
| Encoding evasion (96) | **100%** | 85.4% |
| Benign WordPress (56), scoped | **0 FP** | 8 FP |
| Latency | **85µs** | 1,046µs |

gwaf leads on redirect (82.5% vs 4.8%), XXE (71% vs 42%), deserialization
(58% vs 38%), SSRF (44% vs 25%) and file upload (68% vs 61%); CRS still leads on
RCE (71.5% vs 63.5%), XSS (97.3% vs 93.7%) and SQLi (79.2% vs 70.3%).

### Also in this release

The work that had accumulated unreleased before the corpus replay above.

### Removed

- **Four literal rules the structural detectors superseded**: 4003 (PHP stream
  wrappers), 4004 (PHP open tags), 4008 (Java serialization headers) and 4009
  (the Spring4Shell class-loader walk). `detect/phpi` and `detect/javaser` read
  all four structurally. The ruleset goes 92 → 84 rules, 825 → 813 prefilter
  literals and 8,947 → 8,757 automaton states, with the transform-chain count
  unchanged and still nothing unconditional.

  Retirement was measured, not assumed. `TestRetirementCandidates` removes each
  candidate in turn and re-runs the corpus — and then, because **a corpus is only
  the cases somebody thought of**, each rule's own canonical payloads were fired
  at a WAF built without it.

  That second step is why this list is four rules and not six. The corpus said
  4006 and 4016 were redundant too, and they are not: `jndi:ldap://host/a`
  carries no `${` for `javaser` to anchor on, and `preg_replace('/x/e', …)`
  scores one short of `phpi`'s threshold. Both stayed. The IDs are retired rather
  than reused — they appear in audit logs and in exceptions already written.

  Evasion corpus unchanged at 271/271 with 0/124 false positives. The CRS corpus
  moves by −2 stages of 5,066, which is the honest cost.

### Added

- **The Medium confidence tier, and `OperatorAt` on every semantic detector.**
  `WithMinConfidence` and `WithParanoiaLevel` were wired up with nothing to
  select — `gwaf lint` reported 53 Certain, 29 High and nothing else — which made
  *"confidence tiers are strictly more expressive than paranoia levels"*
  (CLAUDE.md §1) a claim with an empty tier behind it. An operator who wanted a
  wider net had no dial, only the choice between gwaf's defaults and somebody
  else's WAF.

  Five Medium rules (5010–5014), each the *same detector reading the same
  evidence* at a lower score, which is what distinguishes a confidence tier from
  a second, sloppier ruleset. On the CRS corpus: **+169 stages, 36.6% → 39.9%**.

  Off by default and provably so — `gwaf.New()` still compiles Certain and High
  only, and `TestMediumTierIsOptInAndReachable` asserts both halves through
  behaviour: the default must not block `1=1`, and the Medium WAF must.

### Fixed

- **`phpi` declared `"$"` as a prefilter literal**, making the rule a candidate
  for every price, shell variable and template field on the internet. Benign
  traffic went from ≤6 rules evaluated to 8, and in one case 10. The
  variable-function signal now requires a superglobal or `$$` — the form an
  attacker can actually reach, since a local variable they cannot set is not an
  attack they can mount — so the literals are `$$`, `$_` and `$globals`.
  Costs 7 CRS stages; buys back the prefilter.

### Added

- **`detect/javaser` and `detect/phpi`** — structural detectors for the two
  largest CRS miss families, written the way `detect/sqli` is: reading invocation
  structure, never a name list.

  CRS answers Java with `java-classes.data`, several hundred package prefixes
  blocked wherever they appear, and PHP with three function lists totalling
  several hundred more. Both sit behind paranoia levels, because a stack trace in
  a support ticket and the word `array_diff` in a code review are ordinary text.
  A name carries no verdict in either package; only structure does — a
  serialization header, a *nested* interpolation (which is Log4Shell's
  obfuscation and has no benign reading), a class-loader property walk, a stream
  wrapper where a path belongs, a call whose target is data.

  That last one is the case a list can never reach: `$_GET[0]($_GET[1])` names no
  function at all.

  Both are prefilterable, and `FuzzLiteralsAreExhaustive` holds them to it — it
  caught `.exec(` firing the spawn signal with no literal able to cover it, which
  would have made the rule a candidate for every value containing a dot and a
  parenthesis. Removed; every real payload reaches a process through
  `getRuntime()` or `ProcessBuilder`.

  Rules 4018 and 4019, at High confidence for the same reason `shelli` is: a
  build system or an APM agent legitimately carries class names as data.

### Fixed

- **Imported SecLang rules were reading bytes their author never expected.**
  ModSecurity decodes the query string and form body while *populating* ARGS, so
  by the time a rule runs `t:none` means "apply no further transforms" — the
  value is already decoded. gwaf keeps values raw and decodes per rule, which is
  what makes the transform chain a compile-time input. Nobody had reconciled the
  two, so every imported rule without an explicit `t:urlDecode` was silent on
  real query-string traffic. `seclang` now prepends `URLDecode` for the
  collections ModSecurity decodes, and only those: headers and `REQUEST_URI` are
  raw there too, and decoding them would invent a reading the original rule never
  had.

- **The conformance runner ran phase 2 only when a request had a body.** `GET
  /x?foo=payload` has none, so no `phase:2` rule could fire — and that is where
  CRS puts most of its detection. In ModSecurity phase 2 always runs; it is the
  point at which ARGS is complete, query string included.

- **`LoadCRS` converted less than `gwaf-seclang` does.** It never set
  `Options.DataFiles`, so all 17 `@pmFromFile` rules were dropped — 930120's LFI
  filename list among them — and it parsed each file with `Parse` rather than
  `ParseSources`, so `SecDefaultAction` and `SecRuleRemoveById` did not carry
  across files. The suite was measuring a smaller ruleset than gwaf produces and
  reporting the difference as gwaf failing CRS's tests.

  Together these took the rule-ID conformance rate from **28.5% to 44.4%** with
  no detection work at all. CRS 932140 is the worked example: it matched its own
  payload perfectly in isolation and was counted silent across 153 stages.

### Added

- **`TestCRSBridgeFidelity`** — separates the only two reasons a converted CRS
  rule can fail its own test. A rule that was never imported is a coverage number
  the report already carries; a rule that *was* imported and stays silent on the
  payload CRS wrote for it is a translation defect, and no coverage percentage
  shows that. 154 rules are currently in the second list.

### Added

- **`TestCRSGapReport`** — runs gwaf against the Core Rule Set's own regression
  corpus (5,066 stages across 323 files) and groups every failure by CRS rule
  family, so the result is a roadmap rather than a percentage. It separates three
  things a single rate conflates: a missed attack, a false positive, and a CRS
  *rule-scoped negative* that cannot be judged without CRS rule IDs.

  **gwaf blocks nothing that suite calls clean: 0 false positives over 5,066
  stages.**

### Fixed

- **The conformance runner invented false positives.** `ruleScopedPass`
  disqualified a stage from being rule-scoped whenever `status: 200` was set —
  but CRS puts that on nearly every test as boilerplate and carries the real
  assertion in `no_expect_ids` beside it. So 920640, whose body is
  `{"id_order":"select(sleep(10));"}`, was filed as gwaf falsely blocking a clean
  request when CRS is only saying that one rule must not claim it. The presence
  of a `no_expect` assertion now decides it, which took the reported false
  positives from 72 to 0.

  A block with no rule ID also printed as `rule 0 ()`. gwaf rejects a request
  carrying both `Content-Length` and `Transfer-Encoding` before any rule runs,
  and that decision carries `framing_ambiguous` and a reason — the runner now
  prints those instead of saying nothing.

- **`1'or'1` was not detected.** The no-space quote injection: `WHERE u='1'or'1'`
  reads as `u = '1' OR '1'`, and `'1'` casts to 1, so it authenticates. It scored
  1, because under a quoted context the quotes are the context delimiters and
  what remains is a connector between two operands with no comparison for the
  boolean-injection signal to attach to — the shape is invisible to the token
  stream. `SignalQuotedConnector` reads it from the bytes. The welding is the
  discriminator and is what keeps it safe: prose spaces a quoted conjunction
  (`the word 'or' is`), and French and Irish apostrophes come singly (`l'or et
  l'argent`, `O'Brien`), so neither closes the pattern. Found by running CRS's
  corpus (942521, 942522).

- **The UTF-7 reading had never fired on a real request.** `ClassUTF7` looked for
  a literal `+`, but a bare `+` in a query string *is* a space — so every UTF-7
  payload a client can send spells the shift `%2B`, and the class never saw one.
  `+ADw-script+AD4-` was blocked and `%2BADw-script%2BAD4-` was not. This is the
  reading named in its own comment for CVE-2026-21876, inert against the vector
  gwaf is positioned around. `ClassSeparator` had the same hole (`%5C`), masked
  only because rule 1004 matches the backslash form directly.

  Found by auditing every class for the blind spot that made `ClassHTMLEntity`
  inert, rather than by waiting for the next payload. `internal/interpret` now
  carries `TestEveryClassSurvivesPercentEncoding`, a table every class must
  appear in: detect the raw spelling and not the encoded one, and it does not
  work. Three classes had shipped that way.

- **Readings were blind to the encoding every request actually uses.** They are
  enumerated before the transform chain runs, so a value that arrived over a
  query string is still wearing its percent-escapes — and every class keyed on a
  literal character missed it. `ClassHTMLEntity` looked for `&`, which on the
  wire is `%26`, so **no entity payload a browser can send was ever detected**;
  the class fired only for values handed to `AddArgument` directly. The same
  applied to the new best-fit reading. Both now read through one layer of
  percent-encoding, and `hasRawMarkup` does too, so the CMS case it protects
  (`Use the <code>&lt;script&gt;</code> tag`) still suppresses the reading when
  the whole value is encoded.

- **Fullwidth characters walked through.** `ClassPercentU` already claimed U+FF1C
  and U+2215 reach a handler as `<` and `/`; making that claim for only the
  `%uXXXX` spelling was the gap, since `＜script＞` sent as UTF-8 is the same
  characters and the same folding, and NFKC in .NET and Java arrives there by
  another route. `ClassBestFit` folds them. Only punctuation folds — fullwidth
  letters and digits are ordinary CJK input and are left exactly as sent.

- **`shell.php.jpg` in a sentence was blocked.** Rule 4017's chain strips
  whitespace, so the support-desk line "the file upload rejected shell.php.jpg
  correctly" arrived welded together and the component after `.php` was
  `jpgcorrectly` — a word, not an extension. The trailing component must now
  look like one. Bounded by length rather than an allowlist: an upload filter
  reads the final extension against its own list, and a longer one is not on it.

- **Three false positives, found by a benign corpus built to look hostile.** A WAF
  that blocks real traffic is uninstalled by Friday, and its detection rate is
  then zero because it is not running.
  - `the UNION SELECT pattern is a classic injection example` was blocked.
    `SignalUnionSelect` was worth 5 and reached the threshold alone, so any
    adjacent UNION and SELECT fired — which is the keyword matching this detector
    exists to replace. A real UNION SELECT is followed by a select-list; prose is
    followed by English, and that is now the test.
  - `cd ../.. then run make from the project root` was blocked. Rule 1004 matched
    the literal `../..` and its chain strips whitespace, so the sentence arrived
    as `cd../..thenrunmake…`. It is now structural: two *consecutive* segments
    that each end in a separator, which every walking payload has and the
    sentence does not.
  - `1%a0OR%a01=1` in its UTF-8 spelling. The tokenizer accepted the raw `0xA0`
    and not `0xC2 0xA0`, which is not a decision but a gap — the same character,
    two encodings, two verdicts. Found by the mutation fuzzer.

- **`INTO OUTFILE` and `PROCEDURE ANALYSE()` were not detected**, both found by
  running the converted CRS side by side with gwaf's own ruleset and diffing the
  verdicts. The first is the standard MySQL route from injection to code
  execution — write a PHP file into the webroot and request it. Neither has the
  shape the danger-call check looks for: `INTO OUTFILE` has no parentheses and
  `analyse` tokenizes as an identifier. The grammar carries the distinction, so
  the quoted path and the call parentheses are both required and `log into the
  portal` stays clean.

- **The XSS polyglot walked through.** Two independent holes: `scanBreakout`
  stopped its separator run at `*`, though `/**/` between attributes separates
  them exactly as a space does once a browser is inside a tag; and a handler
  assignment with no tag or quote to anchor on was not read at all.
  `SignalHandlerAssignment` is worth 2 and never enough alone — `onclick=alert(1)`
  as a whole value is a string people write about — but with the `javascript:`
  scheme the same value carries, it is the polyglot.

### Fixed

- **Writing a command's full path bypassed shell-injection detection.** `; id`
  was blocked and `; /usr/bin/id` was not: `commandWord` stops at the leading
  slash, and `scanPaths` only resolved basenames against the interpreter list, so
  `/bin/sh` and `/bin/bash` were caught and nothing else was. `| /usr/bin/curl
  evil.test` reached the backend. An absolute path in command position now
  resolves to its final component and is looked up in the full command
  vocabulary — in command position specifically, so `/api/v1/ping` in an ordinary
  value is untouched.

- **`/static/js/node.min.js` was blocked.** `SignalInterpreterPath` is worth 5 and
  reaches the threshold alone, and it fired on any `/interpreter` preceded by a
  path component without checking what followed — so a bundled asset URL, which
  is on a large share of the web, read as the node interpreter. A name followed
  by `.` or `/` is a stem or a directory, not the executable.

- **Triple-encoded input walked through.** `%252e%252e%252f` was blocked because
  the one-pass reading composed with a rule's own `urlDecode` transform covers
  two decoders; `%25252e%25252e%25252f` was not, and a CDN in front of a proxy in
  front of an application is three. `ClassMultiEncoded` adds a fixed-point
  reading, bounded at four passes, triggered only on `%2525`. It is a separate
  reading rather than more passes on `ClassDoubleEncoded` because decoding
  further can destroy the evidence — `%%32%65%%32%65%2fapp.conf`
  (CVE-2021-42013) reads as traversal after one pass and normalises to an
  ordinary `/app.conf` after three. The evasion corpus caught that regression.

- **`%uXXXX` was not decoded at all.** IIS's own encoding is in no URI standard
  and IIS and ASP.NET decode it anyway; `%u002e%u002e%u2215etc%u2215passwd`
  reached the backend. `ClassPercentU` adds the reading, including the handful of
  characters Windows best-fit maps to ASCII when narrowing UTF-16 — U+2215 and
  U+FF0F are not slashes until they arrive at the handler.

- **`1%a0OR%a01=1` was not detected.** MySQL's lexer accepts `0xA0` as
  whitespace, so the injection runs while reading as one identifier to an
  ASCII-only tokenizer. The tab, newline and carriage-return spellings of the
  same payload were all blocked.

### Added

- **Five transforms: `CSSDecode`, `CmdLine`, `ReplaceComments`,
  `RemoveCommentsChar`, `Base64Decode`**, and `transform.All`. The cost of not
  having them was measured rather than guessed: the pentest harness ran a
  converted Core Rule Set and scored **zero on every XSS category**, because CRS
  941100 *is* the `@detectXSS` rule and carries `t:cssDecode`, so the converter
  skipped it — while `@detectSQLi` carries no such transform, converted, and
  scored 3/3. One missing normalization cost an entire detection tier. `seclang`
  maps all five, and each has a fuzz target: `transform.All` is what the fuzz
  corpus and the `MaxOutputLen` test iterate, so a new transform cannot be added
  without them. Both lists were hand-written and had already fallen behind —
  `EscapeDecode` shipped without ever being fuzzed.

- **Protocol and robustness phases in `test/pentest/run.sh`**: `canon`
  (multi-interpretation decoding), `hpp` (parameter pollution), `headers`,
  `multipart` (hand-written bodies — the framing is the attack), `limits` (deep,
  wide and long inputs, where the pass condition is "answered, quickly" rather
  than "blocked") and `concurrent` (interleaved attack and benign traffic,
  checking for cross-transaction state leakage). Every fix above came from them.

### Fixed

- **A converted Core Rule Set answered 403 to every request.** `generate.go`
  rendered every regex operator as `seclang.MustRegex(pattern)`, discarding
  `Negated()`. SecLang's `!@rx` therefore came back as its own opposite, and CRS
  920600 — "block unless the Accept header is well formed" — became "block when
  the Accept header is well formed". `GET /health` with no arguments was blocked.
  That is the invariant in CLAUDE.md §2 that the WAF must never be the outage,
  broken as directly as it can be. The compiler separately ignored negation for
  `@streq`, `@beginsWith`, `@within` and `@pm*`, which CRS also uses; those
  cannot express a negation, so they are now reported rather than imported
  inverted. 36 of 221 imported CRS rules were affected. Found by pointing the
  pentest harness at the converted ruleset, which is the only reason it surfaced:
  every unit test asserted on the `rules.Set`, where negation was always correct,
  and the defect lived in the source emitted from it.

- **Converting a real Core Rule Set release failed outright.** `seclang` kept two
  hand-maintained transform tables: the compiler accepted `t:jsDecode` and emitted
  `transform.EscapeDecode`, `generate.go` had no case for `escape_decode`. So
  `report` counted CRS rule 932210 as translated and `convert` then died on it —
  every conversion of the actual OWASP CRS, which is the only reason the module
  exists. The two tables are now one (`seclang/transform.go`) and a test walks it,
  so a transform the compiler can emit always has a name to render it with. No
  test in the tree could have caught this: they all fed `Generate` a fixture that
  happened not to use the transform.

- **Two CRS rules imported as dead text.** `SecRule REQUEST_METHOD "@within
  %{tx.allowed_methods}"` (911100, and 920430 for HTTP versions) converted to a
  literal match on the string `%{tx.allowed_methods}`, which no request contains.
  That is worse than skipping them: the operator is told method enforcement is in
  place while nothing enforces it. Unexpanded macros in an operator argument are
  now reported with the macro named, per the package's own rule that a rule which
  cannot be translated faithfully is reported, never approximated.

- **Skips named every input file at once.** `gwaf-seclang` concatenated its inputs
  and passed the joined list as one name, so all 27 CRS files shared a location and
  line numbers pointed into a buffer that existed nowhere on disk. Directives now
  carry their own file and line.

### Added

- **`seclang.ParseSources` / `ParseSourcesStrict`.** Compile several SecLang files
  as one ruleset: state carries across them in order as ModSecurity would, while
  each skip still reports the file it came from. Concatenating bytes gets the
  statefulness right and the attribution wrong.

- **`seclang.Options.DataFiles`.** Resolves `@pmFromFile` / `@pmf` phrase lists so
  their rules import with the phrases inlined, keeping the generated ruleset
  self-contained. Eighteen CRS rules were previously reported untranslatable,
  including 930120 (LFI filenames) and the shell-command lists — with them absent
  the converted CRS missed `../../../../etc/passwd` and `; cat /etc/passwd` while
  reporting a successful import. The converter never opens a file itself: reading
  from disk is an environment capability the caller grants, so the library stays
  embeddable where that is not allowed.

- **`detect/promptinjection` and system-prompt-leakage (rules 13001/13002).**
  Prompt injection is number one on the OWASP Top 10 for LLM Applications,
  including the 2026 edition grounded in 7,714 real incidents, and CLAUDE.md has
  listed it in scope since it was written while `detect/` had nothing. It scores
  *imperative structure*, not vocabulary: "ignore all previous instructions"
  fires, "the attack works by telling the model to ignore previous instructions"
  scores zero, and both are in the corpus. Ships at High — a red-team console or
  prompt library produces true matches that are not attacks.

- **Shadow-API discovery.** `Transaction.UndeclaredRoute` reports that one
  request went to a route no schema operation describes;
  `middleware.OnUndeclaredRoute` surfaces it per request. Aggregating is memory
  and memory is the embedder's, so gwaf reports the bit and the embedder keeps
  the inventory. Works in both open and closed schemas, so the signal does not
  disappear at the moment enforcement starts.

- **`audit/`** — a decision rendered as a record complete enough to act on:
  matched bytes (bounded), transform chain, and the *narrowest exception* that
  would suppress the finding. Sinks for line-delimited JSON, fan-out, and
  severity filtering. Zero dependencies: OTel is deliberately not here, because
  an exporter is a dependency the embedder did not choose — `Sink` is one method
  so implementing it over your own is small.

- **`telemetry/`** — counters an operator actually watches: requests, blocked,
  allowed, budget exhaustion, undeclared routes, per-rule and per-severity
  counts, mean/max latency, and `TopRules`. No unbounded label cardinality,
  because that is how a metrics endpoint becomes the outage.

- **Nine runnable godoc examples** (previously zero), covering `New`,
  `Explain`, `WithMode`, `WithSchema`, `WithRuleset`, `WithException`,
  `AddResolver`, `UndeclaredRoute`, and `RulesEvaluated`. CLAUDE.md §2b makes
  these binding; they are tests, so the API cannot drift from its documentation.

  Writing them found three wrong claims immediately: a `Resolver` API that does
  not exist, a `Reason` string that is `schema_violation` rather than `schema`,
  and an example that added a query parameter twice because `SetRequestLine`
  already parses the query string.


### Fixed

- **Nested prototype pollution in JSON bodies.** `{"constructor":{"prototype":
  {"isAdmin":true}}}` passed while the flat `__proto__` form was caught, because
  the JSON parser emits each nesting level as a separate name. The full dotted
  path is now recorded for the positional primitives (`prototype`, `__proto__`,
  `constructor`), gated by length-checked comparisons so ordinary keys pay
  nothing — the unconditional form measured a 28% regression on benign JSON.
- **HTML-entity-encoded schemes in an XSS href.** `java&Tab;script:` and
  `javascript&colon;alert(1)` evaded, because the scheme matcher skipped raw
  control bytes but not their entity forms. It now decodes numeric and the
  scheme-relevant named character references.
- **Apache double-percent-encode traversal (CVE-2021-42013).** `%%32%65`
  collapses to `%2e` then `.` under a permissive decoder; `interpret.Detect` now
  marks the `%%` lead as double-encoded and evaluates the doubly-decoded reading.
  (A Go origin's net/http rejects the malformed escape with 400 before gwaf; this
  matters for gwaf proxying to a non-Go backend.)


### Added

- **`IDPHPPregReplaceEval` (4016)** — `preg_replace` with the `/e` modifier,
  which evaluated the replacement as PHP. Removed in PHP 7, which is exactly why
  it still matters: the installs that never upgraded are the ones being
  compromised. This is the one shape in the dynamic-eval family a literal cannot
  express — the modifier rides on *any* pattern — so it is the L2 regex fallback
  working as designed: RE2, linear time, and prefiltered on the `preg_replace(`
  literals, so a request without them never reaches the regex.

### Fixed

- **Four PHP rules matched too narrowly and let real web shells through.** All
  four were found by the WordPress/PHP/malware scenario in `test/pentest`, and
  each was a literal chosen tighter than the attack it names:

  - `IDPHPCodeUpload` matched `<?=$` rather than `<?=`, so it caught a short
    echo tag only when it echoed a *variable*. `<?=system('id')?>` and
    ``<?=`id`?>`` walked through. `<?=` opens code in every PHP since 5.4 and
    cannot collide with XML, where `<?` starts a processing instruction whose
    target must be a Name.
  - `IDPHPDynamicEval` matched `@eval(` but not `eval($_`, so the same web shell
    written without the error-suppressing `@` was missed —
    `eval($_POST['x'])` is complete on its own. `assert($_` likewise. This
    extends the rule's stated principle rather than relaxing it: the argument is
    a superglobal, so the shape is still "evaluate whatever the client sent",
    and JavaScript's `eval` or Python's `assert` cannot collide because neither
    has `$_`.
  - The same rule's `preg_replace('/.*/e` literal only ever matched the payload
    that spelled `.*`; `/(.*)/e` and `/x/e` passed. Replaced by rule 4016 above.
  - `IDServerConfigUpload` covered Apache only, so an IIS `web.config` naming an
    interpreter through `scriptProcessor=` was not matched. That attribute is
    the IIS form of `AddType … x-httpd-php` and is no more FP-prone. The legacy
    `<httpHandlers>` form is deliberately still not matched: what makes it
    dangerous is the pairing of a wildcard path with a handler type, which a
    literal cannot express, and the element alone is ordinary .NET config.

  Evasion corpus is 227/227 with false positives 0/124, and the benign controls
  that decide deployability — a real image upload, a `web.config` that enables
  nothing, prose about `eval` — all still pass.

- **SQLi evaded detection inside MySQL executable comments.** The tokenizer
  treated every `/*…*/` as one opaque comment, so `UNION` and `SELECT` inside a
  `/*!50000UNION*/ /*!50000SELECT*/` pair were never seen as keywords and the
  scorer found no structure. But `/*!…*/` is not a comment to MySQL — it
  executes, and `/*!NNNNN…*/` executes from version NNNNN — so `detect/sqli` now
  lexes the executable body as code, the way a real parser does. This is the
  `versionedmorekeywords` / `modsecurityversioned` evasion the package header
  always claimed to catch. Found by the pentest harness in `test/pentest`;
  detection is 57/57 with false positives still 0/60 and the tokenizer fuzz
  target clean, because only the executable-comment *structure*, not the
  characters, now lexes as code — benign values carrying `/*!important*/` are
  unaffected.

- **Literal extraction could silently stop a rule firing.** `Literals()` tells
  the prefilter which byte sequences a rule requires, and the engine skips the
  rule entirely when none appear — so a literal that is not genuinely required
  makes the rule quietly stop matching, with no error and nothing in the
  compile report. Two ways to reach that state are fixed:

  - The walk mixed conjunctive and disjunctive reasoning. A concatenation
    returned the literals of *all* its parts including a nested alternation's,
    and the alternation then kept the longest of that mixed list. For
    `\.(php[345]?|phtml|aspx?)$` the parser factors the shared `ph` prefix and
    the surviving literal was `tml` — a rule that no longer fired on `.php`.
  - The minimum-length filter dropped individual members of a disjunction.
    `foo|ab` kept only `foo`, asserting that it covered every match; it does not
    cover `ab`. The filter is now all-or-nothing.

  Both were found by a soundness property — every string a pattern matches must
  contain one of its declared literals — now enforced by a test and a fuzz
  target.

- **A character class between alternation branches produced no literals at
  all.** The parser factors `py|pl` into `p[ly]`, and refusing to enumerate the
  class dragged the whole disjunction below the length floor, so a common
  extension list like `\.(exe|php|sh|py|pl|rb)$` extracted nothing and ran on
  every request. Small classes are now enumerated; wide ones still yield
  nothing, because 26 automaton entries that between them match nearly every
  value is a prefilter that costs memory and excludes nothing.

### Added

- **`rules/op/rx`** — the `@rx` operator, promoted out of the `seclang` module.

  It lived there on the reasoning that an embedder writing `gwaf.New()` should
  not link a regex engine because somebody else is migrating from CRS. That was
  right about the cost and wrong about where to put it: Go links per package, so
  a package of its own gives the same guarantee without making an embedder who
  wants one regex rule take a SecLang parser as well. `seclang` now delegates to
  it, so there is one implementation rather than two that can drift.

  The core module still has zero third-party dependencies.

- **`types.TargetFileNames`** — the `FILES_NAMES` target.

  The multipart parser synthesises a `<field>.filename` argument key for an
  uploaded file's name, and `Target.Name` matches exactly, so there was no way
  to write a rule about "any upload's name": an author had to know the form
  field in advance or inspect every argument — which means blocking
  `?page=index.php` to catch an upload called `index.php`. The name is still
  recorded as an argument too, so no existing rule narrows.

### Breaking

- **`op.Func` returns `*op.FuncOperator` rather than `rules.Operator`**, so the
  chained form `op.Func(name, fn).WithLiterals("…")` compiles. It is the form
  `docs/RULES.md` §5 has always documented, and it was a type error: `Func`
  returned the interface, so the method was unreachable and callers needed an
  `op.LiteralHinter` assertion. `*FuncOperator` satisfies `rules.Operator`, so
  code that only stores the result is unaffected.

  Found by writing `examples/customrules` — an escape hatch that needs a type
  assertion is not "always present and always visible" (CLAUDE.md §2b).

- **`Fuel` moved from `internal/budget` to `types`.** `Operator.Cost()` now
  returns `types.Fuel`; `gwaf.WithFuelLimit` and `Transaction.FuelSpent` take
  and return it.

  This fixes an extension point that could not be used. `Cost()` returned
  `budget.Fuel` from `internal/budget`, and Go's internal-package rule is keyed
  on import path — so every first-party detector satisfied the interface and a
  vendor at their own module path got:

  ```
  myOp does not implement rules.Operator (missing method Cost)
  use of internal package .../internal/budget not allowed
  ```

  `Operator` is one of the interfaces CLAUDE.md §4 describes as the most
  expensive API surface in the project, "third parties implement them, so
  post-v1.0 they are frozen hard". It was impossible to implement, and no test
  in the tree could see that, because everything in the tree is on the
  permitted side of the import-path rule.

  **Migration:** replace `budget.Fuel` with `types.Fuel` and
  `budget.Cost*` with `types.Cost*`. `budget.Fuel` remains as a type *alias*, so
  in-tree code keeps compiling and the two names denote one type.

  `test/extension` is a new module declaring itself `example.com/gwafvendor`. It
  implements `Operator`, `Transform`, `Action`, and `Resolver` from a foreign
  path, so the compiler now enforces what the documentation asserts.

- **Extension points are four, not five.** `Detector` was documented as a fifth,
  "plugging into the L1 semantic tier rather than the rule tier". No such tier
  exists: the engine dispatches through `Operator.Eval` and nothing else, and
  all six first-party detectors expose `Operator()`. A third party writing a
  semantic detector implements `Operator`, the same way they do. The docs were
  describing an architecture nobody built.

### Added

- **File-upload attacks, both halves.** Prompted by a real compromise: an
  attacker writing files into a WordPress install.

  Blocking the *upload* was already strong — 14 of 16 evasions failed, including
  double extensions, `shell.php\x00.jpg`, uppercase `.PHP`, trailing dot and
  space, `.phar`, and a plugin zip — because the detectors read the file content
  and a web shell is PHP whatever the filename claims.

  What was missing is the half that still matters after the first has failed:

  - **Rule 1010, script execution inside an upload directory.** A file that
    arrived before gwaf was deployed, through a plugin it does not sit in front
    of, or with stolen credentials, is already on disk. Requesting it is the
    step that turns a file into code, and that request gwaf can always see.
    Deliberately narrow: a script under a directory whose purpose is
    user-supplied content, not "a PHP file", which would block WordPress itself.
  - **Rule 4015, server configuration directives in an uploaded value.** The
    answer to an upload filter that blocks `.php` is to upload a `.htaccess`
    saying `AddType application/x-httpd-php .jpg` and then upload the shell as
    an image. Both files are individually permitted; together they are RCE.
  - **`core.WordPressHardeningRule`** (opt-in) extends 1010 to all of
    `wp-content`. Not default: a minority of plugins expose endpoints by having
    the browser request their PHP file directly.

- **Positive security now covers what no signature can.** A broad simulation
  (WordPress, malware droppers, CVE exploitation, nginx/Apache/cPanel, Go, Java,
  DDoS, AMP/host spoofing, and gambling-platform abuse) showed the gap is not
  always a missing rule. A stake of `-5000` is a valid number, `"BTC"` is a
  valid string, and `/phpmyadmin/index.php` is a valid path; they are attacks
  only because *this* application does not accept them.

  - `schema.Field.Min` / `.Max` with `schema.Bound` — numeric range validation.
    OpenAPI has modelled `minimum`/`maximum` since Swagger 2.0 and gwaf did not
    carry them across, so every range check stayed in application code where a
    WAF cannot see it. New violation: `ViolationRange`.
  - **`Field.Required` is now enforced.** It was documented as "rejects the
    request when the field is absent" and did nothing: `ViolationMissing` was
    declared and never assigned. Tracked with a bitmask so the hot path still
    allocates nothing.
  - `Schema.Closed()` rejects requests matching no operation. A ruleset would
    need to know every product on the internet to block `/cpanel`,
    `/mgmt/tm/util/bash`, and whatever is disclosed next month; a closed schema
    needs to know one API and rejects all of them without naming any. Opt-in,
    because it is only correct once the schema is complete.
  - `examples/positivesecurity` — runnable and tested, 15 rows.

- **Ten rules for what the simulation showed was genuinely missing**: 1006
  exposed artifacts (`/.git/`, `/.env`, `/.htpasswd`, `/server-status`,
  `/debug/pprof`), 1008 backup and editor leftovers, 1009 traversal to an
  application config file, 4011 OGNL/SpEL reaching the JVM (Struts2
  CVE-2017-5638, Spring Cloud Function CVE-2022-22963), 4012 deserialization
  gadget classes, 4013 PHP dynamic evaluation (the web-shell one-liners), 4014
  remote file inclusion.

- **Five attack classes that a simulation walked straight through**, found by
  replaying current real-world payloads rather than by reading the ruleset:

  | Rule | Class | Tier |
  |---|---|---|
  | 4006 `Log4j lookup expression` | JNDI / CVE-2021-44228, incl. `${lower:}` and `${::-}` nesting | Certain |
  | 4007 `PHP serialized object` | PHP object injection / PHPGGC gadget chains | Certain |
  | 4008 `Java serialized object` | `rO0AB` and raw `\xac\xed`, anchored at value start | Certain |
  | 4009 `Spring class loader property path` | Spring4Shell / CVE-2022-22965 | Certain |
  | 11001 `Cloud metadata endpoint` | SSRF against IMDS (AWS, GCP, ECS, Alibaba) | Certain |
  | 11002 `Protocol-smuggling URL scheme` | SSRF via `gopher://`, `dict://` | Certain |
  | 12001 `Prototype pollution key` | `__proto__`, `constructor.prototype` | Certain |

  `core.LoopbackSSRFRule` is exported rather than shipped, for the same reason
  as GraphQL introspection: `localhost` and `127.0.0.1` are ordinary values in
  CI, staging, and webhook registrations, so a core rule matching them is the
  one that gets the WAF switched off in week one.

- `examples/customrules` — a runnable walk through the whole custom-rule
  surface, tested so that what its comments claim is what CI checks.

- **`rules.Resolver` and `types.TargetResolved`** — the mechanism by which a
  signal gwaf deliberately does not compute reaches a rule: an IP reputation
  score, a JA4 fingerprint, a bot score, a tenant identifier. Registered per
  transaction with `Transaction.AddResolver`, called only when a rule in the
  phase reads its name, and at most once per request.

  This is the implementation behind the scope line in CLAUDE.md §1. gwaf
  analyses one request with no memory, so rate limits and reputation belong to
  the embedder — and that boundary only works if the results of the embedder's
  work have a way back in. Until now they did not.

- **`detect/graphql`** — depth, complexity, alias amplification, and fragment
  cycles, all computed from one document in isolation. Abuse with no payload:
  the document is valid, the field names are real, and the cost is in its shape.
  `graphql.IntrospectionRule` is exported rather than shipped in core, because
  introspection is how every GraphQL development tool discovers a schema.
- **`schema/grpc`** — compiles a protobuf FileDescriptorSet into a gwaf schema
  (separate module). Every RPC becomes a route, and declared int32/bool/enum
  fields are provably inert, so the engine skips them. `bytes` is deliberately
  not inert: the declared type says nothing about the content.
- **Protobuf wire parsing** (`internal/body/protobuf.go`). Printable-run
  extraction has a length floor that is right for a JPEG and wrong for a
  document made of fields: a 7-byte SQL injection in a protobuf string field was
  missed and a 9-byte one was not. Fields are now named by number path, which is
  also what lets a descriptor type them without the core ever needing one.
- gRPC message unframing, per-message decompression via `grpc-encoding`, and
  whole-body base64 decoding for `grpc-web-text` (`internal/body/grpc.go`). Two
  bypasses of the same class as the Content-Encoding one: a payload the origin
  will act on was opaque to the detectors.
- `Decision.Explain()` returning an `Explanation` with the matched span, matched
  bytes, transform chain, interpretation, and `NarrowestException()`.
- `rules.Exception` and `gwaf.WithException` for scoped suppression. Exceptions
  cover a rule's generated counterparts via `Rule.DerivedFrom`.
- `gwaf explain` — describes a rule, or replays a request and explains the
  outcome.
- `detect/nosqli`, `detect/ssti`, `detect/shelli`, `detect/ldapi`.
- `schema/openapi` — OpenAPI 3.x frontend (separate module).
- `seclang` — SecLang/CRS bridge with RE2 literal extraction (separate module),
  plus `gwaf-seclang report|convert`. `convert` emits Go source rather than a
  runtime loader: the point of migrating is to stop having a second
  configuration language, and generated Go is compiler-checked, diffable, and
  costed by `gwaf lint`. Everything untranslatable is a comment in the generated
  file rather than a line in a log nobody kept.
- `adapters/gin`, `adapters/echo`, `adapters/fiber` (separate modules). chi,
  gorilla/mux, connect-go, and `net/http` need no adapter.
- Response phase: `SetResponseStatus`, `AddResponseHeader`,
  `ProcessResponseHeaders`, `WriteResponseBody`, `ProcessResponseBody`.

### Changed

- **`core.CRLFHeaderRule` ships opt-in rather than in core, on a measurement.**
  It is the only rule needing a transform chain that preserves line breaks — the
  break *is* the attack — and a chain no other rule shares is materialised over
  every value of every request. Benign POST JSON measured 15.4µs with it in core
  and 13.7µs without, against a 15µs SLO. One rule may not spend 8% of the
  latency budget on requests it cannot match. The latency gate caught this; it
  was not noticed by review.

- **Rule 4003 matches the wrapper *scheme*, not a list of wrappers.** It carried
  `php://input` and `php://filter` and stopped there, so `phar://`, `zip://`,
  `glob://`, and `php://memory` went through. `phar://` is the serious one:
  reaching a phar archive deserializes its metadata, so it is remote code
  execution wearing the costume of a file read. Matching `php://` covers input,
  filter, memory, temp, fd, stdin and whatever PHP adds next, and it is shorter
  than the list it replaces.

- `detect/ssti` recognises Twig's own escape hatch — `_self.env`,
  `registerUndefinedFilterCallback`. `_self` alone stays absent because
  `{% import _self as forms %}` is how every Twig macro file is written.

- **The benign corpus has an `adjacent` archetype** (10,386 → 10,415). Every
  other archetype models an application and happens to exercise the ruleset;
  this one is the reverse — each request exists because a specific rule could
  plausibly match it. It is what removed `ldap://` and `jar:` from the SSRF
  scheme rule and `${env:` from the Log4j rule: all three matched nothing in the
  corpus as it stood, which proved only that the corpus had never seen an
  identity integration or a Java build.

- `middleware` and `examples` are now separate modules, so a framework adapter
  can never reach the core module's dependency graph.
- `SetRequestLine` parses the request target's query string into arguments.
  Previously only the `net/http` middleware did, so rules reading argument
  *names* were inert for every other embedder.
- Content-Type is no longer trusted for body format. A body that looks like
  JSON is parsed as JSON whatever it claims to be, because
  `json.NewDecoder(r.Body).Decode(&v)` never reads the header.
- `detect/shelli` no longer reads `REQUEST_URI`, and ships at High rather than
  Certain. A query string uses `&` as its own separator, so `?q=x&sort=price`
  parsed as a command boundary followed by `sort` — measured at a 20%
  false-positive rate.

### Performance

Every SLO in CLAUDE.md §2 is met. Benign POST with a 1 KiB JSON body went
16.4 µs → ~13 µs against a 15 µs target, which it had never met; benign GET
1.5 µs → ~0.77 µs; ruleset scaling 354 ns → ~240 ns and still flat from 10 to
10,000 rules. From transform-prefix reuse, phase pruning, and target pruning —
all of which evaluate fewer rules rather than making each one cheaper.

### Testing

- Benign calibration corpus 1,435 → 10,386 requests across eleven application
  archetypes. The `Certain` tier is measurable for the first time; it needs
  ~10,001 distinct requests to observe one violation at its ceiling.
- Evasion corpus 139 → 169 cases; `declaredClasses` gains jndi, phpobj,
  javaser, ssrf, and protopoll. The list existed because a technique-only corpus
  cannot see a missing attack class — and the same blind spot had reappeared one
  level up, since a class absent from *both* the corpus and the list is
  invisible twice over. 139/139 was an honest number about a question that was
  not being asked.
- Evasion corpus reorganised as attack class × evasion technique, with
  `declaredClasses` failing the build when a class gwaf claims to detect has too
  few cases behind the claim.
