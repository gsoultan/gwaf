# Red-team round 4: what was fixed, and what is known and still open

Run 2026-08-14 by six parallel attack-class specialists (Claude Fable 5, the
Mythos-class model) against the shipped ruleset at v0.5.2 (`59636bd`). Fixes
landed in `386484a`; the round is carried by `redteam4_test.go`.

Every reported bypass was reproduced against the real WAF before anything was
changed. That mattered: agents are confident narrators, and reproducing first is
what separated the four real gaps from the plausible-sounding ones.

## The four fixed, and the one shape they share

The engine had already decided what an origin reads, and then did not read it
that way. Invariant #1, four times.

1. **UTF-16/UTF-32 bodies.** `internal/interpret` enumerated UTF-7 (the
   CVE-2026-21876 charset) and not its sibling, so `charset=utf-16` was
   inspected as interleaved NULs and passed clean while a Java servlet or
   ASP.NET decoder read `<script>`. `internal/body/multipart.go` declines to
   transcode part charsets *because* interpret is meant to evaluate them, so the
   gap made that deferral a hole.
2. **SQL line comments.** `--` and `#` ran to end-of-value; every SQL engine
   ends them at the newline and keeps parsing.
3. **Fullwidth shell metacharacters.** `bestFitASCII` folded what a document
   needs (`< > / \ . ' ( ) =`) and omitted `; | & $` and backtick.
4. **Polite imperatives.** `isImperative` disqualified any phrase preceded by a
   word, so "Please ignore all previous instructions…" scored 0 while the
   blunter form scored 5.

### The part that would have been missed

Adding `ClassUTF16` did **not** close finding 1. A wide-char body is binary by
every test in `internal/body` — it is half NULs — so it never reached the
reading layer: `IsBinary` sent it to run extraction, ASCII-as-code-units leaves
printable runs *one byte long*, and `minTextRun` (8) dropped every one. The body
was inspected, found to contain no text at all, and passed.

**A new reading is worthless if the value never arrives at the reading layer.**
Check the path before crediting the class.

## Real, reproduced, and deliberately NOT fixed

Each is a live bypass. The reason is the cost of closing it, not doubt that it
exists.

- **Long UTF-7 runs.** `maxEntityLen = 32` bounds `utf7RunEnd`, so a single
  shift run longer than 32 base64 chars is never claimed as `ClassUTF7` — the
  CVE vector walks through at 43. Measured cutoff: 32 blocks, 43 does not. The
  cap is the anti-quadratic bound; raising it trades a bypass for a DoS. Needs
  the fuel analysis.
- **`CHAR(39)+CHAR(79)`.** `detect/sqli` scores it 5 by its own scorer and never
  runs: `Literals()` omits `char`/`chr`, so the prefilter drops it first. The
  sound literal is the bare word (`char(` is unsound — the detector matches
  `char (39)`), and bare `char` is in "search", "character", "charge". That is
  exactly the trade in [[rejected_literal_hints]] and
  [[prefilter_literal_selectivity]]: **tightening or broadening a literal is a
  measured decision, never a table edit.**
- **Sink operators read the raw sibling value.** `CommandSinkRule` targets
  ARGS_NAMES and `shelli.SinkOperator` reads the value beside the name directly,
  so it sees bytes rather than readings. Confirmed: a fullwidth backtick folds,
  rule 4010 fires on the folded reading (`Interpretation: best_fit`), and 4022 —
  the only rule scoring a backtick around a bare word — never sees it.
  `SQLSinkRule`, `PathSinkRule` and `SSRFParamRule` share the shape, so this is
  one change to how siblings are read, not four.
- **inet_aton spellings.** `IDSSRFMetadata` (Certain, on by default) enumerates
  numeric forms of 169.254.169.254 instead of canonicalising, and its own doc
  claims decimal/hex/octal coverage the list lacks: `0xa9.0xfe.0xa9.0xfe`,
  `0xa9.254.0xa9.254`, `169.16689662` all reach the address and pass.
  `LoopbackSSRFRule` has the same gap (`0177.0.0.1`, `127.1`). One address
  canonicaliser closes both.
- **`LoopbackSSRFRule` is silently inert by default.** It ships `Medium`;
  `defaultConfig` sets `minConf: High`; `selectByConfidence` drops it at compile
  time and `Diagnostics()` returns empty. Enabling it exactly as its godoc shows
  is a no-op with no warning — the §6 "a gate that skips silently reports
  success it did not earn" anti-pattern, applied to a security rule. Worth
  fixing as a diagnostic even if the confidence stays.
- **CLI option injection.** `-c core.sshCommand=id`, `--checkpoint-action=exec=`,
  `-o ProxyCommand=id`, `-e sh`, `-K /tmp/evil.conf` carry no metacharacter and
  no command in position; nothing scores them. A new detector, not a fix.
- **MongoDB aggregation stages.** `detect/nosqli` enumerates query operators and
  no pipeline stage: `$lookup`, `$graphLookup`, `$unionWith` (cross-collection
  reads) and `$out`/`$merge` (write primitives) are invisible.
- **Dotted deserialization type markers.** `typemarker.go`'s
  `isQualifiedClassName` requires a backslash, so it catches PHP namespaces and
  misses .NET/Jackson dotted names (`System.Windows.Data.ObjectDataProvider`).
- **promptinjection false positives.** "Congratulations! You are now a premium
  member." blocks, because `you are now` after `!` reads as clause-leading.
  Same detector as fix 4, different cause: that was `isImperative` too strict,
  this is a phrase too generic. Fixing it means requiring the reassignment to
  name something model-shaped.

## Clean bill

**XSS/mXSS: zero in-scope bypasses across 90 payloads.** The structural scanner
holds — any executing tag completed by `>` scores 5 alone, `on*=` is caught by
name-shape in position, and schemes are matched through tab/NUL/entity
obfuscation. The only misses were payloads inert on a modern browser (legacy-IE
backtick mutation, XHTML-namespace confusion), which fail the Environment test.

## Method note worth reusing

Give each specialist the **five scope tests** and require it to classify every
bypass against them. The XSS and canonicalization agents both self-rejected
findings that were real misses but out of scope, which is what made the reports
worth reading. Validate the harness recipe yourself first — `gwaf.New()` already
loads the core ruleset, and passing `core.Default()` again is a duplicate-ID
compile error that would have burned all six agents.

## Pre-existing, unrelated, still open

`make check` fails at `vuln` on the clean tree too: three Go **stdlib** CVEs
(GO-2026-6090 crypto/tls, GO-2026-6089 net/http, GO-2026-5972 encoding/asn1)
fixed in go1.26.6, while go.mod pins 1.26.5 across every module and CLAUDE.md
documents that toolchain. The go1.26.6 toolchain is already in the module cache.
Bumping it is a project-wide decision, not a red-team fix.

See [[decisions]] and [[measured_results]].
