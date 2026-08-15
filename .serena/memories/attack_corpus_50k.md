# The 50k real-attack corpus, and the pattern it kept finding

Built 2026-08-16. Harness: `test/attackgen/` (generate.py + runner_test.go). The
generated .jsonl are gitignored; the generator and runner are the artifact.

```
python3 test/attackgen/generate.py --n 50000 \
    --out test/attackgen/attacks.jsonl --benign test/attackgen/benign.jsonl \
    --extra /tmp/seeds_serverside.json /tmp/seeds_web.json
A=$PWD/test/attackgen ATTACK_CORPUS=$A/attacks.jsonl BENIGN_CORPUS=$A/benign.jsonl \
    MISS_OUT=$A/misses.jsonl go test -run 'TestAttackCorpus|TestBenignNoFalse' -v ./test/attackgen/
```

## What it is

50,000 attacks from three real sources -- nuclei-templates (CVE exploit
requests), the OWASP CRS regression suite, and ~1560 curated + Mythos-generated
canonical payloads -- expanded across placements (arg/json/form/xml/multipart/
header/path) and encodings (raw/url/double-url/case/base64/comment). Every case
is a real payload in a different position, never a mutated one. A `rid` parameter
keeps repeats distinct without touching the payload.

Detection on the real sources: **nuclei 94.6%, CRS 98.8%.** On the full
adversarial expansion: **82.18%, at 0 false positives** over the benign guard.

## Building it honestly was half the work

A harness that manufactures fake misses teaches nothing. Three generator flaws
had to go before any number meant anything, and each is a lesson:

1. A uniqueness pad appended bytes and turned "whoami" into "whoamix" -- a
   benign string the WAF is right to pass. **Never mutate the payload to make a
   case unique; add a benign sibling parameter.**
2. Structure-blind placement buried NoSQL operators as JSON *values* where the
   detector, which reads keys, correctly saw nothing (0% -> 91% with no gwaf
   change). **Deliver a payload the way it actually arrives** -- key-position for
   NoSQL, whole document for XXE/XSLT, JSON array for an aggregation pipeline.
3. Unencoded reserved characters split a benign LDAP filter "(&(uid=…))" into
   query fragments and read it as an attack. **Percent-encode &, =, +, # inside
   a value in query/form/path position**, as a real client does.

Separate the harness artifact from the finding *before* touching gwaf.

## The pattern the corpus kept finding

Four fixes landed this pass, and three were the same shape: **an operator that
already matched the attack, sitting behind a prefilter that never nominated it.**
The detector could see the payload; the automaton dropped the value first.

- CRLF: the operator matches a break before any header name, but Literals() only
  listed set-cookie/location/a-few, so "\r\nTransfer-Encoding:" (smuggling) never
  ran. Added the smuggling/poisoning header set.
- `..;/` traversal: `repeatedTraversal` read "../" and "..%2f" but `traversalSep`
  did not read ";/", so the Tomcat matrix-param bypass (CVE-2018-11784) walked
  through. Added ";/" and "..;" literal.
- The one real false positive: "order=created_at&dir=desc&select=name" blocked,
  because "&dir" read as a command in position -- but "dir=desc" is a shell
  assignment, not a call. A command name glued to "=value" is now the assignment
  it is, except in a declared command sink.

Plus a new rule: **XSLT remote include/import** (xsl:include href=http://) --
SSRF-to-RCE, scoped to the remote scheme so relative includes stay invisible.

**When a category scores low, read the misses before writing a detector. The gap
is usually a literal, not a signal.**

## What is deliberately still open, with the reason

The remaining misses are dominated by things that are not clean 0-FP fixes:

- **Out of scope by gwaf's own line.** CRS "cve" misses are almost entirely
  session tokens in URLs (cftoken, aspsessionid, koa:sess = CRS family 943 --
  session-management policy the embedder owns). Mass assignment and SAML
  assertion wrapping are authorization. nuclei webshell-*path* probes are
  blocklist reputation, not content.
- **FP-risky.** Command injection in an arbitrary URL *path* segment: adding
  TargetRequestURI to the shell rule fires on "?a&sort" (valueless param in
  command position), so the path is deliberately not shelli-inspected.
- **Needs a parser gwaf does not have.** YAML bodies (!!python/object,
  !ruby/object). Python pickle and Ruby Marshal binary streams.
- **Signature-list-that-goes-stale.** Java ysoserial gadget class *names*
  (ConvertedClosure, BeanComparator). The detector is structural
  (getRuntime()/ProcessBuilder/ScriptEngineManager) by design; naming gadgets is
  "the version of ysoserial that existed when the rule was written".
- **Soundness/selectivity bind.** PHP serialized object with *zero* members
  ("O:N:\"Ns\\Class\":0:{}") -- the operator matches the header, but no fixed
  literal covers a variable-length header without a broad FP-prone string, and a
  real POP chain carries members and is caught. Same family as [[rejected_literal_hints]].

## A meta-note worth acting on later

Several rules have operators that match strictly more than Literals() nominates
(CRLF headers before this fix, phpSerializedObject's 0-member object). That is an
*unsound* prefilter -- the rule silently does not fire on the uncovered inputs --
and FuzzLiteralsAreExhaustive did not catch it, which means the fuzzer does not
generate those shapes. Worth a pass: audit each Operator's match set against its
Literals(), or strengthen the fuzz to target the gap.

See [[coraza_comparison]], [[redteam_round6_blueteam]], [[prefilter_literal_selectivity]].
