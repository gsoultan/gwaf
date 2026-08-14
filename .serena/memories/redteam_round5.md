# Red-team round 5: the statistics, and what they measure

Run 2026-08-14 by six parallel Claude Fable 5 (Mythos-class) specialists against
the shipped engine. Fixes in `1b1dc07`; the measurement is `TestMythosCorpus`.

## The number, and why the shipped corpus could not produce it

`make corpus` reports 334/334 detection and 0/176 false positives. It is honest
and it is not resistance: every payload in it is one gwaf was already fixed
against, so it measures regression. A corpus that only holds fixed payloads
always reports 100%.

`mythos_corpus_test.go` is the other measurement — adversarial traffic aimed at
the *shipped* engine, kept **whether or not it was ever closed**, so an open
bypass still counts against the rate. Same 85 attack payloads, same 42 benign:

| | detection | false positives |
|---|---|---|
| v0.5.2 (`59636bd`, pre-Mythos) | **21/85 — 24.7%** | 3/42 — 7.14% |
| after rounds 4+5 (`1b1dc07`) | **70/85 — 82.4%** | 3/42 — 7.14% |

Per class, before → after: agentic 0→67%, engine 0→100%, ssti 11→89%,
shell 11→56%, sqli 14→57%, prompt 15→85%, charset 13→88%, ssrf 40→100%,
nosql 50→100%, multipart 67→100%. xss and traversal were 100% both times.

**Recall alone is never a passing metric**, so the FP rate is reported beside it
on every run and did not move. The 3 remaining FPs are the known generic-phrase
prompt-injection cases.

## The performance correction worth remembering

The inet_aton canonicalisation was first written as a **transform chain**. It
worked, and it cost **22% on benign GET** — four times the budget.
`TestTransformChainInventory` states the reason in advance: a chain is
materialised once per value per phase, so a seventh chain is paid for by every
value in the phase for the benefit of two rules. That test earned its keep.

Moved into the **operator** (`ruleset/core/addressop.go`), where Eval runs only
after the prefilter nominates, the same canonicalisation measures at nothing.
The trick that keeps it sound: the encoded spellings share no bytes with the
canonical needle, so the *leads* of every spelling are declared as literals —
and they are **derived from the needles** (a first octet has exactly three
spellings), so the list cannot drift.

**Generalise: put per-rule normalisation in the operator, not in a chain.**

## Still open, with the reason (unchanged from round 4 unless noted)

- **Long UTF-7 runs** — `maxEntityLen=32` is the anti-quadratic bound.
- **`CHAR(39)+CHAR(79)`** — bare `char` is in "search"/"character"; not selective
  enough to declare. See [[rejected_literal_hints]].
- **Sink operators read the sibling value raw** — `shelli.SinkOperator` and the
  other sink rules never see a reading, so a folded fullwidth backtick reaches
  rule 4010 but not 4022.
- **CLI option injection** — `-c core.sshCommand=id`, `--checkpoint-action=exec=`.
  No metacharacter, no command in position. Needs a detector.
- **Multilingual / homoglyph / leetspeak prompt injection** — the phrase table is
  English and byte-matched. Round 5 adds that **whitespace variants inside a
  phrase** (double space, tab, NBSP) also defeat `indexFold`, and lead words
  outside the marker list (`just`, `hey`) still bypass.
- **MCP tool-description poisoning, markdown-image exfil steering, hypothetical/
  prefix-injection jailbreaks** — prose with no structural marker (round 5).
- **YAML bodies** — no parser, so `!!python/object/apply:` carries no grammar.
- **GraphQL batch arrays** — `graphqlTargets` is an arg literally named `query`,
  so `[{"query":…}]` batching evades every GraphQL rule *and* the introspection
  opt-in; also `application/graphql` raw bodies (round 5).
- **`LoopbackSSRFRule` silently inert by default** — ships Medium, `minConf` is
  High, `Diagnostics()` empty.
- **Dotted .NET/Jackson type markers** — `isQualifiedClassName` requires a
  backslash.
- **promptinjection FPs** — "Congratulations! You are now a premium member."

## Method notes

- Give each specialist the **five scope tests** and require classification. The
  XSS and canonicalisation agents self-rejected real misses as out-of-scope,
  which is what made the reports usable.
- **Validate the harness recipe yourself first.** `gwaf.New()` already loads the
  core ruleset; passing `core.Default()` again is a duplicate-ID compile error
  that would have burned all six agents.
- **Agents branch from HEAD-at-launch.** The round-5 fuzzing agent reported the
  round-4 `imperativeMarkers` fix as "fictional — grep = 0" because its worktree
  predated it. Verify agent claims against the current tree, not their report.
- A detector scoring a payload it never receives is the recurring shape: check
  `Literals()` and the prefilter before concluding a detector is blind.

See [[redteam_round4]], [[prefilter_literal_selectivity]], [[measured_results]].
