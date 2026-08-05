# Replacing Coraza with gwaf in gateon

Migration plan for `github.com/gsoultan/gateon` (Go 1.26.5, Coraza v3.7.0 + coraza-coreruleset).

**Read this first:** gwaf does not exist yet. gateon has a working, shipped WAF. This plan is
sequenced so gateon gets value in week 1 and never blocks on gwaf's timeline.

---

## 1. What the coupling actually looks like

Better than expected.

| Fact | Implication |
|---|---|
| **Exactly one file imports Coraza** — `internal/middleware/waf.go` (2,052 LOC) | Blast radius is one file |
| `wafWrapper` / `txWrapper` already wrap Coraza | **The seam already exists**; it just isn't an interface yet |
| gateon's transaction lifecycle maps ~1:1 to gwaf's Profile B API | Minimal call-site churn |
| ~21 generated `SecRule`/`SecAction` directives carry config | The real migration work (§4) |
| `waf.Rule.Directive` in the DB is a **SecLang string** | User data. Must migrate losslessly (§5) |
| `GetCollection(variables.TX)` read via runtime type assertion | Fragile Coraza-internals reach-through; gwaf replaces it with a real API |

### The Coraza API surface to reimplement

```
coraza.NewWAFConfig / NewWAF / WAF.NewTransaction / NewTransactionWithID
types.Transaction:
  ProcessConnection, ProcessURI, AddRequestHeader, AddGetRequestArgument,
  ProcessRequestHeaders, ReadRequestBodyFrom, ProcessRequestBody,
  AddResponseHeader, ProcessResponseHeaders, WriteResponseBody, ProcessResponseBody,
  ProcessLogging, Close, IsInterrupted, Interruption, MatchedRules
types.Interruption:  Action, RuleID, Status, Data
variables.TX + collection.Keyed  →  anomaly_score / inbound_anomaly_score
```

That's the whole contract. Twenty-odd methods.

---

## 2. What gateon already built that gwaf planned to

This changes the relationship. gateon is not a naive Coraza consumer — it has independently built
most of gwaf's surrounding architecture:

| gateon has today | gwaf design equivalent |
|---|---|
| `scanner.NewScanner([...literals])` fast-path before Coraza | **L0 prefilter** (CONCEPT.md) — gateon hardcodes the literal list; gwaf compiles it from the ruleset |
| `wasilibs/go-aho-corasick` dependency | Same algorithm, already vendored |
| Shannon entropy checks, body entropy | Signal gwaf doesn't have |
| JA3/JA4/JA4H fingerprinting + consistency validation | L4 behavioral (Phase 6) |
| `reputation.IPReputationStore` | L4 behavioral |
| `vektah/gqlparser/v2` + `graphql_firewall.go` | `schema/graphql` (Phase 3) |
| `kaptinlin/jsonschema` | `schema/openapi` (Phase 3) |
| `tetratelabs/wazero` | Sandboxed operators (Phase 6) |
| Tiered configs, fingerprint-keyed instance cache | Policies (RULES.md §8) |
| eBPF/XDP rate limiting | Below the WAF layer entirely |

**Two consequences.** First, gateon is the design validation — the layered model isn't theoretical,
it's what gateon converged on independently. Second, several gwaf phases have a donor
implementation, which pulls real work off the critical path.

---

## 3. The boundary: the stateless/stateful line

The most important decision in this migration, and there is a single principle that decides every
case:

> **gwaf analyzes one request in isolation, with no memory.**
> **gateon owns everything requiring state, identity, time, or infrastructure.**

"Is *this* request an attack?" is gwaf. "Who is this client, what have they done before, and what
should we do about it?" is gateon. Every assignment below follows from that one line.

### Moves to gwaf

| gateon today | Notes |
|---|---|
| Coraza engine (`waf.go`) | The whole point |
| `security/scanner` (46 LOC Aho-Corasick) | **Superseded, not ported.** gateon's literal list is hardcoded; gwaf compiles the automaton from the ruleset (CONCEPT.md §1) |
| `security/entropy` (105 LOC) | Per-request content analysis → a gwaf `Detector` |
| `middleware/schema_validation.go` (91 LOC, `kaptinlin/jsonschema`) | Folds into `schema/`, and becomes a *plan specializer* rather than a separate pass (CONCEPT.md §6) |
| `middleware/openapi.go` (49 LOC) | **This is a stub** — the file literally says *"In a full implementation, this would use a library like kin-openapi"* and *"Simplified validation logic for demonstration."* gwaf fills a real gap here; it replaces nothing. |
| `middleware/graphql_firewall.go` (282 LOC) | → `schema/graphql`. Depth/complexity/introspection are per-request. |
| SecLang parsing, body parsing, canonicalization | Core engine |

### Stays in gateon — cross-request state

These are disqualified from gwaf by the principle: they all require memory across requests.

| Component | Why it can't be gwaf |
|---|---|
| `security/reputation` (548 LOC) | IP history over time → feed gwaf as a `Resolver` |
| `security/siem`, `security/correlation` (1,239 LOC) | Correlates events *across* requests |
| `internal/ai` (RL, predictor), `telemetry/anomaly` | Learns from traffic history |
| `security/mitigation` (245 LOC) | Response actions — gwaf decides, this acts |
| `middleware/bot_management.go`, `turnstile.go`, `pow.go` | Challenge/response is multi-request and UX-bearing |
| Rate limiting, connlimit, circuit breaker, retry | Counters over time |
| Tiering, licensing, quotas | Business state |
| WAF rule DB store, REST API, UI | Persistence + presentation |

### Stays in gateon — infrastructure and platform

| Component | Why |
|---|---|
| **All eBPF/XDP/AF_XDP, `phantom`** | See §3.1 — this one deserves its own answer |
| TLS fingerprinting (JA3/JA4/JA4H) | Captured at the TLS handshake, before HTTP exists → `Resolver` input to gwaf |
| ClamAV, `security/fim`, `tpm`, `pqc` | External daemons, filesystem, hardware |
| `honeytokens`, `deception.go`, `honeypot.go` | Deployment strategy, not request analysis |
| Routing, proxying, load balancing, HTTP/3 | Transport |

### The judgment calls

Three don't resolve cleanly, and I'd decide them this way:

**`security/yara` (504 LOC, pure-Go engine) — keep in gateon, expose as a gwaf `Detector`.**
Scanning a request body *is* per-request content analysis, so it qualifies on principle. But YARA is
malware-shaped and pairs with ClamAV and `file_security.go` in gateon. This is precisely what the
`Detector` extension interface exists for (RULES.md §4): gateon implements it, registers it, and
gwaf runs it in the L1 tier. Neither codebase absorbs the other.

**`middleware/file_security.go` (544 LOC) — gateon.** Needs ClamAV, `h2non/filetype`, and upload
policy. Content-type sniffing could be a gwaf `Transform` later; not now.

**`security_advanced.go` (407 LOC) — split.** Audit it: per-request checks go to gwaf rules,
anything holding counters stays.

### The consequence I didn't expect: cut gwaf Phase 6

gwaf's planned Phase 6 "behavioral layer" was rate limiting, JA4 fingerprinting, bot scoring, and
reputation feeds. **Every one of those is cross-request state, and gateon already has all four
implemented.** By the principle above they don't belong in gwaf at all.

Phase 6 should shrink to just the **AI/LLM endpoint protections** (prompt injection, model
extraction) — those *are* single-request content analysis. Everything else in that phase is deleted,
not deferred. That's ~8 weeks of duplicated work avoided, and it's a direct result of studying
gateon rather than designing in the abstract.

---

## 3.1 eBPF: stays in gateon, unambiguously

Five independent reasons, any one of which is disqualifying:

1. **Layer mismatch.** XDP runs on raw packets *before* TCP reassembly and TLS termination. There is
   no HTTP request at XDP — no headers, no body, no URI. gwaf's entire input model is parsed HTTP
   semantics. They don't meet.
2. **Platform lock-in.** eBPF is Linux-only — `manager_linux.go` is real, `manager_other.go` is a
   27-line stub. gwaf's positioning is zero-CGO, static binary, runs in Lambda/Cloud Run/WASI/macOS.
   Requiring Linux + `CAP_BPF` + root in the core kills that outright.
3. **Dependencies.** `cilium/ebpf`, `asavie/xdp`, `godzie44/go-uring`. gwaf's core module targets
   zero third-party dependencies (CLAUDE.md §4).
4. **Privilege and lifecycle.** Attaching XDP to a NIC is privileged, process-global, and a
   singleton. A library that N applications embed in one binary cannot own a network interface.
5. **It's enforcement, not detection.** eBPF *acts on* decisions made elsewhere. gwaf decides.

### But there's a missing feedback loop worth building

`internal/middleware/waf.go:1510` currently reads:

```go
// _ = t.cfg.EbpfManager.ShunIP(clientIP)
```

**Commented out.** So today the WAF never feeds eBPF — every `ShunIP` caller is in `alerting`,
`telemetry`, `mitigation`, or `diagnostics_api`, none of which see WAF verdicts directly.

That loop is worth closing, and the right shape keeps the boundary intact:

```
gwaf Decision  ──►  gateon mitigation policy  ──►  ebpf.ShunIP / BlocklistCuckoo
   (stateless)          (stateful: N strikes,        (enforcement)
                         TTL, tier, allowlist)
```

gwaf emits a decision with rule ID, confidence, and severity. **gateon** decides that 5 critical
hits in 60s from one IP earns an XDP shun. gwaf must never call eBPF — it doesn't know about the
allowlist, the tier, or the previous four requests.

### What I found in the cuckoo blocklist (you asked)

`internal/ebpf/manager.go:385` → map `cuckoo_filter`, checked at XDP `xdp_rate_limit.c:292`, right
after the management whitelist and before TCP conntrack. Falls back to `ShunIP` when the map isn't
loaded.

Four observations, in order of how much they'd bother me:

1. **It is not a cuckoo filter.** The C is `BPF_MAP_TYPE_HASH`, `max_entries 1000000`, key `__u32`,
   value `__u32` — a plain exact-match hash map. A cuckoo filter is a *probabilistic* set: stored
   fingerprints, two candidate buckets, relocation on insert, and a false-positive rate.
   The behavior is arguably **better** than the name promises — at XDP a false positive means
   silently dropping an innocent client's packets, which is exactly the failure you don't want — but
   the name will mislead the next person who reads it, and it implies a space/accuracy tradeoff that
   isn't happening. Rename to `blocklist_ips_v4`, or implement the real thing deliberately.
2. **IPv4-only.** The key is `__u32`. No IPv6 path exists — v6 clients bypass this blocklist
   entirely. That's a real coverage gap, not a naming quibble.
3. **A metrics bug.** `internal/api/diagnostics_api.go:443`:
   ```go
   titanStats.CuckooFilterEntries = int32(stats.ShunnedIPsCount) // Cuckoo used for shunning
   ```
   `ShunnedIPsCount` comes from the `shunned_ips` map. `cuckoo_filter` is a *different* map. The
   dashboard reports one map's population as the other's — so a large cuckoo blocklist shows as
   whatever `shunned_ips` happens to hold.
4. **1M entries × 8 bytes ≈ 8 MB** locked kernel memory when full. Fine, but worth a documented
   eviction/TTL policy — nothing currently removes entries except an explicit `UnshunIP`, and
   `BlocklistCuckoo` has no `Unblocklist` counterpart at all.

None of this changes the migration — it's all gateon-side, and all of it stays gateon-side.

---

## 4. Migration phases

### Phase A — Extract the seam (week 1–2, do this now)

**Independent of gwaf. Do it even if gwaf never ships.**

Turn `wafWrapper`/`txWrapper` into a real interface in a new `internal/security/wafengine`:

```go
package wafengine

type Engine interface {
	NewTransaction(id string) Transaction
	Close() error
}

type Transaction interface {
	ProcessConnection(clientIP string, clientPort int, serverIP string, serverPort int)
	ProcessURI(uri, method, proto string)
	AddRequestHeader(k, v string)
	AddGetRequestArgument(k, v string)
	ProcessRequestHeaders() *Interruption
	ReadRequestBodyFrom(r io.Reader) (*Interruption, int, error)
	ProcessRequestBody() (*Interruption, error)

	AddResponseHeader(k, v string)
	ProcessResponseHeaders(status int, proto string) *Interruption
	WriteResponseBody(b []byte) (*Interruption, int, error)
	ProcessResponseBody() (*Interruption, error)

	ProcessLogging()
	Close() error

	IsInterrupted() bool
	Interruption() *Interruption
	MatchedRules() []MatchedRule
	AnomalyScore() Score          // replaces the GetCollection type assertion
}

type Interruption struct {
	Action string
	RuleID int
	Status int
	Data   string
}

type Score struct{ Inbound, Outbound, Total int }
```

Then `wafengine/coraza` implements it with today's code. Nothing else changes.

Wins you bank immediately, independent of gwaf:

- **Kills the `GetCollection(variables.TX)` type assertion.** That reaches into Coraza internals
  through a runtime interface check and silently returns zero if Coraza's shape changes — a real
  bug today, since your anomaly-score audit logging would go quiet without failing.
- Makes the WAF mockable in `waf_*_test.go` (there are 9 such test files, all currently needing a
  real Coraza instance).
- Lets you A/B any engine later, including a future one that isn't gwaf.

Estimated: ~2 days of mechanical work on one file.

### Phase B — gwaf implements the seam (gated on gwaf Phase 1–2)

`wafengine/gwaf` implements the same interface. gateon changes one constructor call.

gwaf's Profile B API (INTEGRATION.md) was designed against this shape, so the adapter is thin —
mostly renaming `Interruption` to `Decision`.

**gwaf requirement this creates:** the SecLang adapter cannot be Phase 5 for gateon's purposes.
gateon's DB stores SecLang in `waf.Rule.Directive`, and those are user-authored rules. Reprioritize:
gateon needs the SecLang **parser** by gwaf Phase 2, even if the CRS **conformance suite** stays in
Phase 5.

### Phase C — Shadow mode (4–8 weeks of production traffic)

**Non-negotiable. You do not swap a security control and hope.**

Run both engines. Coraza decides; gwaf observes.

```go
type shadowEngine struct {
	primary  wafengine.Engine   // coraza — authoritative
	shadow   wafengine.Engine   // gwaf — observe only
	onDiff   func(Divergence)
}
```

Emit a Prometheus metric per divergence class:

| Divergence | Severity |
|---|---|
| Coraza blocks, gwaf allows | **Critical** — coverage gap |
| Coraza allows, gwaf blocks | **High** — false positive |
| Both block, different rule | Info — expected during CRS→native mapping |
| Latency delta | Track p50/p99 both engines |

Cut over when: zero critical divergences for 2 weeks on production traffic, FP rate ≤ Coraza's, and
p99 improved. Anything less and you're guessing.

Cost: ~2× WAF CPU during shadow. Gate it behind a tier or a sampled percentage of routes.

### Phase D — Config migration (parallel with C)

The ~21 generated SecLang directives become typed gwaf config. This is the real work.

| gateon does today (generated SecLang) | gwaf equivalent |
|---|---|
| `setvar:tx.paranoia_level=%d` | `crs.ParanoiaLevel(n)` preset → confidence policy (RULES.md §8) |
| `setvar:tx.inbound_anomaly_score_threshold=%d` | `gwaf.Policy{Threshold: n}` |
| `SecRule TX:ANOMALY_SCORE "@ge ..." deny` (99491/99492) | Built into the policy engine — delete |
| gRPC compat: remove 920180/920350/920300, extend content types (99007–99010) | `gwaf.Except(920180).On(gwaf.ContentTypePrefix("application/grpc"))` — typed, reviewable |
| `setvar:tx.allowed_methods=...` | `gwaf.WithAllowedMethods(...)` |
| `setvar:tx.allowed_admin_ips=%s` (99005) | Policy `Match` predicate |
| `initcol:ip=%{REMOTE_ADDR}` DOS counters (99002) | gateon's own rate limiter / eBPF — **drop from WAF entirely** |
| `X-Gateon-Ip-Reputation-Block` header round-trip (99201) | `Resolver` — pass reputation in-process, stop laundering it through a header |

Two of those are genuine bug fixes, not just ports:

- **The reputation header round-trip.** gateon currently writes its own reputation verdict into a
  request header so a SecLang rule can read it back. If that header ever survives from a client, it's
  a score-injection vector. A `Resolver` passes it in-process where a client can't touch it.
- **`GRPCMode` derivation.** Your comment at `waf.go:95` correctly notes this must come from the
  trusted route type, never `Content-Type`, because one shared WAF instance serves every route. With
  gwaf, per-route policies make that structural rather than a comment — a gRPC policy compiles to a
  different plan, so there's nothing to spoof.

### Phase E — Rule data migration

`waf.Rule.Directive` holds user-authored SecLang. Options, in preference order:

1. **Keep it.** gwaf's SecLang frontend compiles to the same IR (RULES.md §2). Existing rows keep
   working, unchanged. Default path.
2. **Offer conversion.** `gwaf convert --from seclang` emits typed YAML. Store both; let users opt in
   per rule. Add a `format` column (`seclang` | `gwaf`).
3. **Never force-migrate.** These are customer rules in a database. A lossy auto-conversion of a
   security control is the worst possible outcome.

`Rule.ParanoiaLevel int` maps cleanly onto gwaf `Confidence` (PL1→High … PL4→Heuristic), so the API
and UI keep working with a translation in the adapter.

### Phase F — Delete Coraza

Drop `corazawaf/coraza/v3` and `coraza-coreruleset` from `go.mod`. Keep `wafengine` — the interface
was the point, and it's what lets you do this again.

---

## 5. Sequencing against gwaf's roadmap

| gateon phase | Needs from gwaf | gwaf phase |
|---|---|---|
| A — extract seam | nothing | — (**start now**) |
| B — gwaf adapter | core engine + SecLang parser | 1–2 (SecLang pulled forward) |
| C — shadow | `Explain()` for divergence analysis | 4 |
| D — config migration | policies, exceptions, resolvers | 1–3 |
| E — rule data | SecLang frontend + `gwaf convert` | 2, 5 |
| F — delete Coraza | CRS conformance passing | 5 |

Realistically **9–14 months** to Phase F. Phase A pays for itself in week two.

---

## 6. Risks

| Risk | Mitigation |
|---|---|
| **gwaf slips; gateon waits** | Phase A is engine-agnostic and independently valuable. gateon never blocks. |
| Coverage regression vs. CRS | Shadow mode with critical-divergence gate. No cutover on judgment. |
| Customer SecLang rules break | Never force-migrate. SecLang stays a supported frontend indefinitely. |
| Shadow doubles WAF CPU | Sample routes or gate by tier; it's temporary. |
| gwaf becomes gateon-shaped | Boundary in §3 is the guard. Reputation/JA4/ClamAV/tiering stay in gateon — if gwaf starts growing them, it's becoming a gateway, not a library. |
| Two codebases, one maintainer | gwaf's Phase 6 behavioral layer overlaps gateon's existing signals. **Decide once**: donate them to gwaf, or keep them in gateon and cut gwaf Phase 6. Don't build twice. |

---

## 7. What I'd do Monday

1. **Extract `wafengine`** in gateon. Two days, kills a live bug, unblocks everything.
2. **Add divergence metrics scaffolding** while you're in there — you'll need it for shadow mode and
   it costs nothing now.
3. **Reprioritize gwaf's SecLang parser** from Phase 5 into Phase 2. gateon's DB is the forcing
   function, and it was the wrong call to leave it late once a real adopter exists.
4. **Decide the Phase 6 overlap** (reputation, JA4, bot management) before either project builds it
   again. That's the one item on this page that gets more expensive the longer it waits.
