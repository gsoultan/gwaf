# gateon — First Adopter

`~/GolandProjects/gateon` (same author) is gwaf's first adopter. Goal: replace
its embedded **Coraza v3.7.0 + coraza-coreruleset**. Plan:
`gwaf/docs/GATEON-MIGRATION.md`.

## Coupling is small
- **One** file imports Coraza: `internal/middleware/waf.go` (~2050 LOC).
- It already wraps it in `wafWrapper`/`txWrapper` — **the seam exists**, it just
  is not an interface yet.
- ~20 methods of Coraza API total.

## Do first (independent of gwaf)
Extract `internal/security/wafengine` as an interface over today's Coraza code.
~2 days. Kills a live bug: `waf.go:1374` reaches into Coraza internals via a
runtime type assertion to read the anomaly score — if Coraza's shape changes it
silently returns zero and audit logging goes quiet. Also makes 9 `waf_*_test.go`
files mockable.

## Constraints gateon imposes on gwaf
- Its DB (`internal/security/waf`, `Rule.Directive`) stores **user-authored
  SecLang**. This pulled the SecLang *parser* from Phase 5 to Phase 2. Never
  force-migrate customer rules.
- It exposes CRS **paranoia level** in config/API/DB → `WithParanoiaLevel(n)`
  compat preset is required.

## Two real bugs found in gateon during the review
1. **Reputation header round-trip** — gateon writes its verdict into
   `X-Gateon-Ip-Reputation-Block` for SecLang rule 99201 to read back. If that
   header survives from a client it is a score-injection vector. Use a
   `Resolver` (in-process).
2. **`waf.go:1510`** has `ShunIP` **commented out** — the WAF never feeds eBPF.
   Loop should be: gwaf Decision → gateon mitigation policy → ebpf.ShunIP.
   gwaf must never call eBPF; it does not know the allowlist or tier.

## The "cuckoo" blocklist is not a cuckoo filter
`internal/ebpf` `cuckoo_filter` is `BPF_MAP_TYPE_HASH`, 1M entries, `__u32` key.
Exact-match hash map, not probabilistic. Also: **IPv4 only** (v6 bypasses it),
and `diagnostics_api.go:443` reports `shunned_ips` count as cuckoo entries —
different maps. No eviction; no `Unblocklist` counterpart.

## Unresolved, gets more expensive with time
gwaf Phase 6 (reputation, JA4, bot scoring) **overlapped gateon's existing
features** → already cut from gwaf. Confirm before either side rebuilds.
