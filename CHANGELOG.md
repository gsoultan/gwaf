# Changelog

Pre-v1.0, breaking changes are allowed and every one is recorded here
(CLAUDE.md §4). After v1.0 the root package and `types/` are frozen under
semver, and the five extension interfaces are frozen hard.

## Unreleased

### Breaking

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

  `Operator` is one of the five interfaces CLAUDE.md §4 describes as the most
  expensive API surface in the project, "third parties implement them, so
  post-v1.0 they are frozen hard". It was impossible to implement, and no test
  in the tree could see that, because everything in the tree is on the
  permitted side of the import-path rule.

  **Migration:** replace `budget.Fuel` with `types.Fuel` and
  `budget.Cost*` with `types.Cost*`. `budget.Fuel` remains as a type *alias*, so
  in-tree code keeps compiling and the two names denote one type.

  `test/extension` is a new module declaring itself `example.com/gwafvendor`. It
  implements `Operator`, `Transform`, and `Action` from a foreign path, so the
  compiler now enforces what the documentation asserts.

### Added

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
- `seclang` — SecLang/CRS bridge with RE2 literal extraction (separate module).
- `adapters/gin`, `adapters/echo`, `adapters/fiber` (separate modules). chi,
  gorilla/mux, connect-go, and `net/http` need no adapter.
- Response phase: `SetResponseStatus`, `AddResponseHeader`,
  `ProcessResponseHeaders`, `WriteResponseBody`, `ProcessResponseBody`.

### Changed

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
- Evasion corpus reorganised as attack class × evasion technique, with
  `declaredClasses` failing the build when a class gwaf claims to detect has too
  few cases behind the claim.
