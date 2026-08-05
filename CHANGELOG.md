# Changelog

Pre-v1.0, breaking changes are allowed and every one is recorded here
(CLAUDE.md §4). After v1.0 the root package and `types/` are frozen under
semver, and the four extension interfaces are frozen hard.

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
