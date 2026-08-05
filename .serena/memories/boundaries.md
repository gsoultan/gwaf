# Boundaries

## Three artifact tiers (CLAUDE.md §1)
| Tier | Rule |
|---|---|
| **Library** | 100% of runtime logic. Anything in the request path lives here or does not exist. |
| **Toolchain** (`cmd/gwaf`) | Compile-time only. Never in the request path. No detection logic. |
| **Reference integration** (`proxy/`) | Pure glue, ~500 LOC cap, zero detection or policy logic. |

A compiler is a **library plus a driver** — `go build` over `go/*`. A CLI is not
application drift.

**Tripwire:** if `proxy/` grows a config format, plugin system, metrics
endpoint, or a line of detection logic, **tier 1 is missing an API**. Fix the
library.

## No UI, ever — and the binding corollary
No dashboard, no admin server, no config file the library discovers.

**But every datum a UI would need must be reachable as a library API.**
"No UI" is not a licence to withhold data. If a consumer building a control
plane cannot get something programmatically, that is a tier-1 API gap.

## gwaf vs gateon
See [[gateon_adoption]]. gwaf decides *whether a request is an attack*. gateon
keeps transport, reputation, JA4, eBPF, ClamAV, bot management, tiering,
storage, UI. Cross-request state is never gwaf's.

## Embedder always owns
FailMode, block response, log destination, detection-vs-blocking, when to
reload, tenant→policy mapping. Deployment policy, not security logic.
Everything else has a safe default — which is what makes the zero-arg
constructor honest.
