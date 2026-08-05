# Boundaries

## The framing: embedder, not gateon
gwaf is for **any** application — API service, Lambda, CLI, gateway. gateon is
one embedder and a case study, **not the design target**. A decision that only
makes sense for a gateway is made in the wrong place.

Watch for drift: the calibration corpus is 100% gateon-derived (a measurement
bias, not just a size limit), and GATEON-MIGRATION.md is a case study that must
not become the roadmap.

## Five ownership tests
gwaf answers one question: *is this request an attack?* — one request, no memory.
If any of these is yes, it belongs to the embedder:

1. **Memory** — state across requests (rate limits, reputation, bot scores)
2. **Ownership** — owns the socket/connection/lifecycle (buffering, streaming, timeouts)
3. **Environment** — privilege, hardware, daemon, network call (eBPF, JA4, antivirus, feeds)
4. **Policy** — decides what to *do* vs what is *true* (block, challenge, redact, ban)
5. **Dependency** — needs a library the embedder did not choose → **separate module, never core**

**gwaf produces findings; the embedder produces outcomes.**

**gwaf never buffers.** Test 2. `WriteResponseBody` takes what it is given; give
it nothing and it says it saw nothing, not that the response was clean. The
middleware offers buffering opt-in — an integration layer may make one
reasonable choice, the core may not.

Test 5 settles SecLang, OpenAPI-YAML, brotli, and framework adapters uniformly:
all separate modules. **Zero deps in core is the invariant** and the one property
no competitor offers.


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
