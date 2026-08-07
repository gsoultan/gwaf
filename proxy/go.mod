// The reference reverse proxy is its own module, and the isolation is the whole
// point of it existing here at all.
//
// It is tier 3 in CLAUDE.md §1: pure glue over the library, capped at ~500 LOC,
// with zero detection or policy logic of its own. Everything it does, it does by
// calling the gwaf library and the net/http middleware -- if it ever needs a
// feature those do not offer, the feature belongs in the library, not here. A
// separate module makes that boundary enforceable: the proxy cannot reach into
// gwaf's internals even by accident, and an embedder importing gwaf never drags
// in httputil or the proxy's flags.
module github.com/gsoultan/gwaf/proxy

go 1.26.5

require (
	github.com/gsoultan/gwaf v0.0.0
	github.com/gsoultan/gwaf/middleware v0.0.0
)

// Released together from one repository, so the proxy always builds against the
// tree it ships with rather than a published version that may not exist yet.
replace github.com/gsoultan/gwaf => ../

replace github.com/gsoultan/gwaf/middleware => ../middleware
