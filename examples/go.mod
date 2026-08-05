// The examples are their own module because they import the integration
// packages, and a library must never depend on its own integrations. Keeping
// them here would put net/http middleware -- and later every framework adapter
// an example demonstrates -- into the core module's graph.
//
// It also makes the examples honest: they resolve gwaf exactly the way an
// embedder does, so an example that compiles is proof the public API is usable
// from outside.
module github.com/gsoultan/gwaf/examples

go 1.26.5

require (
	github.com/gsoultan/gwaf v0.0.0
	github.com/gsoultan/gwaf/middleware v0.0.0
)

replace (
	github.com/gsoultan/gwaf => ../
	github.com/gsoultan/gwaf/middleware => ../middleware
)
