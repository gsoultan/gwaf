// The net/http integration is its own module so that adding a framework
// adapter never adds a dependency to somebody's core gwaf import.
//
// Nothing here needs a third-party package today -- net/http is stdlib -- and
// that is precisely why the split has to happen now rather than when it does.
// Once gin, echo, and fiber adapters live alongside this one, a single module
// would put all four in the dependency graph of every embedder who wanted one,
// and the zero-third-party-dependency invariant in CLAUDE.md would already be
// lost. See the fifth ownership test in CLAUDE.md §1.
module github.com/gsoultan/gwaf/middleware

go 1.26.5

require github.com/gsoultan/gwaf v0.0.0

// gwaf and its integrations are released together from one repository, so the
// integration always builds against the tree it ships with rather than against
// a published version that may not exist yet.
replace github.com/gsoultan/gwaf => ../
