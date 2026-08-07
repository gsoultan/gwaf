// The conformance suite is its own module because it needs a YAML parser.
//
// go-ftw tests are YAML, and YAML needs a dependency the core module will not
// carry (CLAUDE.md §3, ownership test 5). Keeping the runner here means an
// embedder importing gwaf never inherits a parser they will not run — and the
// suite still exercises the real library, because it imports it like anyone else.
module github.com/gsoultan/gwaf/test/conformance

go 1.26.5

replace github.com/gsoultan/gwaf => ../../

replace github.com/gsoultan/gwaf/seclang => ../../seclang

require (
	github.com/gsoultan/gwaf v0.0.0
	github.com/gsoultan/gwaf/seclang v0.0.0-00010101000000-000000000000
	gopkg.in/yaml.v3 v3.0.1
)
