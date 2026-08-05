// The OpenAPI frontend is its own module because YAML needs a third-party
// parser, and the fifth ownership test in CLAUDE.md §1 is decisive: everything
// in the core module is a dependency an embedder inherits without consent.
//
// Somebody protecting a gRPC service should not acquire a YAML parser because a
// different user wanted OpenAPI.
module github.com/gsoultan/gwaf/schema/openapi

go 1.26.5

require (
	github.com/gsoultan/gwaf v0.0.0
	gopkg.in/yaml.v3 v3.0.1
)

replace github.com/gsoultan/gwaf => ../../
