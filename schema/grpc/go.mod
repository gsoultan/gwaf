// The gRPC schema frontend is its own module because reading a
// FileDescriptorSet needs google.golang.org/protobuf.
//
// The fifth ownership test in CLAUDE.md §1: everything in core is a dependency
// an embedder inherits without consent, and somebody protecting a REST API
// should not acquire a protobuf runtime because a different user speaks gRPC.
module github.com/gsoultan/gwaf/schema/grpc

go 1.26.5

require (
	github.com/gsoultan/gwaf v0.0.0
	google.golang.org/protobuf v1.36.10
)

replace github.com/gsoultan/gwaf => ../../
