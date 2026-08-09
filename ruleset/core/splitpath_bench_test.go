package core

import (
	"testing"

	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/types"
)

// BenchmarkSplitPathEval is on the request path: it runs for every argument
// whose value looks like a sensitive directory, once per sibling.
func BenchmarkSplitPathEval(b *testing.B) {
	o := splitPathOp{}
	ctx := rules.EvalContext{
		Target: types.Target{Kind: types.TargetArgs},
		Key:    "path",
		Siblings: rules.Args{
			Names:  [][]byte{[]byte("path"), []byte("a"), []byte("b"), []byte("target")},
			Values: [][]byte{[]byte("/etc/"), []byte("x"), []byte("y"), []byte("passwd")},
		},
	}
	val := []byte("/etc/")
	b.ReportAllocs()
	for b.Loop() {
		o.Eval(&ctx, val)
	}
}

// BenchmarkSplitPathEvalBenign is the case that actually matters for the
// zero-allocation SLO: an ordinary value, which exits before the join buffer is
// ever declared.
func BenchmarkSplitPathEvalBenign(b *testing.B) {
	o := splitPathOp{}
	ctx := rules.EvalContext{
		Target: types.Target{Kind: types.TargetArgs},
		Key:    "path",
		Siblings: rules.Args{
			Names:  [][]byte{[]byte("path"), []byte("page")},
			Values: [][]byte{[]byte("/wp-content/uploads/"), []byte("2")},
		},
	}
	val := []byte("/wp-content/uploads/")
	b.ReportAllocs()
	for b.Loop() {
		o.Eval(&ctx, val)
	}
}

// BenchmarkOffOriginEval and BenchmarkTypeMarkerEval cover the other two
// operators added alongside this one, on the path they actually take: a sink
// parameter carrying a URL, and a type-marker field carrying a class name.
func BenchmarkOffOriginEval(b *testing.B) {
	o := offOriginURL()
	ctx := rules.EvalContext{
		Target: types.Target{Kind: types.TargetArgs}, Key: "redirect_to",
		Origins: []string{"shop.example.com"},
	}
	val := []byte("https://evil.tld/path")
	b.ReportAllocs()
	for b.Loop() {
		o.Eval(&ctx, val)
	}
}

func BenchmarkTypeMarkerEval(b *testing.B) {
	o := typeMarkerOp{}
	ctx := rules.EvalContext{Target: types.Target{Kind: types.TargetArgs}, Key: "payload.__class"}
	val := []byte(`guzzlehttp\psr7\fnstream`)
	b.ReportAllocs()
	for b.Loop() {
		o.Eval(&ctx, val)
	}
}
