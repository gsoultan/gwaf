// A deliberately foreign module path.
//
// Go's internal-package rule is keyed on import path: anything under
// github.com/gsoultan/gwaf/... may import internal/, and nothing else may. So a
// public interface with a method returning an internal type compiles for every
// in-tree implementation and is impossible for a vendor -- which is exactly what
// happened to Operator.Cost() until this module was written.
//
// Declaring example.com/gwafvendor puts this code where a vendor stands, so the
// compiler enforces the claim in CLAUDE.md §4 instead of a comment asserting it.
module example.com/gwafvendor

go 1.26.5

require github.com/gsoultan/gwaf v0.0.0

replace github.com/gsoultan/gwaf => ../../
