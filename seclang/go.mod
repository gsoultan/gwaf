// The SecLang bridge is its own module because it links a regex engine and the
// literal extraction that keeps imported regex rules prefilterable. That is
// cost an embedder should not inherit for writing "gwaf.New()".
//
// It is a bridge, not the core: it compiles to rules.Rule -- the same IR the Go
// frontend produces -- and adds nothing the typed API cannot express.
module github.com/gsoultan/gwaf/seclang

go 1.26.5

require github.com/gsoultan/gwaf v0.0.0

replace github.com/gsoultan/gwaf => ../
