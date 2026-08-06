// The SecLang bridge is its own module because it is a parser: a lexer, a
// directive grammar and a converter, none of which an embedder writing
// "gwaf.New()" should inherit.
//
// It used to own the regex engine as well. That moved to rules/op/rx in the
// root module, because Go links per package: a package of its own gives the
// same "you only pay if you ask" guarantee without forcing an embedder who
// wants one regex rule to take a SecLang parser with it.
//
// It is a bridge, not the core: it compiles to rules.Rule -- the same IR the Go
// frontend produces -- and adds nothing the typed API cannot express.
module github.com/gsoultan/gwaf/seclang

go 1.26.5

require github.com/gsoultan/gwaf v0.0.0

replace github.com/gsoultan/gwaf => ../
