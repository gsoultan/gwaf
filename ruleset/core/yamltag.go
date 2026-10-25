// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package core

import (
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/rules/op"
)

// yamlUnsafeConstructor reports a YAML tag that names a language object
// constructor.
//
// # Why a tag and not a parser
//
// A YAML deserialization attack is a tag, not a grammar. `yaml.load` in PyYAML,
// `Psych.load` in Ruby and SnakeYAML's default constructor all honour a type
// tag that tells the loader to *instantiate a class* rather than build a plain
// map, and the moment the class is attacker-chosen that is remote code
// execution:
//
//	!!python/object/apply:os.system ["id"]
//	!!python/object/new:subprocess.Popen [["id"]]
//	!!ruby/object:Gem::Installer {}
//
// gwaf has no YAML parser and should not grow one for this: the signal is the
// tag handle itself, which is a fixed, rare literal. `!!python/object` and
// `!!ruby/object` are not something a benign document carries — they are an
// instruction to the loader to call a constructor, and the only reason to send
// one to a server is to pick which constructor. The ordinary YAML type tags a
// real document uses -- `!!str`, `!!int`, `!!map`, `!!timestamp` -- share the
// `!!` handle and nothing else, so matching the constructor prefixes leaves
// them untouched.
//
// # Scope
//
// Python and Ruby object constructors are covered because their handles are
// unambiguous. The Java shape (SnakeYAML's `!!javax.script.ScriptEngineManager`
// chained to a URLClassLoader) is already caught by the gadget-class and
// remote-URL rules; a bare `!!<dotted.class.Name>` Java global tag is left to
// those rather than claimed here, because `!!` followed by a dotted name is the
// one YAML global-tag form an ordinary document can also carry, and an
// allowlist of safe classes is the kind of list that goes stale silently
// (see xmlEntityOrExternalDTD on PUBLIC for the same reasoning).
func yamlUnsafeConstructor() rules.Operator {
	// Constructor handles with no benign reading. Each one tells the loader to
	// instantiate, which a document describing data never needs to do.
	handles := []string{
		"!!python/object", // object, object/apply, object/new all share this prefix
		"!!python/name",
		"!!python/module",
		"!!ruby/object",
		"!!ruby/hash",
		"!!ruby/struct",
		"!!ruby/marshal",
		"!!ruby/array",
	}
	return op.Func("yaml_unsafe_constructor", func(v []byte) bool {
		for _, h := range handles {
			if indexOfFold(v, h) >= 0 {
				return true
			}
		}
		return false
	}).WithLiterals("!!python/", "!!ruby/")
}
