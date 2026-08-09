// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package core

import (
	"testing"

	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/types"
)

// TestTypeMarkerRule covers the JSON form of object injection, which every other
// deserialization rule here is blind to by construction: rule 4007 reads PHP's
// serialize() grammar and detect/javaser reads Java's stream header, and a
// gadget chain expressed as JSON has neither. It is well-formed JSON containing
// well-formed strings; only the field name says a string becomes an object.
func TestTypeMarkerRule(t *testing.T) {
	o := typeMarkerOp{}
	fire := func(key, value string) bool {
		ctx := rules.EvalContext{Target: types.Target{Kind: types.TargetArgs}, Key: key}
		_, ok := o.Eval(&ctx, []byte(value))
		return ok
	}

	t.Run("gadget selection fires", func(t *testing.T) {
		for _, c := range []struct{ key, val string }{
			{"__class", `guzzlehttp\psr7\fnstream`},
			{"class", `yii\behaviors\attributebehavior`},
			{"__class", `monolog\handler\syslogudphandler`},
			{"@class", `symfony\component\cache\adapter\tagawareadapter`},
			{"$type", `doctrine\common\cache\filesystemcache`},
			{"javaclass", `laravel\pendingbroadcast`},
		} {
			if !fire(c.key, c.val) {
				t.Errorf("missed %s=%s", c.key, c.val)
			}
		}
	})

	t.Run("ordinary API values pass", func(t *testing.T) {
		// "type" and "class" are words ordinary APIs use, which is why the value
		// has to look like a qualified name and not merely be a string.
		for _, c := range []struct{ key, val string }{
			{"class", "primary"},
			{"class", "btn btn-lg"},
			{"@type", "Person"},
			{"$type", "invoice"},
			{"__class", "highlight"},
			{"@type", "image/png"},  // a media type is not a class name
			{"class", "v1.2.3"},     // a version is dotted
			{"@type", "photo.jpeg"}, // so is a filename
			{"class", ".leading-dot"},
			{"class", "trailing."},
		} {
			if fire(c.key, c.val) {
				t.Errorf("false positive on %s=%s", c.key, c.val)
			}
		}
	})

	t.Run("qualified names outside a type field pass", func(t *testing.T) {
		// The same string is ordinary content anywhere else: a stack trace in a
		// bug report, a package name in a search box.
		for _, key := range []string{"q", "search", "message", "stack", "name"} {
			if fire(key, `guzzlehttp\psr7\fnstream`) {
				t.Errorf(`false positive: %s=guzzlehttp\psr7\fnstream`, key)
			}
		}
	})
}

// TestTypeMarkerMatchesNestedFields is the reason lastKeySegment exists. A POP
// chain is a nested object by construction — {"payload": {"__class": "..."}} —
// and the body parser emits that as the flattened path "payload.__class". The
// first version matched the whole key and therefore caught nothing at all in a
// real corpus, while passing every unit test, because the tests used top-level
// fields and real payloads do not.
func TestTypeMarkerMatchesNestedFields(t *testing.T) {
	o := typeMarkerOp{}
	fire := func(key, value string) bool {
		ctx := rules.EvalContext{Target: types.Target{Kind: types.TargetArgs}, Key: key}
		_, ok := o.Eval(&ctx, []byte(value))
		return ok
	}
	for _, key := range []string{
		"__class",
		"payload.__class",
		"as hack.__class",
		"items[0].__class",
		"a.b.c.@class",
	} {
		if !fire(key, `guzzlehttp\psr7\fnstream`) {
			t.Errorf("missed nested marker %q", key)
		}
	}
	// A field merely ending in the same letters is not the marker.
	for _, key := range []string{"subclass", "myclass", "xclass"} {
		if fire(key, `guzzlehttp\psr7\fnstream`) {
			t.Errorf("false positive on %q", key)
		}
	}
}
