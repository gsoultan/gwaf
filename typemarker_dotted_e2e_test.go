// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package gwaf_test

import (
	"testing"

	"github.com/gsoultan/gwaf"
)

// A Python (jsonpickle) or Ruby polymorphic marker names its class as a dotted
// module path -- subprocess.Popen, os.system -- which carries no backslash, so
// the backslash-anchored type-marker rule never saw it and the markers also
// never resolved because the key parser split them on '/'. These are a real
// deserialization-RCE vector and must block at zero config, top-level and
// nested, while ordinary JSON bodies do not.
func TestTypeMarkerDottedBlocks(t *testing.T) {
	w, err := gwaf.New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	json := map[string]string{"Content-Type": "application/json"}

	blocked := []struct{ name, body string }{
		{"py-object-popen", `{"py/object":"subprocess.Popen"}`},
		{"py-object-os-system", `{"py/object":"os.system"}`},
		{"py-object-builtins", `{"py/object":"builtins.exec"}`},
		{"rb-object", `{"rb/object":"Gem::Requirement"}`},
		{"py-object-nested", `{"payload":{"py/object":"subprocess.Popen"}}`},
		{"py-object-array", `{"items":[{"py/object":"os.system"}]}`},
		{"py-object-namespaced", `{"py/object":"guzzlehttp\\psr7\\fnstream"}`},
	}
	for _, c := range blocked {
		t.Run(c.name, func(t *testing.T) {
			d := run(t, w, req{method: "POST", target: "/api", headers: json, body: c.body})
			if !d.Blocked() {
				t.Fatalf("%s: not blocked -- a Python/Ruby deserialization marker reached the backend\nbody=%s", c.name, c.body)
			}
		})
	}
}

// The key carries the verdict for py/object and rb/object, so the companion
// rule must not fire where the key is absent or the value is not a class path,
// and must leave the keys that legitimately carry dotted class names alone.
func TestTypeMarkerDottedNoFalsePositive(t *testing.T) {
	w, err := gwaf.New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	json := map[string]string{"Content-Type": "application/json"}

	clean := []struct{ name, body string }{
		// Ordinary objects with dotted/own values, no pickle marker.
		{"plain-object", `{"type":"invoice","class":"primary"}`},
		{"dotted-version", `{"version":"v1.2.3","build":"4.5.6"}`},
		{"filename", `{"file":"photo.jpeg","thumb":"a.b.png"}`},
		{"hostname", `{"host":"api.example.com"}`},
		{"dotnet-type-field", `{"__type":"System.Data.Services.ExpandedWrapper"}`},
		{"jackson-class-field", `{"@class":"com.example.Order"}`},
		{"json-net-type", `{"$type":"MyApp.Models.User, MyApp"}`},
		// A field whose name merely ends in the marker letters is not the marker.
		{"not-pyobject", `{"happy/object":"subprocess.Popen"}`},
		// The marker key with a non-class value is not a gadget selection.
		{"pyobject-bare-word", `{"py/object":"true"}`},
		{"pyobject-number", `{"py/object":"42"}`},
	}
	for _, c := range clean {
		t.Run(c.name, func(t *testing.T) {
			d := run(t, w, req{method: "POST", target: "/api", headers: json, body: c.body})
			if d.Blocked() {
				t.Fatalf("%s: false positive on benign body\nbody=%s", c.name, c.body)
			}
		})
	}
}
