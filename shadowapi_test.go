// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package gwaf_test

import (
	"testing"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/schema"
)

// shadowAPI is the inventory an embedder keeps. gwaf deliberately does not keep
// one — aggregating is memory, and memory belongs to the embedder — so this
// three-line map is the whole "missing" half of the feature, which is the point.
type shadowAPI map[string]int

func newShadowSchema(t *testing.T) *schema.Schema {
	t.Helper()
	api, err := schema.New(
		schema.Operation{Method: "GET", Path: "/api/v1/orders", NoBody: true},
		schema.Operation{Method: "POST", Path: "/api/v1/orders"},
	)
	if err != nil {
		t.Fatalf("schema.New: %v", err)
	}
	return api
}

// TestUndeclaredRouteFindsShadowEndpoints is the discovery half: an open schema
// still reports routes nobody declared, which is what turns "we think we have
// twelve endpoints" into a list of the ones actually receiving traffic.
func TestUndeclaredRouteFindsShadowEndpoints(t *testing.T) {
	waf, err := gwaf.New(gwaf.WithSchema(newShadowSchema(t)))
	if err != nil {
		t.Fatalf("gwaf.New: %v", err)
	}

	inventory := shadowAPI{}
	requests := []struct {
		method, path string
		declared     bool
	}{
		{"GET", "/api/v1/orders", true},
		{"POST", "/api/v1/orders", true},
		{"GET", "/api/v1/orders/legacy-export", false},
		{"GET", "/internal/debug/config", false},
		{"POST", "/api/v0/orders", false}, // an old version still taking traffic
		{"GET", "/api/v1/orders/legacy-export", false},
	}

	for _, r := range requests {
		tx := waf.NewTransaction()
		tx.SetRequestLine(r.method, r.path, "HTTP/1.1")
		got := tx.UndeclaredRoute()
		if got == r.declared {
			t.Errorf("%s %s: UndeclaredRoute() = %v, want %v", r.method, r.path, got, !r.declared)
		}
		if got {
			inventory[r.method+" "+r.path]++
		}
		tx.Close()
	}

	// The inventory is the embedder's, and it is the deliverable: four
	// undeclared *requests* collapsing to three distinct endpoints, because
	// legacy-export was seen twice. Counting distinct endpoints rather than hits
	// is the whole reason the embedder keeps the map instead of gwaf.
	if len(inventory) != 3 {
		t.Errorf("inventory has %d distinct shadow endpoints, want 3: %v", len(inventory), inventory)
	}
	if n := inventory["GET /api/v1/orders/legacy-export"]; n != 2 {
		t.Errorf("repeat observation counted %d times, want 2", n)
	}
}

// TestUndeclaredRouteIsSilentWithoutSchema guards against the finding becoming
// noise. With no schema every route is undeclared, so reporting them all would
// be a firehose rather than a discovery.
func TestUndeclaredRouteIsSilentWithoutSchema(t *testing.T) {
	waf, err := gwaf.New()
	if err != nil {
		t.Fatalf("gwaf.New: %v", err)
	}
	tx := waf.NewTransaction()
	defer tx.Close()
	tx.SetRequestLine("GET", "/anything/at/all", "HTTP/1.1")
	if tx.UndeclaredRoute() {
		t.Error("UndeclaredRoute() is true with no schema configured; it should report nothing")
	}
}

// TestDiscoveryStillReportsUnderAClosedSchema is the transition that matters. An
// operator runs discovery with an open schema, completes the inventory, then
// closes it — and the signal must survive that switch, or the moment enforcement
// starts is the moment observability stops.
func TestDiscoveryStillReportsUnderAClosedSchema(t *testing.T) {
	api := newShadowSchema(t)
	api.Closed()

	waf, err := gwaf.New(gwaf.WithSchema(api))
	if err != nil {
		t.Fatalf("gwaf.New: %v", err)
	}

	tx := waf.NewTransaction()
	defer tx.Close()
	tx.SetRequestLine("GET", "/internal/debug/config", "HTTP/1.1")

	if !tx.UndeclaredRoute() {
		t.Error("a closed schema stopped reporting the undeclared route")
	}
	// And it is enforced, not merely observed.
	if d := tx.ProcessRequestHeaders(); !d.Blocked() {
		t.Error("a closed schema did not block the undeclared route")
	}
}
