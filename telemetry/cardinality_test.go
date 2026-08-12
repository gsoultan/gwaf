// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package telemetry_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/telemetry"
)

// TestCardinalityIsBoundedByTheRulesetNotTheTraffic enforces the claim the
// package documentation makes: that no label a client can influence ever
// becomes a map key.
//
// The package doc says metric cardinality is bounded and refuses per-route
// labels for exactly this reason. That was a comment. This is the harness — a
// future contributor adding ByPath, ByParameter, or ByUserAgent to make a
// dashboard nicer discovers here that they have handed a client the ability to
// grow the process's memory by varying a string, which is how a metrics
// endpoint becomes the outage it was installed to prevent.
//
// The bound is structural: ByRule is keyed by rule ID, and the compiled ruleset
// is finite and fixed at construction. BySeverity is keyed by a typed constant.
// Neither can be driven by a request.
func TestCardinalityIsBoundedByTheRulesetNotTheTraffic(t *testing.T) {
	w, err := gwaf.New()
	if err != nil {
		t.Fatal(err)
	}
	rules := len(w.Ruleset().All())

	var m telemetry.Metrics

	// Every request is a distinct shape: distinct path, distinct parameter name,
	// distinct value, distinct attack class. If any of those reached a label,
	// cardinality would track this loop counter.
	const requests = 5000
	classes := []string{
		"1' OR '1'='1", "<script>alert(1)</script>", "../../../etc/passwd",
		"; cat /etc/passwd", "${jndi:ldap://x/a}", "{{7*7}}", "|id",
	}
	for i := range requests {
		tx := w.NewTransaction()
		tx.SetRequestLine("GET", fmt.Sprintf("/route-%d/sub-%d", i, i%97), "HTTP/1.1")
		tx.SetRemoteAddr(fmt.Sprintf("198.51.100.%d", i%256))
		tx.AddArgument(fmt.Sprintf("param_%d", i), classes[i%len(classes)]+fmt.Sprint(i))
		tx.AddRequestHeader("User-Agent", fmt.Sprintf("scanner/%d", i))
		d := tx.ProcessRequestHeaders()
		m.Observe(d, time.Duration(i%1000)*time.Microsecond)
		tx.Close()
	}

	s := m.Snapshot()
	if s.Requests != requests {
		t.Fatalf("observed %d requests, recorded %d", requests, s.Requests)
	}
	if len(s.ByRule) > rules {
		t.Errorf("ByRule has %d keys for a ruleset of %d rules: a key is coming "+
			"from the request rather than the ruleset", len(s.ByRule), rules)
	}
	// The real assertion. 5000 distinct shapes; if cardinality tracked traffic
	// this would be in the thousands.
	if len(s.ByRule) > requests/10 {
		t.Errorf("ByRule has %d keys after %d distinct requests -- cardinality is "+
			"tracking traffic", len(s.ByRule), requests)
	}
	// Severity is a closed enum: certain/high/medium/low/heuristic and below.
	if len(s.BySeverity) > 8 {
		t.Errorf("BySeverity has %d keys; severity is a typed constant with a "+
			"handful of values, so a key here came from somewhere else",
			len(s.BySeverity))
	}
	if s.Blocked == 0 {
		t.Fatal("no request blocked; the corpus is not exercising the ruleset " +
			"and the cardinality bound above proves nothing")
	}
	t.Logf("%d distinct requests -> %d rule keys, %d severity keys (%d blocked)",
		requests, len(s.ByRule), len(s.BySeverity), s.Blocked)
}
