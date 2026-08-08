// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package sqli

import "testing"

// TestUnionSelectNeedsASelectList is the regression for a false positive the
// benign corpus found: "the UNION SELECT pattern is a classic injection example"
// was blocked.
//
// SignalUnionSelect is worth 5 and reaches the threshold alone, so any adjacent
// UNION and SELECT fired — which is the keyword matching this detector exists to
// replace. The package doc already promised "the union selected a new
// representative" would not fire; it only held because the words were not
// adjacent. A security blog, a WAF vendor's docs and this repository's own
// CHANGELOG all contain the literal pair.
//
// What separates them is what follows: a real UNION SELECT is followed by a
// select-list, and prose is followed by English.
func TestUnionSelectNeedsASelectList(t *testing.T) {
	d := New()

	t.Run("prose passes", func(t *testing.T) {
		for _, benign := range []string{
			"the UNION SELECT pattern is a classic injection example",
			"UNION SELECT attacks are covered in chapter four",
			"we block union select statements at the edge",
			"union select is the technique most people know",
		} {
			if v := d.Analyze([]byte(benign)); v.Detected() {
				t.Errorf("false positive on %q (score %d, signals %v)", benign, v.Score, v.Signals)
			}
		}
	})

	t.Run("injections still fire", func(t *testing.T) {
		for _, attack := range []string{
			"1 UNION SELECT password FROM users",
			"1' UNION SELECT NULL,NULL--",
			"1 UNION SELECT 1,2,3",
			"1 UNION ALL SELECT username, password FROM admin",
			"1 UNION/**/SELECT/**/1,2",
			"-1 union select * from information_schema.tables",
			"1 UNION SELECT @@version",
			"1 UNION SELECT load_file('/etc/passwd')",
		} {
			if v := d.Analyze([]byte(attack)); !v.Detected() {
				t.Errorf("missed %q (score %d, signals %v)", attack, v.Score, v.Signals)
			}
		}
	})
}
