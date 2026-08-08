// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package sqli

import "testing"

// TestMySQLNonBreakingSpaceIsASeparator: MySQL's lexer accepts 0xA0 as
// whitespace, so an injection written with it runs at the origin while reading
// as one long identifier to a tokenizer that only knows ASCII whitespace.
//
// The pentest harness found it: the tab, newline and carriage-return spellings
// of "1 OR 1=1" were all blocked and the 0xA0 spelling reached the backend.
func TestMySQLNonBreakingSpaceIsASeparator(t *testing.T) {
	d := New()
	for _, payload := range []string{
		"1\xa0OR\xa01=1",
		"1\xa0UNION\xa0SELECT\xa0password\xa0FROM\xa0users",
		"admin'\xa0OR\xa0'1'='1",
	} {
		if v := d.Analyze([]byte(payload)); !v.Detected() {
			t.Errorf("missed %q (score %d)", payload, v.Score)
		}
	}
}

// TestNonBreakingSpaceDoesNotBreakProse keeps the separator honest: 0xA0 is a
// real non-breaking space in latin-1 text and in anything pasted out of a word
// processor, so treating it as whitespace must not turn ordinary writing into a
// SQL statement.
func TestNonBreakingSpaceDoesNotBreakProse(t *testing.T) {
	d := New()
	for _, benign := range []string{
		"Ordering\xa0is\xa0open\xa0from\xa010\xa0to\xa018",
		"caf\xa0 menu for table 4",
		"100\xa0%\xa0cotton",
		"select a size from the dropdown",
	} {
		if v := d.Analyze([]byte(benign)); v.Detected() {
			t.Errorf("false positive on %q (score %d)", benign, v.Score)
		}
	}
}
