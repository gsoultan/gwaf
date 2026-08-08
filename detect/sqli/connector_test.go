// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package sqli

import "testing"

// TestWeldedConnector covers the no-space quote injection, found by running the
// Core Rule Set's own regression corpus against gwaf (CRS 942521, 942522).
//
// "WHERE u='1'or'1'" reads as "u = '1' OR '1'", and '1' casts to 1, so it
// authenticates. gwaf scored it 1: under a quoted context the quotes are the
// context delimiters, what remains is a connector between two operands, and
// there is no comparison for the boolean-injection signal to attach to. The
// shape is invisible to the token stream and has to be read from the bytes.
func TestWeldedConnector(t *testing.T) {
	d := New()

	t.Run("injections fire", func(t *testing.T) {
		for _, attack := range []string{
			"1'or'1",
			"a'or'a",
			`\'or'1`,
			"a'and'b",
			"x'||'y",
			"admin'OR'1",
			"a'XOR'b",
			`1"or"1`,
		} {
			if v := d.Analyze([]byte(attack)); !v.Detected() {
				t.Errorf("missed %q (score %d, signals %v)", attack, v.Score, v.Signals)
			}
		}
	})

	// The welding is the whole discriminator, and it has to hold against the
	// languages that use an apostrophe as a letter. Prose puts spaces around a
	// quoted conjunction; French and Irish apostrophes come singly, so there is
	// no second quote to close the pattern.
	t.Run("prose and apostrophes pass", func(t *testing.T) {
		for _, benign := range []string{
			"the word 'or' is a conjunction",
			"choose 'and' or 'or' from the list",
			"l'or et l'argent sont chers",
			"aujourd'hui il fait beau",
			"O'Brien and O'Neil went out",
			"it's 'and' that joins them",
			"rock'n'roll all night",
			"d'or",
			"can't or won't, either way",
		} {
			if v := d.Analyze([]byte(benign)); v.Detected() {
				t.Errorf("false positive on %q (score %d, signals %v)", benign, v.Score, v.Signals)
			}
		}
	})
}
