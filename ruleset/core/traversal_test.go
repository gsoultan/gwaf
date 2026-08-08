// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package core

import "testing"

// TestRepeatedTraversalNeedsTwoWalkingSegments is the regression for a false
// positive the benign corpus found: the search query "cd ../.. then run make
// from the project root" was blocked.
//
// The rule matched the literal "../..", and its transform chain strips
// whitespace, so the sentence arrived as "cd../..thenrunmakefromtheprojectroot"
// and contained it. Telling somebody how to build a project is not an attack.
//
// Two consecutive segments that each end in a separator is what a walking
// payload has and the sentence does not.
func TestRepeatedTraversalNeedsTwoWalkingSegments(t *testing.T) {
	o := repeatedTraversal()

	t.Run("walking payloads fire", func(t *testing.T) {
		for _, attack := range []string{
			"../../etc/passwd",
			"../../../../etc/shadow",
			`..\..\windows\system32`,
			"../../config/database.yml",
			"..%2f..%2fetc%2fpasswd",
			`..%5c..%5cboot.ini`,
			"/var/www/../../etc/passwd",
			`../..\mixed/separators`,
		} {
			if _, ok := o.Eval(nil, []byte(attack)); !ok {
				t.Errorf("missed %q", attack)
			}
		}
	})

	t.Run("prose and single steps pass", func(t *testing.T) {
		// As the chain delivers them: lowercased, whitespace stripped.
		for _, benign := range []string{
			"cd../..thenrunmakefromtheprojectroot",
			"../parent-relative-reference",
			"see../docsforinstructions",
			"a..bversionrange",
			"file..name",
			"...",
			"..",
		} {
			if _, ok := o.Eval(nil, []byte(benign)); ok {
				t.Errorf("false positive on %q", benign)
			}
		}
	})
}
