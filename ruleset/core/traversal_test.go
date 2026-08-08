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

// TestSensitiveFileWithoutTraversal covers the reads that never walk. Replaying
// real WordPress plugin CVEs found parameters handed an absolute or bare path
// -- `logfile=/Windows/win.ini`, `url=/etc/os-release`, `template_name=etc/passwd`
// -- which the traversal rules correctly ignore because there is no "../" in
// them, and which the sensitive-file list missed because every entry required a
// leading slash and named only passwd or shadow.
//
// The benign half is the reason the list stays a list. "etc" is an English word
// and these rules see comment bodies, so the fragments have to be ones prose
// does not produce.
func TestSensitiveFileWithoutTraversal(t *testing.T) {
	o := sensitiveFileOp()

	t.Run("absolute and bare reads fire", func(t *testing.T) {
		for _, attack := range []string{
			"/etc/passwd",
			"etc/passwd",
			"/etc/os-release",
			"/etc/hosts",
			"/etc/group",
			"/windows/win.ini",
			"c:/windows/win.ini",
			"/proc/self/environ",
			"proc/self/cmdline",
			"/root/.ssh/id_rsa",
		} {
			if _, ok := o.Eval(nil, []byte(attack)); !ok {
				t.Errorf("missed %q", attack)
			}
		}
	})

	t.Run("prose and ordinary paths pass", func(t *testing.T) {
		for _, benign := range []string{
			"functions.php",
			"inc/template-functions.php",
			"/wp-content/uploads/2026/01/photo.jpg",
			"bugs,features,etc/issuesarewelcome",
			"etcetera",
			"sketching/etc/notes",
			"/var/log/app.log",
		} {
			if _, ok := o.Eval(nil, []byte(benign)); ok {
				t.Errorf("false positive on %q", benign)
			}
		}
	})
}
