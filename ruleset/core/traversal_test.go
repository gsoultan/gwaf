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

// TestPHPSerializedNeedsAnObject is the false positive a WordPress replay found.
//
// The rule is named for object injection and matched plain arrays too, so
// "a:3:{s:7:"enabled";b:1;...}" blocked -- which is what WordPress's options API
// stores in admin-ajax every time a plugin setting is saved.
//
// Requiring an object is not a weakening. The attack needs a class to
// instantiate before a magic method (__wakeup, __destruct, __toString) can fire;
// unserialize() on an array of scalars builds no objects and calls nothing, so
// there is no gadget chain to reach. An object nested inside an array is still
// an object, which is the shape PHPGGC actually emits.
func TestPHPSerializedNeedsAnObject(t *testing.T) {
	o := phpSerializedObject()

	// Values arrive lowercased and whitespace-stripped: the rule runs behind
	// decodeChain, so the operator never sees an uppercase "O:".
	t.Run("objects fire", func(t *testing.T) {
		for _, attack := range []string{
			`o:8:"stdclass":1:{s:4:"data";s:3:"pwn";}`,
			`a:2:{i:0;s:4:"pwn!";i:1;o:8:"stdclass":0:{}}`,
			`o:24:"guzzlehttp\psr7\fnstream":1:{s:33:"_fn_close";s:6:"system";}`,
			`c:11:"arrayobject":24:{x:i:0;a:0:{};m:a:0:{}}`,
		} {
			if _, ok := o.Eval(nil, []byte(attack)); !ok {
				t.Errorf("missed %q", attack)
			}
		}
	})

	t.Run("scalar arrays pass", func(t *testing.T) {
		for _, benign := range []string{
			`a:3:{s:7:"enabled";b:1;s:5:"email";s:17:"alice@example.com";s:5:"limit";i:25;}`,
			`a:2:{s:4:"name";s:5:"Alice";s:3:"age";i:30;}`,
			`a:0:{}`,
			`a:1:{i:0;a:1:{s:3:"key";s:5:"value";}}`,
		} {
			if _, ok := o.Eval(nil, []byte(benign)); ok {
				t.Errorf("false positive on %q", benign)
			}
		}
	})
}
