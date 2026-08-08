// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package core

import "testing"

// TestDoubleExtensionNeedsAPlausibleExtension is the regression for a false
// positive the benign corpus found: the support-desk sentence "the file upload
// rejected shell.php.jpg correctly" was blocked.
//
// The rule's chain strips whitespace, so the sentence arrives welded together
// and the component after ".php" is "jpgcorrectly" — a word, not an extension.
// Security tooling, bug trackers and this project's own documentation all
// describe these filenames in prose.
//
// The bound is on length rather than an allowlist: an upload filter reads the
// final extension against its own list, and one longer than five characters is
// not going to be on it, so requiring brevity costs no bypass.
func TestDoubleExtensionNeedsAPlausibleExtension(t *testing.T) {
	o := doubleExtension()

	t.Run("uploads still blocked", func(t *testing.T) {
		for _, attack := range []string{
			"shell.php.jpg",
			"shell.php.jpeg",
			"avatar.phtml.png",
			"x.asp;.jpg",
			"b.php%00.png",
			"x.php.",
			"/uploads/2026/shell.php.gif",
			"backdoor.jsp.webp",
			"/x.php/anything",
		} {
			if _, ok := o.Eval(nil, []byte(attack)); !ok {
				t.Errorf("missed %q", attack)
			}
		}
	})

	// As the chain delivers them: lowercased, whitespace stripped.
	t.Run("prose about uploads passes", func(t *testing.T) {
		for _, benign := range []string{
			"thefileuploadrejectedshell.php.jpgcorrectly",
			"weblockedavatar.php.pngyesterdayafternoon",
			"seetheshell.php.jpgexampleinthedocs",
		} {
			if _, ok := o.Eval(nil, []byte(benign)); ok {
				t.Errorf("false positive on %q", benign)
			}
		}
	})
}
