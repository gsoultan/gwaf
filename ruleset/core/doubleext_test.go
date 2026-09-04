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

// TestDoubleExtensionSeparatorsNeedTheAttackShape is the regression for a second
// false-positive class, found the same way as the first: an embedder's benign
// corpus, this time a pasted Ruby backtrace.
//
// The separator switch returned true the moment an executable extension was
// followed by ";", ":", ",", a space or a tab, on the stated premise that "none
// of these appears in a filename by convention, so no further test is needed".
// The premise is true of a filename and false of the *value* the rule scans,
// which is arbitrary request text that may merely contain one.
//
// A colon after a script name is how every stack trace, compiler and linter on
// earth reports a line: "orders_controller.rb:22", "deploy.sh:10: syntax error".
// A comma after one is how every list of files is written. Those are refused,
// and a bug tracker, a CI dashboard or a support desk transports them all day.
//
// The attack shapes all put a *second extension* or an NTFS stream after the
// separator — "x.asp;.jpg", "x.php:.jpg", "x.php::$DATA" — so requiring that is
// what separates them, and it costs no bypass: a filter reads an extension, and
// a line number is not one.
//
// Space and tab are in the same switch and produce no false positive today only
// because the rule's chain strips whitespace, so "see deploy.sh for details"
// arrives welded as "seedeploy.shfordetails". They are held to the same test
// rather than left to depend on that.
func TestDoubleExtensionSeparatorsNeedTheAttackShape(t *testing.T) {
	o := doubleExtension()

	t.Run("parser confusion still blocked", func(t *testing.T) {
		for _, attack := range []string{
			"x.asp;.jpg",   // IIS semicolon truncation
			"x.php:.jpg",   // NTFS alternate data stream
			"x.php::$DATA", // the same, naming the default stream
			"x.php .jpg",   // trailing-space strippers
			"x.php,.jpg",
		} {
			if _, ok := o.Eval(nil, []byte(attack)); !ok {
				t.Errorf("missed %q", attack)
			}
		}
	})

	// As the chain delivers them: lowercased, whitespace stripped.
	t.Run("stack traces and file lists pass", func(t *testing.T) {
		for _, benign := range []string{
			"app/controllers/orders_controller.rb:22:in`show'",
			"implicit_render.rb:6:in`send_action'",
			"deploy.sh:10:syntaxerrornearunexpectedtoken",
			"files:report.sh,notes.txt",
			"rundeploy.sh;thentest.sh",
			"lib/tasks/import.rb:14",
		} {
			if _, ok := o.Eval(nil, []byte(benign)); ok {
				t.Errorf("false positive on %q", benign)
			}
		}
	})
}
