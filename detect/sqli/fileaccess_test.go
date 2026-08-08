// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package sqli

import "testing"

// TestIntoOutfileAndProcedureAnalyse covers the two gaps the CRS differential
// found: payloads the converted Core Rule Set blocked and gwaf did not.
//
// INTO OUTFILE is the standard MySQL route from an injection to code execution —
// write a PHP file into the webroot and request it. PROCEDURE ANALYSE() is the
// information-disclosure primitive that turns a blind injection into an
// error-based one. Neither has the shape the danger-call check looks for: INTO
// OUTFILE has no parentheses at all, and "analyse" tokenizes as an identifier.
//
// This is the point of running gwaf against CRS rather than only against its own
// corpus: a corpus only contains attacks somebody already thought of.
func TestIntoOutfileAndProcedureAnalyse(t *testing.T) {
	d := New()

	t.Run("attacks fire", func(t *testing.T) {
		for _, attack := range []string{
			"1 INTO OUTFILE '/tmp/x'",
			"1 into dumpfile '/var/www/html/shell.php'",
			"1 UNION SELECT '<?php system($_GET[0]); ?>' INTO OUTFILE '/var/www/s.php'",
			"1 PROCEDURE ANALYSE()",
			"1 procedure analyse(extractvalue(rand(),concat(0x3a,version())),1)",
			"-1 union select 1,2 into outfile '/tmp/a'",
		} {
			if v := d.Analyze([]byte(attack)); !v.Detected() {
				t.Errorf("missed %q (score %d, signals %v)", attack, v.Score, v.Signals)
			}
		}
	})

	// The grammar carries the distinction rather than the keywords. MySQL
	// requires a quoted path after OUTFILE and parentheses after ANALYSE, so
	// demanding both costs no payload and keeps ordinary sentences out — "log
	// into the portal" and "our procedure is documented" are not attacks.
	t.Run("prose passes", func(t *testing.T) {
		for _, benign := range []string{
			"put the files into outfile storage next week",
			"the procedure analyses the sample twice",
			"log into the portal with your email",
			"our procedure is documented in the handbook",
			"import the data into our warehouse",
			"the analyse step runs after the import procedure",
		} {
			if v := d.Analyze([]byte(benign)); v.Detected() {
				t.Errorf("false positive on %q (score %d, signals %v)", benign, v.Score, v.Signals)
			}
		}
	})
}
