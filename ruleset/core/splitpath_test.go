// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package core

import (
	"testing"

	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/types"
)

// TestSplitPathRule covers the payload that is in no single value.
//
// "path=/etc/&target=passwd" is a real WordPress plugin CVE: the application
// joins the two and opens /etc/passwd. Per-argument inspection is structurally
// blind to it — "/etc/" is a directory and "passwd" is a word, and a rule
// looking at either alone is right to pass it.
func TestSplitPathRule(t *testing.T) {
	o := splitPathOp{}

	eval := func(key, value string, names, vals []string) bool {
		ctx := rules.EvalContext{
			Target: types.Target{Kind: types.TargetArgs},
			Key:    key,
		}
		for i := range names {
			ctx.Siblings.Names = append(ctx.Siblings.Names, []byte(names[i]))
			ctx.Siblings.Values = append(ctx.Siblings.Values, []byte(vals[i]))
		}
		_, ok := o.Eval(&ctx, []byte(value))
		return ok
	}

	t.Run("a directory joined to a sensitive name fires", func(t *testing.T) {
		for _, c := range []struct {
			key, val    string
			names, vals []string
		}{
			{"path", "/etc/", []string{"path", "target"}, []string{"/etc/", "passwd"}},
			{"dir", "/etc/", []string{"dir", "file"}, []string{"/etc/", "shadow"}},
			{"path", "/etc", []string{"path", "name"}, []string{"/etc", "passwd"}},
			{"base", "/proc/self/", []string{"base", "target"}, []string{"/proc/self/", "environ"}},
		} {
			if !eval(c.key, c.val, c.names, c.vals) {
				t.Errorf("missed %s=%s with siblings %v", c.key, c.val, c.vals)
			}
		}
	})

	t.Run("either half alone passes", func(t *testing.T) {
		// This is the whole reason the rule needs siblings: neither value is an
		// attack, and a rule that blocked "/etc/" on its own would block every
		// file manager in existence.
		for _, c := range []struct {
			key, val    string
			names, vals []string
		}{
			{"path", "/etc/", []string{"path"}, []string{"/etc/"}},
			// A sibling that does not complete to anything sensitiveFileOp knows.
			{"path", "/etc/", []string{"path", "target"}, []string{"/etc/", "myapp.conf"}},
			{"path", "/var/www/", []string{"path", "target"}, []string{"/var/www/", "index.html"}},
			{"path", "/uploads/", []string{"path", "target"}, []string{"/uploads/", "passwd"}},
			{"q", "passwd", []string{"q"}, []string{"passwd"}},
		} {
			if eval(c.key, c.val, c.names, c.vals) {
				t.Errorf("false positive on %s=%s with siblings %v", c.key, c.val, c.vals)
			}
		}
	})
}
