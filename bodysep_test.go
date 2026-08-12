package gwaf_test

import "testing"

func TestBodySemicolonUnion(t *testing.T) {
	w := newWAF(t)
	for _, tc := range []struct {
		name, body string
		want       bool
	}{
		{"nosql name, no semicolon", `password[$ne]=1`, true},
		{"name-anchored nosql after ;", `a=1;password[$ne]=1`, true},
		{"value-anchored shell after ;", `cmd=;whoami`, true},
		{"ordinary list value", `tags=red;green;blue`, false},
		{"css value", `style=color:red;font-weight:bold`, false},
		{"plain pair", `name=Alice&city=Paris`, false},
	} {
		tx := w.NewTransaction()
		tx.SetRequestLine("POST", "/x", "HTTP/1.1")
		tx.SetRemoteAddr("192.0.2.1")
		tx.AddRequestHeader("Content-Type", "application/x-www-form-urlencoded")
		tx.ProcessRequestHeaders()
		tx.SetRequestBody([]byte(tc.body))
		if got := tx.ProcessRequestBody().Blocked(); got != tc.want {
			t.Errorf("%-30s blocked=%v want=%v  %s", tc.name, got, tc.want, tc.body)
		}
		tx.Close()
	}
}
