package gwaf_test

import "testing"

func TestHPPJoinedReading(t *testing.T) {
	w := newWAF(t)
	for _, tc := range []struct {
		name, target string
		want         bool
	}{
		// The actual ASP.NET technique: a comment swallows the comma the
		// framework joins with, so the two halves become one statement.
		{"sqli split, comment eats comma", `/x?q=1/*&q=*/union+select+pw+from+users--`, true},
		{"sqli split, second half whole", `/x?q=ok&q=1'+union+select+pw--`, true},
		{"single value control", `/x?q=1'+UNION+SELECT+pw--`, true},
		// Ordinary repeated parameters must not become an attack by being joined.
		{"repeated tag filter", `/x?tag=red&tag=green&tag=blue`, false},
		{"repeated id list", `/x?id=1&id=2&id=3`, false},
		{"checkbox group", `/x?opt=a&opt=b`, false},
		{"distinct names", `/x?a=1&b=2`, false},
	} {
		tx := w.NewTransaction()
		tx.SetRequestLine("GET", tc.target, "HTTP/1.1")
		tx.SetRemoteAddr("192.0.2.1")
		if got := tx.ProcessRequestHeaders().Blocked(); got != tc.want {
			t.Errorf("%-30s blocked=%v want=%v  %s", tc.name, got, tc.want, tc.target)
		}
		tx.Close()
	}
}
