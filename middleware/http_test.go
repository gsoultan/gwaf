// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package middleware_test

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/middleware"
)

func newWAF(t *testing.T, opts ...gwaf.Option) *gwaf.WAF {
	t.Helper()
	w, err := gwaf.New(opts...)
	if err != nil {
		t.Fatalf("gwaf.New: %v", err)
	}
	return w
}

// echoHandler records what the handler actually received, which is how the
// body double-read trap is caught.
type echoHandler struct {
	called   bool
	gotBody  string
	bodyErr  error
	response string
}

func (h *echoHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.called = true
	b, err := io.ReadAll(r.Body)
	h.gotBody, h.bodyErr = string(b), err
	if h.response != "" {
		_, _ = io.WriteString(w, h.response)
	} else {
		_, _ = io.WriteString(w, "ok")
	}
}

func TestBlocksAttacks(t *testing.T) {
	w := newWAF(t)
	h := &echoHandler{}
	srv := middleware.HTTP(w)(h)

	tests := []struct{ name, target, body, ctype string }{
		{"sqli in query", "/search?id=1%27+OR+1%3D1--", "", ""},
		{"xss in query", "/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", "", ""},
		{"traversal in path", "/files?p=..%2f..%2fetc%2fpasswd", "", ""},
		{"sqli in json body", "/api", `{"q":"1 UNION SELECT password FROM users"}`,
			"application/json"},
		{"xss in form body", "/api", "c=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
			"application/x-www-form-urlencoded"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h.called = false

			var body io.Reader
			method := http.MethodGet
			if tt.body != "" {
				body, method = strings.NewReader(tt.body), http.MethodPost
			}
			r := httptest.NewRequest(method, tt.target, body)
			if tt.ctype != "" {
				r.Header.Set("Content-Type", tt.ctype)
			}
			rec := httptest.NewRecorder()

			srv.ServeHTTP(rec, r)

			if rec.Code != http.StatusForbidden {
				t.Errorf("status = %d, want 403", rec.Code)
			}
			if h.called {
				t.Error("handler ran for a blocked request")
			}
		})
	}
}

func TestAllowsBenignTraffic(t *testing.T) {
	w := newWAF(t)
	h := &echoHandler{}
	srv := middleware.HTTP(w)(h)

	tests := []struct{ name, target, body, ctype string }{
		{"plain get", "/api/v1/orders/12345", "", ""},
		{"search", "/search?q=golang+web+framework", "", ""},
		{"json body", "/api", `{"name":"Alice","qty":3}`, "application/json"},
		{"form body", "/api", "email=user%40example.com&msg=Thanks",
			"application/x-www-form-urlencoded"},
		{"markup comment", "/api", `{"c":"use the <b>bold</b> tag"}`, "application/json"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h.called = false

			var body io.Reader
			method := http.MethodGet
			if tt.body != "" {
				body, method = strings.NewReader(tt.body), http.MethodPost
			}
			r := httptest.NewRequest(method, tt.target, body)
			if tt.ctype != "" {
				r.Header.Set("Content-Type", tt.ctype)
			}
			rec := httptest.NewRecorder()

			srv.ServeHTTP(rec, r)

			if rec.Code != http.StatusOK {
				t.Errorf("status = %d, want 200", rec.Code)
			}
			if !h.called {
				t.Error("handler did not run for a benign request")
			}
		})
	}
}

// TestBodyIsReadableByHandler is the first trap. The handler still needs the
// body the firewall just inspected; middleware that reads it without putting it
// back hands the application an empty body, and the failure looks like an
// application bug rather than a middleware one.
func TestBodyIsReadableByHandler(t *testing.T) {
	w := newWAF(t)
	h := &echoHandler{}
	srv := middleware.HTTP(w)(h)

	for _, body := range []string{
		`{"name":"Alice","qty":3}`,
		"email=user%40example.com",
		strings.Repeat("x", 10000),
		"",
	} {
		t.Run(body[:min(len(body), 20)], func(t *testing.T) {
			h.gotBody, h.bodyErr = "", nil

			r := httptest.NewRequest(http.MethodPost, "/api", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			srv.ServeHTTP(httptest.NewRecorder(), r)

			if h.bodyErr != nil {
				t.Fatalf("handler could not read the body: %v", h.bodyErr)
			}
			if h.gotBody != body {
				t.Errorf("handler read %d bytes, want %d — the body was consumed "+
					"by inspection and not restored", len(h.gotBody), len(body))
			}
		})
	}
}

func TestContentLengthIsRestored(t *testing.T) {
	w := newWAF(t)
	var got int64
	srv := middleware.HTTP(w)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = r.ContentLength
	}))

	body := `{"name":"Alice"}`
	r := httptest.NewRequest(http.MethodPost, "/api", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	srv.ServeHTTP(httptest.NewRecorder(), r)

	if got != int64(len(body)) {
		t.Errorf("ContentLength = %d, want %d", got, len(body))
	}
}

// ---- the ResponseWriter interface trap -------------------------------------

// recordingWriter implements the optional interfaces so the test can observe
// whether the wrapper reached them.
type recordingWriter struct {
	http.ResponseWriter
	flushed  bool
	hijacked bool
	readFrom bool
}

func (w *recordingWriter) Flush() { w.flushed = true }

func (w *recordingWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.hijacked = true
	return nil, nil, errors.New("test hijack")
}

func (w *recordingWriter) ReadFrom(r io.Reader) (int64, error) {
	w.readFrom = true
	return io.Copy(w.ResponseWriter, r)
}

// TestResponseWriterInterfacesArePreserved is the second trap.
//
// Wrapping a ResponseWriter naively drops http.Flusher, http.Hijacker, and
// io.ReaderFrom. The symptom is not an error: server-sent events silently stop
// streaming, WebSocket upgrades silently fail, and sendfile silently degrades —
// weeks after the middleware was added, and never obviously connected to it.
func TestResponseWriterInterfacesArePreserved(t *testing.T) {
	w := newWAF(t)

	t.Run("flusher", func(t *testing.T) {
		rec := &recordingWriter{ResponseWriter: httptest.NewRecorder()}
		srv := middleware.HTTP(w, middleware.WithResponseInspection(1<<20))(
			http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
				f, ok := rw.(http.Flusher)
				if !ok {
					t.Fatal("http.Flusher was lost by the wrapper")
				}
				f.Flush()
			}))
		srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if !rec.flushed {
			t.Error("Flush did not reach the underlying writer")
		}
	})

	t.Run("hijacker", func(t *testing.T) {
		rec := &recordingWriter{ResponseWriter: httptest.NewRecorder()}
		srv := middleware.HTTP(w, middleware.WithResponseInspection(1<<20))(
			http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
				h, ok := rw.(http.Hijacker)
				if !ok {
					t.Fatal("http.Hijacker was lost by the wrapper")
				}
				_, _, _ = h.Hijack()
			}))
		srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if !rec.hijacked {
			t.Error("Hijack did not reach the underlying writer")
		}
	})

	t.Run("readerfrom", func(t *testing.T) {
		rec := &recordingWriter{ResponseWriter: httptest.NewRecorder()}
		srv := middleware.HTTP(w, middleware.WithResponseInspection(1<<20))(
			http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
				rf, ok := rw.(io.ReaderFrom)
				if !ok {
					t.Fatal("io.ReaderFrom was lost by the wrapper")
				}
				_, _ = rf.ReadFrom(strings.NewReader("streamed"))
			}))
		srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if !rec.readFrom {
			t.Error("ReadFrom did not reach the underlying writer")
		}
	})

	t.Run("response controller", func(t *testing.T) {
		// The modern path: http.ResponseController walks Unwrap.
		rec := &recordingWriter{ResponseWriter: httptest.NewRecorder()}
		srv := middleware.HTTP(w, middleware.WithResponseInspection(1<<20))(
			http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
				if err := http.NewResponseController(rw).Flush(); err != nil {
					t.Fatalf("ResponseController could not reach the writer: %v", err)
				}
			}))
		srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if !rec.flushed {
			t.Error("Flush via ResponseController did not reach the writer")
		}
	})
}

func TestResponseIsWrittenThrough(t *testing.T) {
	w := newWAF(t)
	h := &echoHandler{response: "hello from the handler"}

	for _, name := range []string{"without inspection", "with inspection"} {
		t.Run(name, func(t *testing.T) {
			var srv http.Handler
			if name == "with inspection" {
				srv = middleware.HTTP(w, middleware.WithResponseInspection(1<<20))(h)
			} else {
				srv = middleware.HTTP(w)(h)
			}

			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

			if got := rec.Body.String(); got != "hello from the handler" {
				t.Errorf("body = %q, want the handler's output", got)
			}
		})
	}
}

func TestOversizedResponseFallsThrough(t *testing.T) {
	w := newWAF(t)
	payload := strings.Repeat("x", 5000)
	h := &echoHandler{response: payload}
	srv := middleware.HTTP(w, middleware.WithResponseInspection(1000))(h)

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	// Exceeding the buffer limit must pass the response through intact, never
	// truncate it: a firewall that silently shortens responses is worse than
	// one that does not inspect them.
	if got := rec.Body.String(); got != payload {
		t.Errorf("response truncated: got %d bytes, want %d", len(got), len(payload))
	}
}

func TestCustomBlockHandler(t *testing.T) {
	w := newWAF(t)
	srv := middleware.HTTP(w, middleware.WithBlockHandler(
		func(rw http.ResponseWriter, _ *http.Request, d gwaf.Decision) {
			rw.Header().Set("X-Rule", d.RuleID().String())
			rw.WriteHeader(http.StatusTeapot)
			_, _ = io.WriteString(rw, "custom")
		}))(&echoHandler{})

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/?id=1%27+OR+1%3D1--", nil))

	if rec.Code != http.StatusTeapot {
		t.Errorf("status = %d, want 418", rec.Code)
	}
	if rec.Body.String() != "custom" {
		t.Errorf("body = %q, want custom", rec.Body.String())
	}
	if rec.Header().Get("X-Rule") == "" || rec.Header().Get("X-Rule") == "0" {
		t.Error("the block handler received no rule attribution")
	}
}

// TestDefaultBlockResponseLeaksNothing checks that a rejected client is not told
// which rule fired. That detail belongs in the audit record; telling the client
// is telling an attacker what to work around.
func TestDefaultBlockResponseLeaksNothing(t *testing.T) {
	w := newWAF(t)
	srv := middleware.HTTP(w)(&echoHandler{})

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", nil))

	body := strings.ToLower(rec.Body.String())
	for _, leak := range []string{"script", "rule", "xss", "3010", "detect"} {
		if strings.Contains(body, leak) {
			t.Errorf("default block response leaks %q: %q", leak, rec.Body.String())
		}
	}
}

func TestOnDecisionCallback(t *testing.T) {
	w := newWAF(t)
	var decisions []gwaf.Decision
	var paths []string

	srv := middleware.HTTP(w, middleware.OnDecision(
		func(r *http.Request, d gwaf.Decision) {
			decisions = append(decisions, d)
			paths = append(paths, r.URL.Path)
		}))(&echoHandler{})

	srv.ServeHTTP(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/ok", nil))
	srv.ServeHTTP(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/bad?id=1%27+OR+1%3D1--", nil))

	if len(decisions) != 2 {
		t.Fatalf("callback ran %d times, want 2 — it must fire for allowed "+
			"requests too, or a deployment cannot see what it is not blocking",
			len(decisions))
	}
	if decisions[0].Blocked() {
		t.Error("benign request reported as blocked")
	}
	if !decisions[1].Blocked() {
		t.Error("attack not reported as blocked")
	}
	if paths[1] != "/bad" {
		t.Errorf("path = %q, want /bad", paths[1])
	}
}

// TestMalformedQueryIsStillInspected covers the deliberate choice not to use
// url.ParseQuery: it drops pairs it considers malformed, and a pair an attacker
// deliberately malformed is exactly the one worth inspecting.
func TestMalformedQueryIsStillInspected(t *testing.T) {
	w := newWAF(t)
	srv := middleware.HTTP(w)(&echoHandler{})

	for _, target := range []string{
		"/?%zz=1&id=1%27+OR+1%3D1--",
		"/?id=1%27+OR+1%3D1--&broken=%",
		"/?=1%27+OR+1%3D1--",
	} {
		t.Run(target, func(t *testing.T) {
			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
			if rec.Code != http.StatusForbidden {
				t.Errorf("status = %d, want 403 — a malformed neighbour must not "+
					"hide a payload", rec.Code)
			}
		})
	}
}

func TestHostHeaderIsInspected(t *testing.T) {
	w := newWAF(t)
	srv := middleware.HTTP(w)(&echoHandler{})

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	// Host lives on the struct rather than in Header, so it is easy to miss.
	r.Host = "evil.com/../../etc/passwd"
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, r)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 — the Host header was not inspected", rec.Code)
	}
}

func TestConcurrentRequests(t *testing.T) {
	w := newWAF(t)
	// A stateless handler: echoHandler records what it saw, which is useful for
	// the single-threaded tests and is itself a data race when shared.
	srv := middleware.HTTP(w)(http.HandlerFunc(
		func(rw http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			_, _ = io.WriteString(rw, "ok")
		}))

	const goroutines = 32
	done := make(chan bool, goroutines)

	for g := range goroutines {
		go func(g int) {
			ok := true
			for range 50 {
				rec := httptest.NewRecorder()
				if g%2 == 0 {
					srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
						"/?id=1%27+OR+1%3D1--", nil))
					ok = ok && rec.Code == http.StatusForbidden
				} else {
					srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
						"/?q=ordinary+search", nil))
					ok = ok && rec.Code == http.StatusOK
				}
			}
			done <- ok
		}(g)
	}

	for range goroutines {
		if !<-done {
			t.Error("wrong verdict under concurrency")
		}
	}
}

func TestNoBodyRequestsAreCheap(t *testing.T) {
	w := newWAF(t)
	var sawBody bool
	srv := middleware.HTTP(w)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		sawBody = len(b) > 0
	}))

	r := httptest.NewRequest(http.MethodGet, "/api/v1/orders", nil)
	srv.ServeHTTP(httptest.NewRecorder(), r)

	if sawBody {
		t.Error("a body appeared on a request that had none")
	}
}

func BenchmarkMiddlewareBenign(b *testing.B) {
	w, err := gwaf.New()
	if err != nil {
		b.Fatal(err)
	}
	srv := middleware.HTTP(w)(http.HandlerFunc(
		func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(200) }))

	r := httptest.NewRequest(http.MethodGet, "/api/v1/orders/12345", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0")

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		srv.ServeHTTP(httptest.NewRecorder(), r)
	}
}

func BenchmarkMiddlewareBlocked(b *testing.B) {
	w, err := gwaf.New()
	if err != nil {
		b.Fatal(err)
	}
	srv := middleware.HTTP(w)(http.HandlerFunc(
		func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(200) }))

	r := httptest.NewRequest(http.MethodGet, "/?id=1%27+OR+1%3D1--", nil)

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		srv.ServeHTTP(httptest.NewRecorder(), r)
	}
}
