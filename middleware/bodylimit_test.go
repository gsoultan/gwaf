package middleware_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/middleware"
)

// hugeBody streams n bytes without ever holding them, the way a client does.
type hugeBody struct{ left int64 }

func (h *hugeBody) Read(p []byte) (int, error) {
	if h.left <= 0 {
		return 0, io.EOF
	}
	n := len(p)
	if int64(n) > h.left {
		n = int(h.left)
	}
	for i := range p[:n] {
		p[i] = 'A'
	}
	h.left -= int64(n)
	return n, nil
}
func (h *hugeBody) Close() error { return nil }

func TestUnboundedBodyRead(t *testing.T) {
	w, err := gwaf.New()
	if err != nil {
		t.Fatal(err)
	}
	h := middleware.HTTP(w)(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.WriteHeader(200)
	}))

	const size = 256 << 20 // 256 MiB, far past the 1 MiB MaxBodySize
	req := httptest.NewRequest("POST", "/x", &hugeBody{left: size})
	req.Header.Set("Content-Type", "application/octet-stream")
	req.ContentLength = size

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	runtime.ReadMemStats(&after)
	grew := int64(after.TotalAlloc - before.TotalAlloc)
	t.Logf("status=%d allocated=%d MiB for a %d MiB body (MaxBodySize is 1 MiB)",
		rec.Code, grew>>20, size>>20)
	if grew > 8<<20 {
		t.Errorf("read %d MiB into memory for a body the WAF will reject at 1 MiB: "+
			"an unbounded read from a request", grew>>20)
	}
}

// TestOversizeBodyReachesHandlerWhole is the half that could corrupt data.
//
// Under FailOpen an oversize request proceeds, and a handler handed a silently
// shortened body is worse than the bug the bound fixes: it protects nothing and
// loses bytes. The buffered prefix is chained to the unread remainder, so the
// handler streams the whole thing while the middleware never holds more than
// the limit plus one byte.
func TestOversizeBodyReachesHandlerWhole(t *testing.T) {
	w, err := gwaf.New(gwaf.WithFailMode(gwaf.FailOpen))
	if err != nil {
		t.Fatal(err)
	}
	const size = 4 << 20 // 4 MiB, past the 1 MiB limit

	var got int64
	h := middleware.HTTP(w)(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		n, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			t.Errorf("handler read: %v", err)
		}
		got = n
		rw.WriteHeader(200)
	}))

	req := httptest.NewRequest("POST", "/x", &hugeBody{left: size})
	req.Header.Set("Content-Type", "application/octet-stream")
	req.ContentLength = size
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200 under FailOpen", rec.Code)
	}
	if got != size {
		t.Errorf("handler read %d bytes of a %d byte body: the body was truncated "+
			"for the origin, which loses data rather than protecting anything", got, size)
	}
}
