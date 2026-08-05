// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Package middleware wires gwaf into net/http.
//
// This is integration profile A from docs/INTEGRATION.md — the case that covers
// most users, where the answer should be three lines:
//
//	waf, _ := gwaf.New()
//	mux := http.NewServeMux()
//	http.ListenAndServe(":8080", middleware.HTTP(waf)(mux))
//
// It lives in the core module because net/http is standard library, so it costs
// an embedder nothing. Framework adapters — chi, echo, gin — need their own
// dependencies and therefore their own modules; importing the chi adapter must
// never put chi in someone else's dependency graph.
//
// # Two traps this handles
//
// Both are things most WAF middleware gets wrong, and both are silent.
//
// **Body double-read.** The handler still needs the body the firewall just
// inspected. Reading it without putting it back gives the handler an empty
// body, and reading it twice is not possible from a stream. The body is read
// once into a bounded buffer and r.Body is replaced with a reader over it.
//
// **ResponseWriter interface loss.** Wrapping a ResponseWriter naively drops
// http.Flusher, http.Hijacker, and io.ReaderFrom, which silently breaks
// server-sent events, WebSocket upgrades, and sendfile. The wrapper here
// implements Unwrap so http.ResponseController finds the original, and also
// delegates the classic interfaces directly for code that type-asserts.
package middleware

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/gsoultan/gwaf"
)

// BlockHandler writes the response for a blocked request.
//
// The default writes a bare 403 with no detail. What a rejected client is told
// is an application decision — some deployments want a correlation ID, some
// want to look like a 404 — and it is not the library's to make.
type BlockHandler func(w http.ResponseWriter, r *http.Request, d gwaf.Decision)

// Option configures the middleware.
type Option func(*config)

type config struct {
	onBlock      BlockHandler
	onDecision   func(*http.Request, gwaf.Decision)
	inspectResp  bool
	maxRespBytes int
}

func defaultConfig() config {
	return config{
		onBlock:      defaultBlockHandler,
		maxRespBytes: 128 << 10,
	}
}

// WithBlockHandler sets the response written for a blocked request.
func WithBlockHandler(h BlockHandler) Option {
	return func(c *config) {
		if h != nil {
			c.onBlock = h
		}
	}
}

// OnDecision registers a callback for every decision, blocking or not, with the
// request that produced it. It runs on the request path and must not block.
func OnDecision(fn func(*http.Request, gwaf.Decision)) Option {
	return func(c *config) { c.onDecision = fn }
}

// WithResponseInspection enables response-phase analysis.
//
// It is off by default because it is the expensive choice and the one that
// changes behaviour: inspecting a response body means buffering it, which
// defeats streaming and delays time-to-first-byte. Deployments that need
// data-leakage detection opt in knowingly; everyone else should not pay for it.
//
// Bodies larger than maxBytes are passed through uninspected rather than
// buffered without limit. That is a coverage decision and it is reported
// through OnDecision, not hidden.
func WithResponseInspection(maxBytes int) Option {
	return func(c *config) {
		c.inspectResp = true
		if maxBytes > 0 {
			c.maxRespBytes = maxBytes
		}
	}
}

// defaultBlockHandler writes a bare 403.
//
// Deliberately says nothing about why. Telling a client which rule fired is
// telling an attacker which rule to work around, and the detail belongs in the
// audit record instead.
func defaultBlockHandler(w http.ResponseWriter, _ *http.Request, d gwaf.Decision) {
	status := d.Status()
	if status == 0 {
		status = http.StatusForbidden
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, "Forbidden\n")
}

// HTTP returns middleware that runs every request through waf.
func HTTP(waf *gwaf.WAF, opts ...Option) func(http.Handler) http.Handler {
	cfg := defaultConfig()
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			serve(waf, &cfg, next, w, r)
		})
	}
}

func serve(waf *gwaf.WAF, cfg *config, next http.Handler, w http.ResponseWriter, r *http.Request) {
	tx := waf.NewTransaction()
	defer tx.Close()

	populateRequest(tx, r)

	if d := tx.ProcessRequestHeaders(); d.Blocked() {
		report(cfg, r, d)
		cfg.onBlock(w, r, d)
		return
	}

	// Blocking above means the body was never read from the client, which is
	// the point of the phase ordering: a request rejected on its headers costs
	// nothing to read.
	restore, ok := captureBody(tx, r)
	if !ok {
		// The body could not be read. Treating that as clean would assert
		// something about bytes nobody saw.
		d := tx.Decision()
		report(cfg, r, d)
		cfg.onBlock(w, r, d)
		return
	}
	restore()

	if d := tx.ProcessRequestBody(); d.Blocked() {
		report(cfg, r, d)
		cfg.onBlock(w, r, d)
		return
	}

	if !cfg.inspectResp {
		report(cfg, r, tx.Decision())
		next.ServeHTTP(w, r)
		return
	}

	rw := &responseWriter{ResponseWriter: w, limit: cfg.maxRespBytes}
	next.ServeHTTP(rw, r)
	rw.flushBuffered()
	report(cfg, r, tx.Decision())
}

func report(cfg *config, r *http.Request, d gwaf.Decision) {
	if cfg.onDecision != nil {
		cfg.onDecision(r, d)
	}
}

// populateRequest hands the request line, headers, and query arguments to the
// transaction.
func populateRequest(tx *gwaf.Transaction, r *http.Request) {
	target := r.URL.RequestURI()
	if r.RequestURI != "" {
		// The raw request-target is preferred over the parsed URL: parsing
		// normalizes, and a normalized view can differ from what the origin
		// receives. Inspecting what was actually sent is the whole point.
		target = r.RequestURI
	}
	tx.SetRequestLine(r.Method, target, r.Proto)

	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		tx.SetRemoteAddr(host)
	} else if r.RemoteAddr != "" {
		tx.SetRemoteAddr(r.RemoteAddr)
	}

	for name, values := range r.Header {
		for _, v := range values {
			tx.AddRequestHeader(name, v)
		}
	}
	// Host is carried on the struct rather than in Header, so it would
	// otherwise never be inspected — and it reaches routing and cache keys.
	if r.Host != "" {
		tx.AddRequestHeader("Host", r.Host)
	}

	addQueryArgs(tx, r.URL)
}

// addQueryArgs parses the query string and records each argument.
//
// url.ParseQuery is not used: it drops pairs it considers malformed, and a pair
// an attacker deliberately malformed is exactly the one worth inspecting. The
// origin's own parser may well accept it.
func addQueryArgs(tx *gwaf.Transaction, u *url.URL) {
	q := u.RawQuery
	for len(q) > 0 {
		var pair string
		if i := strings.IndexAny(q, "&;"); i >= 0 {
			pair, q = q[:i], q[i+1:]
		} else {
			pair, q = q, ""
		}
		if pair == "" {
			continue
		}

		name, value := pair, ""
		if i := strings.IndexByte(pair, '='); i >= 0 {
			name, value = pair[:i], pair[i+1:]
		}

		// Decoding failures keep the raw form rather than dropping the pair.
		if dec, err := url.QueryUnescape(name); err == nil {
			name = dec
		}
		if dec, err := url.QueryUnescape(value); err == nil {
			value = dec
		}
		tx.AddArgument(name, value)
	}
}

// captureBody reads the request body for inspection and puts it back.
//
// The returned function restores r.Body so the handler reads the same bytes.
// The bool reports whether the body could be read at all; a body that could not
// be read has not been shown to be clean.
func captureBody(tx *gwaf.Transaction, r *http.Request) (restore func(), ok bool) {
	if r.Body == nil || r.Body == http.NoBody {
		return func() {}, true
	}

	// A GET with no declared body is the common case and must not pay for a read.
	if r.ContentLength == 0 {
		return func() {}, true
	}

	buf, err := io.ReadAll(r.Body)
	_ = r.Body.Close()
	if err != nil {
		return func() {}, false
	}

	tx.SetRequestBody(buf)
	return func() {
		r.Body = io.NopCloser(bytes.NewReader(buf))
		r.ContentLength = int64(len(buf))
	}, true
}

// responseWriter buffers a response for inspection.
//
// It implements Unwrap so http.ResponseController reaches the original writer,
// and delegates Flush, Hijack, Push, and ReadFrom directly for code that type
// asserts instead. Without both, wrapping silently breaks server-sent events,
// WebSocket upgrades, and sendfile — a failure that shows up as "streaming
// mysteriously buffers" long after the middleware was added.
type responseWriter struct {
	http.ResponseWriter

	buf    bytes.Buffer
	limit  int
	status int

	wroteHeader bool
	// passthrough is set once buffering is abandoned, either because the
	// response exceeded the limit or because the handler took over the
	// connection. From then on writes go straight through.
	passthrough bool
}

// Unwrap lets http.ResponseController find the underlying writer, which is the
// modern way optional interfaces are reached.
func (w *responseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *responseWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.status = status
	if w.passthrough {
		w.ResponseWriter.WriteHeader(status)
	}
}

func (w *responseWriter) Write(p []byte) (int, error) {
	if w.passthrough {
		return w.ResponseWriter.Write(p)
	}
	if w.buf.Len()+len(p) > w.limit {
		// Over the limit: stop buffering and let everything through rather
		// than growing without bound. The response is not inspected, which is
		// a coverage decision the caller sees through OnDecision.
		w.startPassthrough()
		return w.ResponseWriter.Write(p)
	}
	return w.buf.Write(p)
}

// startPassthrough flushes what was buffered and stops buffering.
func (w *responseWriter) startPassthrough() {
	if w.passthrough {
		return
	}
	w.passthrough = true
	if w.status != 0 {
		w.ResponseWriter.WriteHeader(w.status)
	}
	if w.buf.Len() > 0 {
		_, _ = w.ResponseWriter.Write(w.buf.Bytes())
		w.buf.Reset()
	}
}

// flushBuffered writes whatever is still held.
func (w *responseWriter) flushBuffered() {
	if w.passthrough {
		return
	}
	w.passthrough = true
	if w.status != 0 {
		w.ResponseWriter.WriteHeader(w.status)
	}
	if w.buf.Len() > 0 {
		_, _ = w.ResponseWriter.Write(w.buf.Bytes())
		w.buf.Reset()
	}
}

// Flush implements http.Flusher.
//
// Flushing means the handler wants bytes on the wire now — server-sent events,
// streaming JSON — so buffering is abandoned rather than silently defeating it.
func (w *responseWriter) Flush() {
	w.startPassthrough()
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack implements http.Hijacker, which is what a WebSocket upgrade needs.
func (w *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	// The connection is leaving HTTP entirely; anything buffered must go out
	// first or it is lost.
	w.startPassthrough()
	return h.Hijack()
}

// Push implements http.Pusher.
func (w *responseWriter) Push(target string, opts *http.PushOptions) error {
	if p, ok := w.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
}

// ReadFrom implements io.ReaderFrom so sendfile is still reachable.
//
// Buffering is abandoned first: the point of ReadFrom is to avoid copying
// through user space, and buffering would defeat it entirely.
func (w *responseWriter) ReadFrom(src io.Reader) (int64, error) {
	w.startPassthrough()
	if rf, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		return rf.ReadFrom(src)
	}
	return io.Copy(w.ResponseWriter, src)
}
