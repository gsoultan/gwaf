// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Command gwaf-proxy is a reference reverse proxy that puts gwaf in front of an
// application it does not have to be written in Go.
//
// # Why this exists
//
// gwaf is a library, and a library protects only the process that imports it. A
// PHP shop, a Node service, or a WordPress install cannot import a Go package,
// so without something in front of them gwaf's detection is unreachable to the
// applications that need it most. This binary is that something: it terminates
// HTTP, runs each request through gwaf, and forwards what survives to an
// upstream over the network.
//
// # What it deliberately is not
//
// It is tier 3 in CLAUDE.md §1 -- pure glue, and every line here either parses a
// flag, builds a gwaf option, or wires net/http. It contains no detection logic,
// no rule of its own, no config file it discovers, no plugin system, and no
// metrics endpoint. Those are tripwires: if this proxy ever needs one, the
// library is missing an API and the fix goes there, not here. The whole file is
// under the ~500-line cap for the same reason -- the moment it grows a feature,
// it has started becoming the product gwaf refuses to be.
//
// Everything it does do is a decision the operator owns: where to listen, where
// to forward, whether to block or only observe, and what to do when a request
// cannot be fully analysed. gwaf produces the finding; the deployment produces
// the outcome.
//
// # Usage
//
//	gwaf-proxy -upstream http://127.0.0.1:8080 -listen :8443 -tls-cert c.pem -tls-key k.pem
//	gwaf-proxy -upstream http://127.0.0.1:8080 -detect-only      # observe first, block later
//
// This is a reference. It is production-shaped -- graceful shutdown, timeouts,
// structured logs -- but an operator with needs beyond these flags should copy
// it and embed the library directly, which is the point of gwaf being a library.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/middleware"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "gwaf-proxy:", err)
		os.Exit(1)
	}
}

// options is the operator-owned deployment surface. Every field is a deployment
// choice (where, whether, how to fail) rather than a detection choice, because
// detection is the library's and this binary does not second-guess it.
type options struct {
	listen        string
	upstream      string
	detectOnly    bool
	failOpen      bool
	blockStatus   int
	inspectResp   int
	logJSON       bool
	verbose       bool
	healthPath    string
	tlsCert       string
	tlsKey        string
	readTimeout   time.Duration
	writeTimeout  time.Duration
	upstreamTimeo time.Duration
}

func parseFlags(args []string) (options, error) {
	fs := flag.NewFlagSet("gwaf-proxy", flag.ContinueOnError)
	var o options
	fs.StringVar(&o.listen, "listen", ":8080", "address to listen on")
	fs.StringVar(&o.upstream, "upstream", "", "upstream base URL to forward to (required), e.g. http://127.0.0.1:9000")
	fs.BoolVar(&o.detectOnly, "detect-only", false, "evaluate and log, but do not block -- the safe first step of a rollout")
	fs.BoolVar(&o.failOpen, "fail-open", false, "forward requests that could not be fully analysed (default: fail closed)")
	fs.IntVar(&o.blockStatus, "block-status", http.StatusForbidden, "HTTP status returned for a blocked request")
	fs.IntVar(&o.inspectResp, "response-inspection", 0, "buffer up to N bytes of each response for leak detection (0 = never buffer, the default)")
	fs.BoolVar(&o.logJSON, "log-json", false, "emit logs as JSON rather than text")
	fs.BoolVar(&o.verbose, "v", false, "log every decision, not only blocks (includes the rule ID)")
	fs.StringVar(&o.healthPath, "health-path", "", "path answered locally with 200 without touching gwaf or upstream, e.g. /healthz (empty = disabled)")
	fs.StringVar(&o.tlsCert, "tls-cert", "", "TLS certificate file (enables HTTPS when set with -tls-key)")
	fs.StringVar(&o.tlsKey, "tls-key", "", "TLS private key file")
	fs.DurationVar(&o.readTimeout, "read-timeout", 15*time.Second, "maximum time to read a request, including its body")
	fs.DurationVar(&o.writeTimeout, "write-timeout", 30*time.Second, "maximum time to write a response")
	fs.DurationVar(&o.upstreamTimeo, "upstream-timeout", 30*time.Second, "maximum time to wait for the upstream")
	if err := fs.Parse(args); err != nil {
		return options{}, err
	}
	if o.upstream == "" {
		return options{}, errors.New("-upstream is required")
	}
	if (o.tlsCert == "") != (o.tlsKey == "") {
		return options{}, errors.New("-tls-cert and -tls-key must be set together")
	}
	return o, nil
}

func run(args []string) error {
	o, err := parseFlags(args)
	if err != nil {
		return err
	}

	logger := newLogger(o.logJSON)

	target, err := url.Parse(o.upstream)
	if err != nil {
		return fmt.Errorf("invalid -upstream %q: %w", o.upstream, err)
	}
	if target.Scheme != "http" && target.Scheme != "https" {
		return fmt.Errorf("-upstream must be http or https, got %q", target.Scheme)
	}

	// The WAF. Detection is entirely the library's; the only things set here are
	// the operator's deployment choices, each mapped to a documented option.
	wafOpts := []gwaf.Option{
		gwaf.WithLogger(logger),
		gwaf.WithBlockStatus(o.blockStatus),
	}
	if o.detectOnly {
		wafOpts = append(wafOpts, gwaf.WithMode(gwaf.DetectionOnly))
	}
	if o.failOpen {
		wafOpts = append(wafOpts, gwaf.WithFailMode(gwaf.FailOpen))
	}
	waf, err := gwaf.New(wafOpts...)
	if err != nil {
		return fmt.Errorf("building waf: %w", err)
	}

	// The reverse proxy. httputil streams both directions and never buffers,
	// which is exactly gwaf's "never hold a response" invariant -- so response
	// inspection is opt-in and off here unless the operator asks for it.
	rp := newReverseProxy(target, o.upstreamTimeo, logger)

	mwOpts := []middleware.Option{
		middleware.WithBlockHandler(blockHandler(o, logger)),
		middleware.OnDecision(decisionLogger(o, logger)),
	}
	if o.inspectResp > 0 {
		mwOpts = append(mwOpts, middleware.WithResponseInspection(o.inspectResp))
	}

	var handler http.Handler = middleware.HTTP(waf, mwOpts...)(rp)
	if o.healthPath != "" {
		handler = withHealth(o.healthPath, handler)
	}

	srv := &http.Server{
		Addr:              o.listen,
		Handler:           handler,
		ReadTimeout:       o.readTimeout,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      o.writeTimeout,
	}

	mode := "BLOCKING"
	if o.detectOnly {
		mode = "DETECT-ONLY"
	}
	logger.Info("gwaf-proxy starting",
		"listen", o.listen, "upstream", o.upstream, "mode", mode,
		"fail", failName(o.failOpen), "tls", o.tlsCert != "")

	return serve(srv, o, logger)
}

// serve runs the server and shuts it down gracefully on SIGINT/SIGTERM, so an
// in-flight request is allowed to finish rather than being cut off.
func serve(srv *http.Server, o options, logger *slog.Logger) error {
	errc := make(chan error, 1)
	go func() {
		if o.tlsCert != "" {
			errc <- srv.ListenAndServeTLS(o.tlsCert, o.tlsKey)
		} else {
			errc <- srv.ListenAndServe()
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case sig := <-stop:
		logger.Info("shutting down", "signal", sig.String())
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		return srv.Shutdown(ctx)
	}
}

// newReverseProxy forwards to target, streaming both directions. It sets
// X-Forwarded-* headers and turns an upstream failure into a 502 rather than a
// panic, so an upstream that is down does not take the proxy with it.
func newReverseProxy(target *url.URL, timeout time.Duration, logger *slog.Logger) *httputil.ReverseProxy {
	rp := &httputil.ReverseProxy{}

	// Rewrite rather than the deprecated Director (staticcheck SA1019, Go 1.26).
	// The difference is not cosmetic: Rewrite hands over both the inbound and
	// outbound requests, so SetXForwarded sets X-Forwarded-For/-Host/-Proto from
	// the connection gwaf actually saw and *overwrites* any the client sent.
	// Director-based proxies famously append to a client-supplied
	// X-Forwarded-For, which lets a client forge its own address in the
	// upstream's logs and access rules.
	rp.Rewrite = func(pr *httputil.ProxyRequest) {
		pr.SetURL(target)
		// SetURL rewrites the path against target; keep the upstream's expected
		// Host, which is what name-based virtual hosts route on.
		pr.Out.Host = target.Host
		pr.SetXForwarded()
	}

	rp.Transport = &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ResponseHeaderTimeout: timeout,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          256,
		ForceAttemptHTTP2:     true,
	}

	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		// A request that gwaf already allowed failing at the upstream is an
		// availability problem, not a security one, so it is logged plainly and
		// answered with a 502 rather than leaking the error to the client.
		logger.Warn("upstream error", "path", r.URL.Path, "err", err.Error())
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("Bad Gateway\n"))
	}
	return rp
}

// blockHandler writes the response for a blocked request. It does not tell the
// client which rule fired -- that names the defence for an attacker -- but with
// -v the rule is exposed in a header so an operator tuning the deployment can
// see it. The detail always reaches the log through decisionLogger.
func blockHandler(o options, logger *slog.Logger) middleware.BlockHandler {
	return func(w http.ResponseWriter, r *http.Request, d gwaf.Decision) {
		status := d.Status()
		if status == 0 {
			status = o.blockStatus
		}
		if o.verbose {
			w.Header().Set("X-Gwaf-Rule", d.RuleID().String())
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(status)
		_, _ = w.Write([]byte("Forbidden\n"))
	}
}

// decisionLogger records decisions. Blocks are always logged; allows only when
// -v is set, because logging every allowed request is a firehose an operator
// rarely wants and never wants by default.
func decisionLogger(o options, logger *slog.Logger) func(*http.Request, gwaf.Decision) {
	return func(r *http.Request, d gwaf.Decision) {
		if d.Blocked() {
			logger.Warn("blocked",
				"method", r.Method, "path", r.URL.Path, "remote", clientIP(r),
				"rule", d.RuleID().String(), "reason", d.Reason().String(),
				"msg", d.Message(), "severity", d.Severity().String())
			return
		}
		if o.verbose {
			logger.Info("allowed", "method", r.Method, "path", r.URL.Path, "score", d.Score())
		}
	}
}

// withHealth answers a liveness probe locally, before gwaf or the upstream, so a
// health check neither counts as traffic nor depends on the upstream being up.
func withHealth(path string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == path {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok\n"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func newLogger(jsonOut bool) *slog.Logger {
	if jsonOut {
		return slog.New(slog.NewJSONHandler(os.Stderr, nil))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, nil))
}

func failName(open bool) string {
	if open {
		return "open"
	}
	return "closed"
}

// clientIP reports the immediate peer. It deliberately does not trust
// X-Forwarded-For: deciding which proxy hop to believe is deployment policy the
// operator owns, and a naive trust is a spoofable audit record.
func clientIP(r *http.Request) string {
	if i := strings.LastIndexByte(r.RemoteAddr, ':'); i >= 0 {
		return r.RemoteAddr[:i]
	}
	return r.RemoteAddr
}
