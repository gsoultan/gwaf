// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Package gin protects a Gin router with gwaf.
//
//	r := gin.Default()
//	r.Use(gwafgin.Middleware(waf))
//
// Two lines, which is the contract in CLAUDE.md §2b: if protecting a handler
// takes more, the API is wrong.
//
// # Why this is a separate module, and why it is this small
//
// Gin is a dependency somebody chose for their router, not one they should
// inherit from a firewall. Anyone using chi, gorilla/mux, connect-go, or the
// standard library needs nothing from here — `middleware.HTTP` is already a
// `func(http.Handler) http.Handler` and composes with all of them directly.
// Shipping an adapter package for each of those would be duplication dressed as
// integration.
//
// Gin needs an adapter only because gin.HandlerFunc is not http.Handler. The
// whole of that adaptation is below: gin.Context carries the underlying
// http.ResponseWriter and *http.Request, so the real middleware runs unchanged
// and this file just plumbs the continuation.
package gin

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/middleware"
)

// Middleware returns Gin middleware that runs a request through waf.
//
// Options are the net/http middleware's, so blocking behaviour, decision
// callbacks, and response inspection are configured identically whichever
// router is in front of them. There is one implementation of the integration
// semantics, which is the point of keeping this file thin.
func Middleware(waf *gwaf.WAF, opts ...middleware.Option) gin.HandlerFunc {
	wrap := middleware.HTTP(waf, opts...)

	return func(c *gin.Context) {
		// blocked stays false unless the wrapped handler runs, which is how the
		// adapter learns what the middleware decided without the middleware
		// needing to know about Gin.
		reached := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached = true
			// The middleware may have replaced the writer to inspect the
			// response, and it may have restored a re-readable body. Both have
			// to reach the handler, so the context is updated rather than
			// bypassed.
			c.Writer = ginWriter{ResponseWriter: c.Writer, w: w}
			c.Request = r
		})

		wrap(next).ServeHTTP(c.Writer, c.Request)

		if !reached {
			// gwaf blocked and the response is already written. Abort stops the
			// chain without writing a second status.
			c.Abort()
			return
		}
		c.Next()
	}
}

// ginWriter satisfies gin.ResponseWriter while writing through the middleware's
// writer, so response inspection sees what the handler produced.
type ginWriter struct {
	gin.ResponseWriter
	w http.ResponseWriter
}

func (g ginWriter) Write(b []byte) (int, error) { return g.w.Write(b) }
func (g ginWriter) WriteHeader(code int)        { g.w.WriteHeader(code) }
func (g ginWriter) Header() http.Header         { return g.w.Header() }
func (g ginWriter) WriteString(s string) (int, error) {
	return g.w.Write([]byte(s))
}
