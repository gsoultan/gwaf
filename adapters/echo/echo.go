// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Package echo protects an Echo server with gwaf.
//
//	e := echo.New()
//	e.Use(gwafecho.Middleware(waf))
//
// # Why this is a separate module, and why it is this small
//
// Echo is a dependency somebody chose for their router, not one they should
// inherit from a firewall. Anyone using chi, gorilla/mux, connect-go, or the
// standard library needs nothing from here — `middleware.HTTP` is already a
// `func(http.Handler) http.Handler` and composes with all of them directly.
//
// Echo needs an adapter only because echo.HandlerFunc is not http.Handler. All
// of that adaptation is below: echo.Context exposes the underlying
// http.ResponseWriter and *http.Request, so the real middleware runs unchanged
// and the integration semantics stay in one place.
package echo

import (
	"net/http"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/middleware"
	"github.com/labstack/echo/v4"
)

// Middleware returns Echo middleware that runs a request through waf.
//
// Options are the net/http middleware's, so blocking behaviour, decision
// callbacks, and response inspection are configured identically whichever
// router is in front of them.
func Middleware(waf *gwaf.WAF, opts ...middleware.Option) echo.MiddlewareFunc {
	wrap := middleware.HTTP(waf, opts...)

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// handlerErr carries an error out of the inner http.Handler, which
			// has no way to return one. Echo's contract is that a middleware
			// returns the handler's error, and swallowing it would lose the
			// application's own error handling.
			var handlerErr error
			reached := false

			inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached = true
				// The middleware may have replaced the writer to inspect the
				// response and restored a re-readable body; both have to reach
				// the handler.
				c.SetRequest(r)
				c.Response().Writer = w
				handlerErr = next(c)
			})

			wrap(inner).ServeHTTP(c.Response().Writer, c.Request())

			if !reached {
				// gwaf blocked and the response is already written. Returning
				// nil stops the chain without Echo writing a second one.
				return nil
			}
			return handlerErr
		}
	}
}
