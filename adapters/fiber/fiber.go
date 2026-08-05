// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Package fiber protects a Fiber app with gwaf.
//
//	app := fiber.New()
//	app.Use(gwaffiber.Middleware(waf))
//
// # Why this one is real code and the others are not
//
// The Gin and Echo adapters are ten lines each because both routers carry an
// http.ResponseWriter and an *http.Request, so the net/http middleware runs
// unchanged underneath them.
//
// Fiber does not. It is built on fasthttp, which has no net/http types at all —
// no http.Request, no http.Header, no io.Reader body. Bridging through
// fasthttpadaptor would allocate a full http.Request per request and throw away
// the reason somebody chose Fiber.
//
// So this drives the transaction API directly, which is exactly what that API
// exists for. gwaf's core takes strings and byte slices and knows nothing about
// net/http; the middleware package is one integration built on it, and this is
// another. If the transaction API could not support a non-net/http server
// cleanly, that would be a tier-1 gap — this package is the evidence that it
// can.
//
// # What the embedder still owns
//
// Fiber reads the whole body before a handler runs, so the body is available
// here with no buffering decision to make. That is Fiber's choice, not gwaf's:
// on a streaming server the same code would feed WriteResponseBody in chunks or
// feed it nothing, and gwaf would report what it was shown rather than assuming
// the rest was clean.
package fiber

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gsoultan/gwaf"
)

// Config controls the adapter.
type Config struct {
	// OnBlock writes the response for a blocked request. When nil, a 403 with
	// no body is written — deliberately terse, because a block page that echoes
	// why is a block page that helps an attacker tune.
	OnBlock func(c *fiber.Ctx, d gwaf.Decision) error

	// OnDecision observes every decision, blocked or not. This is where an
	// embedder wires metrics and audit; gwaf produces findings and the embedder
	// decides what they mean.
	OnDecision func(c *fiber.Ctx, d gwaf.Decision)

	// InspectResponse runs the response phase over the body Fiber produced.
	//
	// Off by default. Fiber has the whole body in memory by the time a handler
	// returns, so there is no buffering cost here — but response inspection is
	// still a policy choice the embedder makes rather than one a firewall makes
	// for them.
	InspectResponse bool
}

// Middleware returns Fiber middleware that runs a request through waf.
func Middleware(waf *gwaf.WAF, cfg ...Config) fiber.Handler {
	var c Config
	if len(cfg) > 0 {
		c = cfg[0]
	}
	if c.OnBlock == nil {
		c.OnBlock = func(ctx *fiber.Ctx, d gwaf.Decision) error {
			return ctx.SendStatus(d.Status())
		}
	}

	return func(ctx *fiber.Ctx) error {
		tx := waf.NewTransaction()
		defer tx.Close()

		decide := func(d gwaf.Decision) error {
			if c.OnDecision != nil {
				c.OnDecision(ctx, d)
			}
			if d.Blocked() {
				return c.OnBlock(ctx, d)
			}
			return nil
		}

		req := ctx.Request()
		tx.SetRequestLine(
			string(req.Header.Method()),
			string(req.RequestURI()),
			string(req.Header.Protocol()),
		)
		tx.SetRemoteAddr(ctx.IP())

		// Header values are converted to strings because the transaction API
		// takes strings; fasthttp's buffers are reused after the handler
		// returns, so retaining a view into them would be a use-after-free the
		// moment anything held a decision past the request.
		req.Header.VisitAll(func(k, v []byte) {
			tx.AddRequestHeader(string(k), string(v))
		})

		if d := tx.ProcessRequestHeaders(); d.Blocked() {
			return decide(d)
		}

		if body := req.Body(); len(body) > 0 {
			tx.SetRequestBody(body)
		}
		if d := tx.ProcessRequestBody(); d.Blocked() {
			return decide(d)
		}
		if err := decide(tx.Decision()); err != nil {
			return err
		}

		if err := ctx.Next(); err != nil {
			return err
		}
		if !c.InspectResponse {
			return nil
		}

		resp := ctx.Response()
		tx.SetResponseStatus(resp.StatusCode())
		resp.Header.VisitAll(func(k, v []byte) {
			tx.AddResponseHeader(string(k), string(v))
		})
		if d := tx.ProcessResponseHeaders(); d.Blocked() {
			resp.ResetBody()
			return c.OnBlock(ctx, d)
		}
		if body := resp.Body(); len(body) > 0 {
			if d := tx.WriteResponseBody(body); d.Blocked() {
				resp.ResetBody()
				return c.OnBlock(ctx, d)
			}
		}
		if d := tx.ProcessResponseBody(); d.Blocked() {
			resp.ResetBody()
			return c.OnBlock(ctx, d)
		}
		return nil
	}
}
