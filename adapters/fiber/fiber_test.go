// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package fiber_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	fiberapp "github.com/gofiber/fiber/v2"
	"github.com/gsoultan/gwaf"
	gwaffiber "github.com/gsoultan/gwaf/adapters/fiber"
)

func newApp(t *testing.T, cfg ...gwaffiber.Config) *fiberapp.App {
	t.Helper()
	w, err := gwaf.New()
	if err != nil {
		t.Fatalf("gwaf.New: %v", err)
	}
	app := fiberapp.New(fiberapp.Config{DisableStartupMessage: true})
	app.Use(gwaffiber.Middleware(w, cfg...))
	app.Get("/search", func(c *fiberapp.Ctx) error {
		return c.SendString("results for " + c.Query("q"))
	})
	app.Post("/orders", func(c *fiberapp.Ctx) error {
		return c.Status(http.StatusCreated).JSON(fiberapp.Map{"ok": true})
	})
	return app
}

func do(t *testing.T, app *fiberapp.App, req *http.Request) (int, string) {
	t.Helper()
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// TestBlocksAttacks is the point of the package: gwaf's transaction API driven
// directly against a server that has no net/http types at all.
func TestBlocksAttacks(t *testing.T) {
	app := newApp(t)
	for _, target := range []string{
		"/search?q=1%27%20OR%201%3D1--",
		"/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
		"/search?q=x%3B%20cat%20/etc/passwd",
	} {
		code, _ := do(t, app, httptest.NewRequest(http.MethodGet, target, nil))
		if code != http.StatusForbidden {
			t.Errorf("%s: status = %d, want 403", target, code)
		}
	}
}

func TestBlocksAttacksInTheBody(t *testing.T) {
	app := newApp(t)
	req := httptest.NewRequest(http.MethodPost, "/orders",
		strings.NewReader(`{"q":"1' OR 1=1--"}`))
	req.Header.Set("Content-Type", "application/json")
	if code, _ := do(t, app, req); code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", code)
	}
}

func TestPassesBenignTraffic(t *testing.T) {
	app := newApp(t)

	code, body := do(t, app, httptest.NewRequest(http.MethodGet, "/search?q=running+shoes", nil))
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if !strings.Contains(body, "running shoes") {
		t.Errorf("handler output lost: %q", body)
	}

	req := httptest.NewRequest(http.MethodPost, "/orders",
		strings.NewReader(`{"sku":"SKU-1","qty":2}`))
	req.Header.Set("Content-Type", "application/json")
	code, body = do(t, app, req)
	if code != http.StatusCreated {
		t.Errorf("status = %d, want 201", code)
	}
	if body != `{"ok":true}` {
		t.Errorf("body = %q", body)
	}
}

func TestBlockedRequestDoesNotReachTheHandler(t *testing.T) {
	w, err := gwaf.New()
	if err != nil {
		t.Fatal(err)
	}
	reached := false
	app := fiberapp.New(fiberapp.Config{DisableStartupMessage: true})
	app.Use(gwaffiber.Middleware(w))
	app.Get("/x", func(c *fiberapp.Ctx) error {
		reached = true
		return c.SendString("ok")
	})

	code, _ := do(t, app, httptest.NewRequest(http.MethodGet, "/x?q=1%27%20OR%201%3D1--", nil))
	if reached {
		t.Error("the handler ran for a blocked request")
	}
	if code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", code)
	}
}

// TestResponseInspection covers the response phase driven from fasthttp.
func TestResponseInspection(t *testing.T) {
	w, err := gwaf.New()
	if err != nil {
		t.Fatal(err)
	}
	app := fiberapp.New(fiberapp.Config{DisableStartupMessage: true})
	app.Use(gwaffiber.Middleware(w, gwaffiber.Config{InspectResponse: true}))
	app.Get("/key", func(c *fiberapp.Ctx) error {
		return c.SendString("-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n")
	})
	app.Get("/ok", func(c *fiberapp.Ctx) error {
		return c.JSON(fiberapp.Map{"id": 42})
	})

	code, body := do(t, app, httptest.NewRequest(http.MethodGet, "/key", nil))
	if code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", code)
	}
	if strings.Contains(body, "PRIVATE KEY") {
		t.Error("the private key reached the client")
	}

	if code, _ := do(t, app, httptest.NewRequest(http.MethodGet, "/ok", nil)); code != http.StatusOK {
		t.Errorf("benign response: status = %d, want 200", code)
	}
}

// TestOnDecisionSeesEveryRequest is where an embedder wires metrics: gwaf
// produces findings and the embedder decides what they mean.
func TestOnDecisionSeesEveryRequest(t *testing.T) {
	w, err := gwaf.New()
	if err != nil {
		t.Fatal(err)
	}
	var seen int
	app := fiberapp.New(fiberapp.Config{DisableStartupMessage: true})
	app.Use(gwaffiber.Middleware(w, gwaffiber.Config{
		OnDecision: func(*fiberapp.Ctx, gwaf.Decision) { seen++ },
	}))
	app.Get("/x", func(c *fiberapp.Ctx) error { return c.SendString("ok") })

	do(t, app, httptest.NewRequest(http.MethodGet, "/x?q=hello", nil))
	do(t, app, httptest.NewRequest(http.MethodGet, "/x?q=1%27%20OR%201%3D1--", nil))
	if seen < 2 {
		t.Errorf("OnDecision fired %d times, want at least 2", seen)
	}
}
