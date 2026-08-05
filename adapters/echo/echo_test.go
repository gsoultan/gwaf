// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package echo_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gsoultan/gwaf"
	gwafecho "github.com/gsoultan/gwaf/adapters/echo"
	echorouter "github.com/labstack/echo/v4"
)

func newServer(t *testing.T) *echorouter.Echo {
	t.Helper()
	w, err := gwaf.New()
	if err != nil {
		t.Fatalf("gwaf.New: %v", err)
	}
	e := echorouter.New()
	e.Use(gwafecho.Middleware(w))
	e.GET("/search", func(c echorouter.Context) error {
		return c.String(http.StatusOK, "results for "+c.QueryParam("q"))
	})
	e.POST("/orders", func(c echorouter.Context) error {
		return c.JSON(http.StatusCreated, map[string]bool{"ok": true})
	})
	return e
}

func TestBlocksAttacks(t *testing.T) {
	e := newServer(t)
	for _, target := range []string{
		"/search?q=1%27%20OR%201%3D1--",
		"/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
		"/search?q=x%3B%20cat%20/etc/passwd",
	} {
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: status = %d, want 403", target, rec.Code)
		}
	}
}

func TestPassesBenignTraffic(t *testing.T) {
	e := newServer(t)

	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/search?q=running+shoes", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "running shoes") {
		t.Errorf("handler output lost: %q", rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/orders",
		strings.NewReader(`{"sku":"SKU-1","qty":2}`))
	req.Header.Set("Content-Type", "application/json")
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201", rec.Code)
	}
}

// TestHandlerErrorIsReturned covers Echo's contract: a middleware returns the
// handler's error, and swallowing it would lose the application's own error
// handling.
func TestHandlerErrorIsReturned(t *testing.T) {
	w, err := gwaf.New()
	if err != nil {
		t.Fatal(err)
	}
	e := echorouter.New()
	e.Use(gwafecho.Middleware(w))
	e.GET("/boom", func(c echorouter.Context) error {
		return echorouter.NewHTTPError(http.StatusTeapot, "brewing")
	})

	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/boom", nil))
	if rec.Code != http.StatusTeapot {
		t.Errorf("status = %d, want 418: the handler's error was swallowed", rec.Code)
	}
}

func TestBlockedRequestDoesNotReachTheHandler(t *testing.T) {
	w, err := gwaf.New()
	if err != nil {
		t.Fatal(err)
	}
	reached := false
	e := echorouter.New()
	e.Use(gwafecho.Middleware(w))
	e.GET("/x", func(c echorouter.Context) error {
		reached = true
		return c.String(http.StatusOK, "ok")
	})

	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x?q=1%27%20OR%201%3D1--", nil))
	if reached {
		t.Error("the handler ran for a blocked request")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}
