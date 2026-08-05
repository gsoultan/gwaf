// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package gin_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ginrouter "github.com/gin-gonic/gin"
	"github.com/gsoultan/gwaf"
	gwafgin "github.com/gsoultan/gwaf/adapters/gin"
)

func newRouter(t *testing.T) *ginrouter.Engine {
	t.Helper()
	ginrouter.SetMode(ginrouter.TestMode)

	w, err := gwaf.New()
	if err != nil {
		t.Fatalf("gwaf.New: %v", err)
	}
	r := ginrouter.New()
	r.Use(gwafgin.Middleware(w))
	r.GET("/search", func(c *ginrouter.Context) {
		c.String(http.StatusOK, "results for %s", c.Query("q"))
	})
	r.POST("/orders", func(c *ginrouter.Context) {
		c.JSON(http.StatusCreated, ginrouter.H{"ok": true})
	})
	return r
}

func TestBlocksAttacks(t *testing.T) {
	r := newRouter(t)
	for _, target := range []string{
		"/search?q=1%27%20OR%201%3D1--",
		"/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
		"/search?q=x%3B%20cat%20/etc/passwd",
	} {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: status = %d, want 403", target, rec.Code)
		}
	}
}

func TestPassesBenignTraffic(t *testing.T) {
	r := newRouter(t)

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/search?q=running+shoes", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "running shoes") {
		t.Errorf("handler output lost: %q", rec.Body.String())
	}

	// The handler's own status and body survive the adapter.
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/orders",
		strings.NewReader(`{"sku":"SKU-1","qty":2}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201", rec.Code)
	}
	if rec.Body.String() != `{"ok":true}` {
		t.Errorf("body = %q", rec.Body.String())
	}
}

// TestBlockedRequestDoesNotReachTheHandler is the property that matters: a
// firewall that runs the handler and then discards its output has already let
// the side effects happen.
func TestBlockedRequestDoesNotReachTheHandler(t *testing.T) {
	ginrouter.SetMode(ginrouter.TestMode)
	w, err := gwaf.New()
	if err != nil {
		t.Fatal(err)
	}
	reached := false
	r := ginrouter.New()
	r.Use(gwafgin.Middleware(w))
	r.GET("/x", func(c *ginrouter.Context) {
		reached = true
		c.String(http.StatusOK, "ok")
	})

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x?q=1%27%20OR%201%3D1--", nil))
	if reached {
		t.Error("the handler ran for a blocked request")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}
