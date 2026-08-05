// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Command basic is the smallest useful gwaf integration.
//
// Run it, then try:
//
//	curl 'localhost:8080/api/orders?id=12345'                 # 200
//	curl 'localhost:8080/api/orders?id=1%27+OR+1%3D1--'       # 403
//	curl 'localhost:8080/api/orders?id=abc'                   # 403, schema
package main

import (
	"encoding/json"
	"log"
	"log/slog"
	"net/http"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/middleware"
	"github.com/gsoultan/gwaf/schema"
)

func main() {
	// Describing the API is optional, but it is the highest-value thing an
	// embedder can do: out-of-spec requests are rejected before any rule runs,
	// and in-spec values of constrained types skip rule evaluation entirely.
	api, err := schema.New(schema.Operation{
		Method: "GET",
		Path:   "/api/orders",
		NoBody: true,
		Query: []schema.Field{
			{Name: "id", Kind: schema.KindInteger},
			{Name: "status", Kind: schema.KindEnum,
				Enum: []string{"pending", "shipped", "delivered"}},
			{Name: "note", Kind: schema.KindString, MaxLength: 500},
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	waf, err := gwaf.New(gwaf.WithSchema(api))
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/orders", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":     r.URL.Query().Get("id"),
			"status": "shipped",
		})
	})

	// The whole integration. Everything above is application code.
	handler := middleware.HTTP(waf,
		middleware.OnDecision(func(r *http.Request, d gwaf.Decision) {
			if !d.Blocked() {
				return
			}
			slog.Warn("blocked",
				"path", r.URL.Path,
				"rule", d.RuleID(),
				"reason", d.Reason(),
				"msg", d.Message(),
				// Says which alternative decoding found the payload, or "none"
				// when it was visible in the bytes as sent.
				"interpretation", d.Interpretation(),
				"detail", d.Detail())
		}),
	)(mux)

	log.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", handler))
}
