// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/gsoultan/gwaf/calibrate"
)

func TestDraftSchemaDescribesTheCorpusAndKeepsNoValue(t *testing.T) {
	var corpus []calibrate.Request
	for i := range 30 {
		corpus = append(corpus, calibrate.Request{
			Target: fmt.Sprintf("/orders/%d?page=%d", 500+i, i),
			Args:   map[string]string{"token": fmt.Sprintf("secret-token-%04d", i)},
		})
	}
	corpus = append(corpus, calibrate.Request{Target: "/seen-once"})

	var out, diag bytes.Buffer
	if err := draftSchema(&out, &diag, corpus, 20); err != nil {
		t.Fatal(err)
	}

	var doc struct {
		Paths map[string]map[string]struct {
			Parameters []struct {
				Name, In string
				Schema   struct{ Type string }
			}
		}
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("the draft is not JSON: %v\n%s", err, out.String())
	}
	get, ok := doc.Paths["/orders/{id}"]["get"]
	if !ok || len(doc.Paths) != 1 {
		t.Fatalf("drafted paths %v, want only /orders/{id}", doc.Paths)
	}
	types := map[string]string{}
	for _, p := range get.Parameters {
		types[p.In+":"+p.Name] = p.Schema.Type
	}
	want := map[string]string{"path:id": "string", "query:page": "integer", "query:token": "string"}
	if fmt.Sprint(types) != fmt.Sprint(want) {
		t.Errorf("parameters %v, want %v", types, want)
	}
	if strings.Contains(out.String(), "secret-token") {
		t.Error("the draft contains a value from the corpus")
	}
	if !strings.Contains(diag.String(), "drafted 1 operations from 31 of 31 requests") {
		t.Errorf("the summary does not account for the corpus:\n%s", diag.String())
	}
}

func TestDraftSchemaSaysWhenThereIsNothingToDraft(t *testing.T) {
	var out, diag bytes.Buffer
	err := draftSchema(&out, &diag, []calibrate.Request{{Target: "/a"}}, 20)
	if err == nil || out.Len() != 0 {
		t.Errorf("err %v and %d bytes written, want an error and no document", err, out.Len())
	}
	if err := draftSchema(&out, &diag, nil, 0); err == nil {
		t.Error("a -min-samples of 0 was accepted")
	}
}
