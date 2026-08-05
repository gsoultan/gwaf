// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package gwaf_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/gsoultan/gwaf"
)

// respond drives a full request and response through a transaction.
func respond(t *testing.T, w *gwaf.WAF, status int, headers map[string]string, body string) gwaf.Decision {
	t.Helper()

	tx := w.NewTransaction()
	defer tx.Close()

	tx.SetRequestLine("GET", "/api/v1/orders", "HTTP/1.1")
	if d := tx.ProcessRequestHeaders(); d.Blocked() {
		return d
	}

	tx.SetResponseStatus(status)
	for k, v := range headers {
		tx.AddResponseHeader(k, v)
	}
	if d := tx.ProcessResponseHeaders(); d.Blocked() {
		return d
	}
	if body != "" {
		if d := tx.WriteResponseBody([]byte(body)); d.Blocked() {
			return d
		}
	}
	return tx.ProcessResponseBody()
}

// TestResponseLeaksAreDetected covers what the response phase exists for: not
// "is this an attack" but "did the origin just disclose something".
func TestResponseLeaksAreDetected(t *testing.T) {
	w := newWAF(t)

	leaks := []struct{ name, body string }{
		{"rsa private key", "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----"},
		{"openssh private key", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNza..."},
		{"pkcs8 private key", "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADAN..."},
		{"go panic", "panic: runtime error: index out of range\n\ngoroutine 1 [running]:\nmain.main()"},
		{"python traceback", "Traceback (most recent call last):\n  File \"app.py\", line 42"},
		{"java stack", "java.lang.NullPointerException\n\tat java.lang.String.length(String.java:623)"},
		{"dotnet stack", "System.NullReferenceException: Object reference not set\n   at System.Web.Mvc"},
		{"php fatal", "Fatal error: Uncaught Error: Call to undefined function in /var/www/app.php"},
		{"mysql error", "You have an error in your SQL syntax; check the manual near ''"},
		{"postgres error", "PG::SyntaxError: ERROR: syntax error at or near \"UNION\""},
		{"pdo error", "SQLSTATE[42000]: Syntax error or access violation"},
		{"oracle error", "ORA-01756: quoted string not properly terminated"},
	}

	for _, l := range leaks {
		t.Run(l.name, func(t *testing.T) {
			d := respond(t, w, 500, map[string]string{"Content-Type": "text/plain"}, l.body)
			if !d.Blocked() {
				t.Errorf("leak not detected: %s", l.name)
			}
		})
	}
}

// TestBenignResponsesPass is the counterweight. Certificates are public,
// error messages that name no framework are ordinary, and an API that returns
// the word "panic" in prose is not leaking anything.
func TestBenignResponsesPass(t *testing.T) {
	w := newWAF(t)

	cases := []struct{ name, ctype, body string }{
		{"json payload", "application/json",
			`{"orders":[{"id":1,"total":42.00}],"page":1}`},
		{"public certificate", "application/x-pem-file",
			"-----BEGIN CERTIFICATE-----\nMIIDdzCCAl+gAwIBAgIE...\n-----END CERTIFICATE-----"},
		{"public key", "application/x-pem-file",
			"-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQ...\n-----END PUBLIC KEY-----"},
		{"generic error json", "application/json",
			`{"error":"not found","code":404}`},
		{"prose mentioning panic", "application/json",
			`{"note":"do not panic, the retry will handle it"}`},
		{"prose mentioning sql", "application/json",
			`{"help":"check your SQL syntax in the query builder"}`},
		{"html page", "text/html",
			"<!DOCTYPE html><html><body><h1>Orders</h1><p>42 total</p></body></html>"},
		{"empty", "application/json", ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := respond(t, w, 200, map[string]string{"Content-Type": c.ctype}, c.body)
			if d.Blocked() {
				t.Errorf("benign response blocked: rule=%d msg=%q", d.RuleID(), d.Message())
			}
		})
	}
}

// TestLeakInHeaderIsCaughtBeforeBody checks the property that makes the header
// phase worth having: a leak detectable from headers alone stops the response
// before a single byte is written, which is the only moment it can be stopped.
func TestLeakInHeaderIsCaughtBeforeBody(t *testing.T) {
	w := newWAF(t)

	tx := w.NewTransaction()
	defer tx.Close()

	tx.SetRequestLine("GET", "/api", "HTTP/1.1")
	tx.ProcessRequestHeaders()
	tx.SetResponseStatus(500)
	tx.AddResponseHeader("X-Debug-Error", "ORA-01756: quoted string not properly terminated")

	d := tx.ProcessResponseHeaders()
	if !d.Blocked() {
		t.Error("a leak in a response header was not caught at the header phase")
	}
}

// TestResponseBodyStreamsInChunks verifies that an embedder can feed gwaf
// incrementally rather than handing it a whole buffer, which is what lets a
// proxy avoid buffering.
func TestResponseBodyStreamsInChunks(t *testing.T) {
	w := newWAF(t)

	tx := w.NewTransaction()
	defer tx.Close()

	tx.SetRequestLine("GET", "/api", "HTTP/1.1")
	tx.ProcessRequestHeaders()
	tx.SetResponseStatus(200)
	tx.AddResponseHeader("Content-Type", "text/plain")
	tx.ProcessResponseHeaders()

	// A payload split across chunk boundaries: no single chunk contains it.
	for _, chunk := range []string{
		"some output\n-----BEGIN RSA ", "PRIVATE KEY-----\nMIIEow...",
	} {
		if d := tx.WriteResponseBody([]byte(chunk)); d.Blocked() {
			t.Fatalf("unexpected block mid-stream: %v", d)
		}
	}

	if d := tx.ProcessResponseBody(); !d.Blocked() {
		t.Error("a leak spanning two chunks was not detected")
	}
}

// TestGwafNeverBuffers is the boundary as a test. gwaf holds only what it was
// given; an embedder that streams and passes nothing gets no claim about the
// body, rather than a claim that it was clean.
func TestGwafNeverBuffers(t *testing.T) {
	w := newWAF(t)

	tx := w.NewTransaction()
	defer tx.Close()

	tx.SetRequestLine("GET", "/api", "HTTP/1.1")
	tx.ProcessRequestHeaders()
	tx.SetResponseStatus(200)
	tx.ProcessResponseHeaders()

	// No WriteResponseBody call at all: the embedder streamed straight to the
	// client and chose not to share the body.
	d := tx.ProcessResponseBody()
	if d.Blocked() {
		t.Error("gwaf blocked a response it was never shown")
	}
	if d.Reason() != gwaf.ReasonNoMatch {
		t.Errorf("Reason() = %v", d.Reason())
	}
}

// ---- developer experience ---------------------------------------------------

// TestDecisionLogsAsStructuredFields checks the first thing any embedder does
// with a Decision.
func TestDecisionLogsAsStructuredFields(t *testing.T) {
	w := newWAF(t)
	d := run(t, w, req{args: map[string]string{"id": "1' OR 1=1--"}})
	if !d.Blocked() {
		t.Fatal("expected a block to log")
	}

	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Warn("blocked", "waf", d)

	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("log output is not valid JSON: %v", err)
	}
	waf, ok := got["waf"].(map[string]any)
	if !ok {
		t.Fatalf("waf group missing from log: %s", buf.String())
	}

	// Every field an operator needs to triage without opening the code.
	for _, key := range []string{
		"verdict", "reason", "rule", "msg", "severity", "confidence",
		"target", "rules_evaluated",
	} {
		if _, ok := waf[key]; !ok {
			t.Errorf("log is missing %q: %v", key, waf)
		}
	}
}

func TestDecisionStringIsUseful(t *testing.T) {
	w := newWAF(t)
	d := run(t, w, req{args: map[string]string{"id": "1' OR 1=1--"}})

	s := d.String()
	for _, want := range []string{"block", "reason=", "rule="} {
		if !strings.Contains(s, want) {
			t.Errorf("String() = %q, want it to contain %q", s, want)
		}
	}
	if strings.Contains(s, "\n") {
		t.Errorf("String() spans lines, which breaks grep: %q", s)
	}
}
