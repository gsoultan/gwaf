// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package leaks

import "testing"

// The numbers below are the brands' published test numbers. Each satisfies Luhn
// and none has ever been issued.
func TestCardNumberDetectsEveryBrand(t *testing.T) {
	for _, tc := range []struct{ brand, pan string }{
		{"visa-16", "4111111111111111"},
		{"visa-13", "4222222222222"},
		{"visa-19", "4111111111111111110"},
		{"mastercard", "5555555555554444"},
		{"mastercard-2series", "2223003122003222"},
		{"amex-34", "signature 341111111111111 on file"},
		{"amex-37", "378282246310005"},
		{"discover", "6011111111111117"},
		{"discover-65", "6511111111111112"},
		{"jcb", "3530111333300000"},
		{"diners", "30569309025904"},
		{"diners-36", "36227206271667"},
		{"unionpay", "6212341111111117"},
	} {
		t.Run(tc.brand, func(t *testing.T) {
			if _, ok := CardNumber().Eval(nil, []byte(tc.pan)); !ok {
				t.Errorf("missed a %s card: %q", tc.brand, tc.pan)
			}
		})
	}
}

// TestCardNumberToleratesFormatting covers the way a card is written when a
// human is meant to read it, which is how an invoice or a receipt leaks one.
func TestCardNumberToleratesFormatting(t *testing.T) {
	for _, pan := range []string{
		"4111 1111 1111 1111",
		"4111-1111-1111-1111",
		"3782 822463 10005",
		`{"card":"5555555555554444"}`,
		"Paid with 4111111111111111.",
		"<td>4111 1111 1111 1111</td>",
	} {
		t.Run(pan, func(t *testing.T) {
			if _, ok := CardNumber().Eval(nil, []byte(pan)); !ok {
				t.Errorf("missed a formatted card: %q", pan)
			}
		})
	}
}

// TestCardNumberIgnoresLookalikes is the half that matters most in production.
// Every one of these matches the Visa-shaped regex usually written for this.
func TestCardNumberIgnoresLookalikes(t *testing.T) {
	for _, tc := range []struct{ name, value string }{
		{"order id starting with 4", "4000000000000000"},
		{"sixteen digits, bad check digit", "4111111111111112"},
		{"microsecond timestamp", "1755678901234567"},
		{"unassigned prefix", "9999999999999995"},
		{"amex prefix at mastercard length", "3411111111111111"},
		{"mastercard prefix at amex length", "551111111111116"},
		{"too short", "411111111111"},
		{"too long", "41111111111111111111"},
		{"embedded in a longer digit run", "99441111111111111199"},
		{"sha-like hex", "4f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c"},
		{"phone number", "+1 415 555 0100"},
		{"empty", ""},
		{"no digits at all", "no card numbers here"},
		{"maestro, a stated gap", "6759649826438453"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := CardNumber().Eval(nil, []byte(tc.value)); ok {
				t.Errorf("false positive on %s: %q", tc.name, tc.value)
			}
		})
	}
}

// TestCardNumberReportsTheMatchedSpan checks the operator locates the card
// rather than pointing at the whole body. The span is what an audit entry shows
// and what a redacting action would need.
func TestCardNumberReportsTheMatchedSpan(t *testing.T) {
	value := []byte(`{"name":"ada","card":"4111 1111 1111 1111","cvv":"123"}`)
	m, ok := CardNumber().Eval(nil, value)
	if !ok {
		t.Fatal("card not found")
	}
	if got := string(value[m.Span.Off:m.Span.End()]); got != "4111 1111 1111 1111" {
		t.Errorf("span covers %q, want the card number", got)
	}
}

func TestLuhnValid(t *testing.T) {
	digits := func(s string) []byte {
		out := make([]byte, len(s))
		for i := range s {
			out[i] = s[i] - '0'
		}
		return out
	}
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"4111111111111111", true},
		{"4111111111111112", false},
		{"79927398713", true},
		{"79927398710", false},
		{"0", true},
	} {
		if got := luhnValid(digits(tc.in)); got != tc.want {
			t.Errorf("luhnValid(%s) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func BenchmarkCardNumberScan(b *testing.B) {
	// A page-sized body with the card at the far end, so the benchmark measures
	// the scan rather than an early exit.
	body := make([]byte, 0, 64<<10)
	for len(body) < 64<<10 {
		body = append(body, `{"id":1755678901234567,"name":"ada lovelace","note":"no card here"},`...)
	}
	body = append(body, `{"card":"4111111111111111"}`...)
	op := CardNumber()

	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	for b.Loop() {
		if _, ok := op.Eval(nil, body); !ok {
			b.Fatal("card not found")
		}
	}
}
