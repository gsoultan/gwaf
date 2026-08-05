// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package budget

import "testing"

func TestMeterSpend(t *testing.T) {
	var m Meter
	m.Reset(100)

	if !m.Spend(60) {
		t.Fatal("first spend failed")
	}
	if got := m.Remaining(); got != 40 {
		t.Errorf("Remaining() = %d, want 40", got)
	}
	if got := m.Spent(); got != 60 {
		t.Errorf("Spent() = %d, want 60", got)
	}
	if m.Exhausted() {
		t.Error("Exhausted() = true before the budget ran out")
	}
}

func TestMeterExhaustion(t *testing.T) {
	var m Meter
	m.Reset(100)

	if m.Spend(101) {
		t.Error("overspend reported success")
	}
	if !m.Exhausted() {
		t.Error("Exhausted() = false after overspend")
	}
	if got := m.Remaining(); got != 0 {
		t.Errorf("Remaining() = %d, want 0", got)
	}
}

// TestExhaustionIsSticky covers the security property: once the budget is gone,
// evaluation must not resume. Continuing would produce a decision derived from
// a partially evaluated ruleset, which is indistinguishable from a bypass.
func TestExhaustionIsSticky(t *testing.T) {
	var m Meter
	m.Reset(10)

	if m.Spend(20) {
		t.Fatal("overspend reported success")
	}
	if m.Spend(0) {
		t.Error("a zero-cost spend resumed an exhausted meter")
	}
	if m.Spend(1) {
		t.Error("a later spend resumed an exhausted meter")
	}
}

// TestDeterminism is the property that makes fuel usable where wall-clock is
// not: identical work always consumes identical fuel, so a budget violation
// reproduces in a test.
func TestDeterminism(t *testing.T) {
	const ops = 50
	var first Fuel

	for run := range 100 {
		var m Meter
		m.Reset(DefaultLimit)
		for i := range ops {
			m.Spend(Fuel(i%7) + CostRuleDispatch)
		}
		if run == 0 {
			first = m.Spent()
			continue
		}
		if got := m.Spent(); got != first {
			t.Fatalf("run %d spent %d, first run spent %d", run, got, first)
		}
	}
}

func TestUnmetered(t *testing.T) {
	var m Meter
	m.Reset(0)

	if !m.Unmetered() {
		t.Error("Unmetered() = false for a zero limit")
	}
	if !m.Spend(1 << 40) {
		t.Error("unmetered Spend failed")
	}
	if m.Exhausted() {
		t.Error("unmetered meter reported exhaustion")
	}
	if got := m.Spent(); got != 0 {
		t.Errorf("Spent() = %d, want 0 when unmetered", got)
	}
}

func TestResetClearsExhaustion(t *testing.T) {
	var m Meter
	m.Reset(10)
	m.Spend(20)

	m.Reset(100)
	if m.Exhausted() {
		t.Error("Reset did not clear exhaustion")
	}
	if !m.Spend(50) {
		t.Error("Spend failed after Reset")
	}
}

// TestNoOverflowOnHugeSpend guards the arithmetic: a very large charge must
// exhaust the meter rather than wrap negative and appear to succeed.
func TestNoOverflowOnHugeSpend(t *testing.T) {
	var m Meter
	m.Reset(100)

	if m.Spend(1 << 62) {
		t.Error("an enormous spend reported success")
	}
	if !m.Exhausted() {
		t.Error("an enormous spend did not exhaust the meter")
	}
}
