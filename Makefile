# Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

GO      ?= go
FUZZTIME ?= 30s

.DEFAULT_GOAL := check

## check: everything CI runs.
.PHONY: check
check: fmt-check vet lint test race deps

## fmt: format the tree.
.PHONY: fmt
fmt:
	gofmt -s -w .

## fmt-check: fail if anything is unformatted.
.PHONY: fmt-check
fmt-check:
	@out=$$(gofmt -s -l .); \
	if [ -n "$$out" ]; then echo "unformatted files:"; echo "$$out"; exit 1; fi

.PHONY: vet
vet:
	$(GO) vet ./...

## lint: staticcheck, when installed.
.PHONY: lint
lint:
	@if command -v staticcheck >/dev/null 2>&1; then \
		staticcheck ./...; \
	else \
		echo "staticcheck not installed; skipping (go install honnef.co/go/tools/cmd/staticcheck@latest)"; \
	fi

.PHONY: test
test:
	$(GO) test ./...

.PHONY: race
race:
	$(GO) test -race ./...

## corpus: detection rate and false-positive rate, reported together.
.PHONY: corpus
corpus:
	$(GO) test -run 'TestEvasionCorpus|TestBenignCorpus' -v . 2>&1 | \
		grep -E 'detection:|false positives:|NOT BLOCKED|FALSE POSITIVE'

## cover: coverage across all packages.
.PHONY: cover
cover:
	$(GO) test -coverprofile=coverage.out -coverpkg=./... ./...
	$(GO) tool cover -func=coverage.out | tail -1

## bench: run the benchmark suite.
.PHONY: bench
bench:
	$(GO) test -run=XXX -bench=. -benchmem ./...

## bench-save: record a baseline for regression comparison.
.PHONY: bench-save
bench-save:
	@mkdir -p bench
	$(GO) test -run=XXX -bench=. -benchmem -count=10 ./... > bench/baseline.txt
	@echo "baseline written to bench/baseline.txt"

## bench-check: compare against the recorded baseline. Requires benchstat.
##
## The SLOs in CLAUDE.md §2 are gated here. A >5% regression fails the build;
## see docs/PERFORMANCE.md.
.PHONY: bench-check
bench-check:
	@if [ ! -f bench/baseline.txt ]; then echo "no baseline; run 'make bench-save'"; exit 1; fi
	@if ! command -v benchstat >/dev/null 2>&1; then \
		echo "benchstat not installed (go install golang.org/x/perf/cmd/benchstat@latest)"; exit 1; \
	fi
	$(GO) test -run=XXX -bench=. -benchmem -count=10 ./... > /tmp/gwaf-bench-new.txt
	benchstat bench/baseline.txt /tmp/gwaf-bench-new.txt

## fuzz: run every fuzz target for FUZZTIME each.
##
## Parsers and canonicalization take attacker input, so fuzzing them is a
## requirement rather than an extra (CLAUDE.md §4).
.PHONY: fuzz
fuzz:
	$(GO) test -run=XXX -fuzz=FuzzScan -fuzztime=$(FUZZTIME) ./internal/prefilter/
	$(GO) test -run=XXX -fuzz=FuzzTransforms -fuzztime=$(FUZZTIME) ./rules/transform/
	$(GO) test -run=XXX -fuzz=FuzzIndexFold -fuzztime=$(FUZZTIME) ./rules/op/
	$(GO) test -run=XXX -fuzz=FuzzBuild -fuzztime=$(FUZZTIME) ./internal/interpret/
	$(GO) test -run=XXX -fuzz=FuzzValidateInert -fuzztime=$(FUZZTIME) ./schema/
	$(GO) test -run=XXX -fuzz=FuzzAnalyze -fuzztime=$(FUZZTIME) ./detect/sqli/
	$(GO) test -run=XXX -fuzz=FuzzAnalyze -fuzztime=$(FUZZTIME) ./detect/xss/

## vuln: check dependencies and stdlib for known vulnerabilities.
.PHONY: vuln
vuln:
	@if command -v govulncheck >/dev/null 2>&1; then \
		govulncheck ./...; \
	else \
		echo "govulncheck not installed (go install golang.org/x/vuln/cmd/govulncheck@latest)"; exit 1; \
	fi

## deps: assert the core module has no third-party dependencies.
##
## The dependency count of the core module is a tracked KPI (CLAUDE.md §4):
## anything an embedder inherits from gwaf is a supply-chain liability they did
## not choose. Integrations live in their own modules for this reason.
.PHONY: deps
deps:
	@deps=$$($(GO) list -deps ./... | grep -v '^github.com/gsoultan/gwaf' | grep '\.' | grep -v '^golang.org/x/' || true); \
	if [ -n "$$deps" ]; then \
		echo "core module gained third-party dependencies:"; echo "$$deps"; exit 1; \
	fi; \
	echo "core module dependencies: 0 third-party"

## help: list targets.
.PHONY: help
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## //'
