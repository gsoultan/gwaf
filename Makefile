# Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

GO      ?= go
FUZZTIME ?= 30s

# gwaf is multi-module by design: integrations live outside the core module so
# that importing gwaf never drags in a framework somebody did not choose
# (CLAUDE.md §3). Every target that walks the tree has to walk all of them, or
# the split silently stops being checked -- which is worse than not splitting,
# because the invariant then only appears to hold.
MODULES ?= . ./middleware ./examples ./schema/openapi ./schema/grpc ./seclang \
           ./adapters/gin ./adapters/echo ./adapters/fiber \
           ./test/extension

# Tools are resolved through GOPATH/bin as well as PATH.
#
# `go install` puts binaries in GOPATH/bin, which is frequently not on PATH in a
# make shell even when it is in the developer's interactive shell. The lint
# target used to probe with `command -v staticcheck` and print "not installed;
# skipping" when it missed -- so on a machine where staticcheck was installed and
# working, every `make check` silently skipped it and still reported success.
# A security tool that is optional is a security tool that is off.
GOBIN        := $(shell $(GO) env GOPATH)/bin
STATICCHECK  := $(shell command -v staticcheck 2>/dev/null || echo $(GOBIN)/staticcheck)
GOVULNCHECK  := $(shell command -v govulncheck 2>/dev/null || echo $(GOBIN)/govulncheck)

.DEFAULT_GOAL := check

## check: everything CI runs, including the security scanners.
##
## vuln and lint are part of this rather than separate targets somebody has to
## remember. gwaf is security infrastructure (CLAUDE.md §4); a gate that omits
## the vulnerability scan is a gate that reports a clean run it did not perform.
.PHONY: check
check: fmt-check vet lint test race deps calibrate lint-rules vuln

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
	@for m in $(MODULES); do \
		echo "vet $$m"; (cd $$m && $(GO) vet ./...) || exit 1; \
	done

## lint: staticcheck across every module. Required, never skipped.
##
## This used to skip when the binary was not on PATH, and that is exactly how it
## failed: staticcheck was installed in GOPATH/bin the whole time, `command -v`
## missed it, and every run printed "skipping" next to a passing gate. An
## analyser that quietly opts out is worse than one that was never wired up,
## because the green tick says it ran.
.PHONY: lint
lint:
	@if [ ! -x "$(STATICCHECK)" ]; then \
		echo "staticcheck not found at $(STATICCHECK)"; \
		echo "install: go install honnef.co/go/tools/cmd/staticcheck@latest"; \
		exit 1; \
	fi
	@for m in $(MODULES); do \
		echo "staticcheck $$m"; (cd $$m && $(STATICCHECK) ./...) || exit 1; \
	done

.PHONY: test
test:
	@for m in $(MODULES); do \
		echo "test $$m"; (cd $$m && $(GO) test ./...) || exit 1; \
	done

.PHONY: race
race:
	@for m in $(MODULES); do \
		echo "race $$m"; (cd $$m && $(GO) test -race ./...) || exit 1; \
	done

## calibrate: measure each rule's false-positive rate against the benign corpus.
##
## Confidence is a measured property, not an authored one (docs/CONCEPT.md §8).
## A rule declaring more precision than the corpus supports fails here rather
## than in production. The tool also reports what the corpus *cannot* measure;
## the fix for that is always more corpus, never a looser ceiling.
.PHONY: calibrate
calibrate:
	$(GO) run ./cmd/gwaf calibrate

## lint: report prefilter coverage and the cost of unconditional rules.
.PHONY: lint-rules
lint-rules:
	$(GO) run ./cmd/gwaf lint

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

## bench-publish: everything docs/BENCHMARKS.md reports, with provenance.
##
## Prints the hardware and toolchain first, because a benchmark without them is
## a number nobody can disagree with -- and a number nobody can disagree with is
## not evidence.
.PHONY: bench-publish
bench-publish:
	@echo "# gwaf benchmarks"
	@echo "# commit:  $$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
	@echo "# go:      $$($(GO) version)"
	@echo "# host:    $$(uname -srm)"
	@echo "# cpu:     $$(sysctl -n machdep.cpu.brand_string 2>/dev/null || \
	                    grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2- || echo unknown)"
	@echo
	@GWAF_BENCH_REPORT=1 $(GO) test -run='TestLatencyDistribution|TestSLO' -v . \
		| grep -E 'workload|ns|µs|ms|heap growth|--- (PASS|FAIL)' || true
	@echo
	@$(GO) test -run=XXX -bench=. -benchmem -count=5 . | grep -E '^(Benchmark|ok|PASS)'
	@echo
	@$(GO) test -run='TestEvasionCorpus$$|TestBenignCorpus$$' -v . \
		| grep -E 'detection:|false positives:' || true
	@$(GO) run ./cmd/gwaf calibrate 2>&1 | grep -E 'corpus:|power:|every rule' || true

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
	$(GO) test -run=XXX -fuzz=FuzzParseJSON -fuzztime=$(FUZZTIME) ./internal/body/
	$(GO) test -run=XXX -fuzz=FuzzParseForm -fuzztime=$(FUZZTIME) ./internal/body/
	$(GO) test -run=XXX -fuzz=FuzzParseMultipart -fuzztime=$(FUZZTIME) ./internal/body/

## vuln: check every module's dependencies and the stdlib for known CVEs.
##
## Every module, not just the root one, and the distinction is the whole point.
## The core module has zero third-party dependencies by design (CLAUDE.md §4),
## so scanning it alone scans the one place that cannot have a dependency
## vulnerability. Everything an adopter actually pulls in -- gin, echo, fiber,
## the SecLang and OpenAPI frontends -- lives in the modules this used to skip.
##
## Runs inside `make check` rather than as a target somebody remembers, because
## we ship security infrastructure and a scan nobody runs is not a control.
.PHONY: vuln
vuln:
	@if [ ! -x "$(GOVULNCHECK)" ]; then \
		echo "govulncheck not found at $(GOVULNCHECK)"; \
		echo "install: go install golang.org/x/vuln/cmd/govulncheck@latest"; \
		exit 1; \
	fi
	@for m in $(MODULES); do \
		echo "govulncheck $$m"; (cd $$m && $(GOVULNCHECK) ./...) || exit 1; \
	done

## deps: assert the core module has no third-party dependencies.
##
## The dependency count of the core module is a tracked KPI (CLAUDE.md §4):
## anything an embedder inherits from gwaf is a supply-chain liability they did
## not choose. Integrations that need a dependency live in their own modules.
##
## Two checks, because either alone can be fooled. go.mod is the declaration;
## the package walk is what actually gets linked. The walk uses `.Standard`
## rather than matching import paths, because the standard library vendors
## packages under paths like `vendor/golang.org/x/net/...` that look
## third-party and are not -- net/http pulls several in.
.PHONY: deps
deps:
	@reqs=$$($(GO) list -m -f '{{if not .Main}}{{.Path}}{{end}}' all | grep -v '^$$' || true); \
	if [ -n "$$reqs" ]; then \
		echo "core module declares third-party modules:"; echo "$$reqs"; exit 1; \
	fi
	@pkgs=$$($(GO) list -deps -f '{{if not .Standard}}{{.ImportPath}}{{end}}' ./... \
		| grep -v '^github.com/gsoultan/gwaf' || true); \
	if [ -n "$$pkgs" ]; then \
		echo "core module links non-standard packages:"; echo "$$pkgs"; exit 1; \
	fi; \
	echo "core module dependencies: 0 third-party"

## help: list targets.
.PHONY: help
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## //'
