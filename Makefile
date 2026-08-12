# Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

GO      ?= go
FUZZTIME ?= 30s

# gwaf is multi-module by design: integrations live outside the core module so
# that importing gwaf never drags in a framework somebody did not choose
# (CLAUDE.md §3). Every target that walks the tree has to walk all of them, or
# the split silently stops being checked -- which is worse than not splitting,
# because the invariant then only appears to hold.
MODULES ?= . ./middleware ./examples ./schema/openapi ./schema/grpc ./seclang \
           ./adapters/gin ./adapters/echo ./adapters/fiber ./proxy \
           ./test/extension ./test/conformance

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
CYCLONEDX    := $(shell command -v cyclonedx-gomod 2>/dev/null || echo $(GOBIN)/cyclonedx-gomod)

# Pinned, not @latest. An SBOM generator is a supply-chain tool; resolving it to
# whatever was published this morning is the problem it exists to describe.
CYCLONEDX_VERSION := v1.9.0

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

## conformance: run the go-ftw suite.
##
## Bundled tests always run. The external OWASP CRS corpus is opt-in, because it
## is thousands of files this repository does not vendor and a suite that
## silently passes when its input is missing is worse than one that is absent:
##
##   git clone --depth 1 https://github.com/coreruleset/coreruleset /tmp/crs
##   CRS_TESTS=/tmp/crs/tests/regression/tests make conformance
##
## Add CRS_RULES=/tmp/crs/rules to switch to exact rule-ID comparison through
## the seclang bridge, which is the stricter claim.
.PHONY: conformance
conformance:
	@cd test/conformance && $(GO) test -v ./... 2>&1 | \
		grep -E 'conformance \[|loaded|--- (PASS|FAIL|SKIP)|^(ok|FAIL)'

## headtohead: gwaf vs Coraza + CRS on the same corpus. Requires a CRS checkout.
##
##   git clone --depth 1 https://github.com/coreruleset/coreruleset /tmp/crs
##   CRS_TESTS=/tmp/crs/tests/regression/tests CRS_RULES=/tmp/crs/rules make headtohead
##
## Read test/headtohead/README.md before quoting either number: each corpus is
## one engine's home turf, and both are reported for that reason.
.PHONY: headtohead
headtohead:
	@cd test/headtohead && $(GO) test -v -timeout 25m ./... 2>&1 | \
		grep -E 'detection|false positives|engine |gwaf |coraza|CAVEAT|^\s+[0-9]\.|--- (PASS|FAIL|SKIP)'

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

## bench-guard: refuse to measure on a machine that is already busy.
##
## A vulnerability scanner left running in another terminal made a benign GET
## read 880ns against a 734ns baseline -- a 20% "regression" that was entirely
## the scanner, and that a paired measurement (with and without the change, back
## to back) immediately showed was not real. Recording that number as the
## baseline would have raised the bar permanently and hidden a real regression
## later, which is the failure this guard exists to prevent.
##
## Set FORCE=1 to measure anyway. The threshold is a quarter of the cores,
## because a benchmark wants the machine, not a share of it.
.PHONY: bench-guard
bench-guard:
	@cpus=$$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 1); \
	load=$$(uptime | sed -e 's/.*load averages*://' -e 's/,/ /g' | awk '{print $$1}'); \
	if [ -n "$$FORCE" ]; then \
		echo "bench-guard: FORCE set, measuring at load $$load on $$cpus cores"; \
	else \
		awk -v l="$$load" -v c="$$cpus" 'BEGIN{ if (l > c/4) exit 1; exit 0 }' || { \
			echo "bench-guard: load $$load on $$cpus cores -- too busy to measure."; \
			echo "  A benchmark taken here is not comparable to the baseline, and"; \
			echo "  saving it would hide a future regression. Close what is running,"; \
			echo "  or set FORCE=1 if you know the number is only indicative."; \
			echo "  To judge a change without a quiet machine, measure it paired"; \
			echo "  (with and without, back to back) or use structural metrics:"; \
			echo "      go run ./cmd/gwaf lint   # literals, automaton states, unconditional"; \
			exit 1; \
		}; \
	fi

## bench: run the benchmark suite.
.PHONY: bench
bench: bench-guard
	$(GO) test -run=XXX -bench=. -benchmem ./...

## slo: hold the published latency targets, and fail when they are not met.
##
## This is the only target whose exit code depends on the wall-clock SLOs in
## CLAUDE.md section 2, and it exists because until now nothing's did.
## TestLatencyDistribution has always measured the right workloads and asserted
## the right numbers, but it runs at a 10x advisory ceiling unless
## GWAF_LATENCY_STRICT is set -- a deliberate and correct choice, since a shared
## CI runner cannot support a p50 assertion (see the reasoning in
## latency_test.go). The gap was that the one target which did set it,
## bench-publish, piped through `|| true` for its formatting and therefore could
## not fail, and the code comment pointed at `make bench`, which does not set it
## and does not even run the test.
##
## So the strict claim was reachable only by a human reading output. Run this on
## reference hardware; bench-guard refuses a busy machine, because a p50 taken
## next to a running scanner is not evidence either way.
.PHONY: slo
slo: bench-guard
	GWAF_LATENCY_STRICT=1 $(GO) test -run='TestLatencyDistribution|TestSLO' -v .

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
	@GWAF_BENCH_REPORT=1 GWAF_LATENCY_STRICT=1 $(GO) test -run='TestLatencyDistribution|TestSLO' -v . \
		| grep -E 'workload|ns|µs|ms|heap growth|--- (PASS|FAIL)' || true
	@echo
	@$(GO) test -run=XXX -bench=. -benchmem -count=5 . | grep -E '^(Benchmark|ok|PASS)'
	@echo
	@$(GO) test -run='TestEvasionCorpus$$|TestBenignCorpus$$' -v . \
		| grep -E 'detection:|false positives:' || true
	@$(GO) run ./cmd/gwaf calibrate 2>&1 | grep -E 'corpus:|power:|every rule' || true

## bench-save: record a baseline for regression comparison.
##
## Guarded hardest of the three: this one is written down and every later
## comparison is made against it.
.PHONY: bench-save
bench-save: bench-guard
	@mkdir -p bench
	$(GO) test -run=XXX -bench=. -benchmem -count=10 ./... > bench/baseline.txt
	@echo "baseline written to bench/baseline.txt"

## bench-check: compare against the recorded baseline. Requires benchstat.
##
## The SLOs in CLAUDE.md §2 are gated here. A >5% regression fails the build;
## see docs/PERFORMANCE.md.
.PHONY: bench-check
bench-check: bench-guard
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
	$(GO) test -run=XXX -fuzz=FuzzAnalyze -fuzztime=$(FUZZTIME) ./detect/promptinjection/
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

nuclei: ## gwaf vs Coraza + CRS on real CVE exploit traffic from nuclei-templates.
##
##   git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates /tmp/nuclei-templates
##   git clone --depth 1 https://github.com/coreruleset/coreruleset /tmp/crs
##   python3 test/headtohead/extract_corpus.py /tmp/nuclei-templates/http > /tmp/corpus.json
##   NUCLEI_CORPUS=/tmp/corpus.json CRS_RULES=/tmp/crs/rules make nuclei
##
## Reports detection, false positives and latency from one run. Read all three:
## an engine that blocks everything scores 100% on any corpus of attacks.
.PHONY: nuclei
nuclei:
	cd test/headtohead && go test -run TestNucleiHeadToHead -v -timeout 25m .

## sbom: generate a CycloneDX SBOM for every module.
##
## SECURITY.md has always said "Releases ship an SBOM and SLSA provenance". It
## was not true: v0.5.0 shipped zero assets, and nothing in the tree produced
## either one. That is the same failure as a gate that skips when its tool is
## missing -- a documented control that nothing implements is worse than an
## absent one, because the policy tells a reader it is there.
##
## Every module, for the reason `vuln` scans every module: core has no
## third-party dependencies by design, so an SBOM of core alone describes the
## one place with nothing to describe. What an adopter pulls in lives in the
## adapters.
.PHONY: sbom
sbom:
	@if [ ! -x "$(CYCLONEDX)" ]; then \
		echo "cyclonedx-gomod not found at $(CYCLONEDX)"; \
		echo "install: go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@$(CYCLONEDX_VERSION)"; \
		exit 1; \
	fi
	@mkdir -p dist/sbom
	@for m in $(MODULES); do \
		name=$$(echo $$m | sed -e 's|^\./||' -e 's|^\.$$|core|' -e 's|/|-|g'); \
		echo "sbom $$m -> dist/sbom/$$name.cdx.json"; \
		$(CYCLONEDX) mod -licenses -json -output dist/sbom/$$name.cdx.json $$m || exit 1; \
	done
	@echo "SBOMs in dist/sbom/"
