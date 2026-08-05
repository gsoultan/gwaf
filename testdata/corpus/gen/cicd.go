// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package main

import "fmt"

// The CI/CD archetype: shell commands and template expressions travelling as
// data.
//
// This is the counterweight detect/shelli most needs and is least likely to
// have. A pipeline configuration API accepts `make build && ./deploy.sh` in a
// JSON field because running it is the product. Every value here is a command
// somebody meant to store, and none of them is an injection — the request is
// creating a pipeline definition, not smuggling a command into one.
//
// It is also adversarial to detect/ssti, since GitHub Actions and GitLab CI
// both express variables as `${{ ... }}` and `$CI_...`, and to detect/nosqli,
// because a matrix key can be anything the user names it.
//
// The distinction the detectors have to hold: `; cat /etc/passwd` appended to a
// hostname is injection, while `cat Dockerfile | docker build -` stored in a
// `run:` field is a build step. Position and provenance differ; the bytes do
// not differ much at all.
func emitCICD(emit func(request)) {
	// Build steps as an operator would write them.
	steps := []string{
		"make build",
		"make build && make test",
		"npm ci && npm run build",
		"go test ./... -race -cover",
		"go build -ldflags \"-s -w\" -o bin/app ./cmd/app",
		"docker build -t registry.example.com/app:$CI_COMMIT_SHA .",
		"docker push registry.example.com/app:latest",
		"kubectl apply -f k8s/ && kubectl rollout status deploy/app",
		"./scripts/deploy.sh production",
		"curl -sSf https://api.example.com/health || exit 1",
		"aws s3 sync ./dist s3://assets.example.com/ --delete",
		"terraform plan -out=tfplan && terraform apply tfplan",
		"pytest -v --cov=src tests/",
		"bundle exec rails db:migrate",
		"cat VERSION | tr -d '\\n'",
		"find . -name '*.log' -mtime +7 -delete",
		"tar czf artifacts.tar.gz dist/ && sha256sum artifacts.tar.gz",
		"echo \"$SLACK_TOKEN\" | docker login -u ci --password-stdin",
		"sed -i 's/VERSION/1.2.3/g' manifest.yaml",
		"grep -r 'TODO' src/ | wc -l",
		"awk '{print $1}' access.log | sort | uniq -c",
		"psql -c 'SELECT count(*) FROM users' >> report.txt",
		"ssh deploy@app-01.internal 'systemctl restart app'",
		"rsync -avz --delete ./build/ web@cdn:/var/www/",
		"base64 -d < secret.b64 > secret.key && chmod 600 secret.key",
		// "/bin/sh -c '...'" was here and is deliberately gone. An explicit
		// interpreter invocation arriving in a request value is the most
		// conclusive remote-execution shape there is, and gwaf reports it by
		// design. A CI platform that stores one needs a scoped exception on the
		// field that carries it -- that is what rules.Exception is for -- and
		// calling it ordinary benign traffic would have quietly cost the
		// detection everywhere else.
		"bash -eo pipefail scripts/release.sh",
		"npx playwright test --reporter=github",
		"trivy image --severity HIGH,CRITICAL app:latest",
	}

	// Template expressions from the two dominant CI systems.
	expressions := []string{
		"${{ matrix.os }}",
		"${{ matrix.go-version }}",
		"${{ secrets.GITHUB_TOKEN }}",
		"${{ github.event.pull_request.number }}",
		"${{ github.ref == 'refs/heads/main' }}",
		"${{ steps.build.outputs.digest }}",
		"${{ runner.os == 'Linux' && 'ubuntu' || 'macos' }}",
		"${{ needs.test.result == 'success' }}",
		"$CI_COMMIT_SHA",
		"$CI_PIPELINE_ID",
		"${CI_PROJECT_DIR}/artifacts",
		"${DOCKER_REGISTRY:-registry.example.com}",
		"$(git rev-parse --short HEAD)",
		"$(date -u +%Y-%m-%dT%H:%M:%SZ)",
	}

	pipelinePaths := []string{
		"/api/v4/projects/17/pipeline",
		"/api/v1/pipelines",
		"/api/v1/workflows/build/steps",
		"/api/v1/jobs",
		"/repos/example/app/actions/workflows/ci.yml/dispatches",
	}

	branches := []string{"main", "develop", "release/1.2", "feature/o'brien-fix", "hotfix/CVE-2026-21876"}
	envs := []string{"production", "staging", "review/pr-42"}
	for i, s := range steps {
		for j, p := range pipelinePaths {
			for k, br := range branches {
				emit(request{
					Name:   fmt.Sprintf("step %d on %s branch%d", i, p, k),
					Method: "POST",
					Target: p + "?ref=" + urlEncode(br),
					Args:   map[string]string{"ref": br},
					Headers: map[string]string{
						"Content-Type": "application/json",
						"User-Agent":   cicdAgents[(i+j+k)%len(cicdAgents)],
					},
					Body: fmt.Sprintf(
						`{"name":"build-%d","image":"golang:1.26","run":%q,"env":%q,"timeout":600}`,
						i, s, envs[k%len(envs)]),
				})
			}
			emit(request{
				Name:   fmt.Sprintf("step %d on %s", i, p),
				Method: "POST",
				Target: p,
				Headers: map[string]string{
					"Content-Type":  "application/json",
					"Authorization": "Bearer glpat-xxxxxxxxxxxxxxxxxxxx",
					"User-Agent":    cicdAgents[(i+j)%len(cicdAgents)],
				},
				Body: fmt.Sprintf(
					`{"name":"build-%d","image":"golang:1.26","run":%q,"timeout":600}`,
					i, s),
			})
		}
	}

	for i, e := range expressions {
		emit(request{
			Name:   fmt.Sprintf("expression %d", i),
			Method: "POST",
			Target: "/api/v1/workflows/deploy/steps",
			Headers: map[string]string{
				"Content-Type": "application/json",
				"User-Agent":   cicdAgents[i%len(cicdAgents)],
			},
			Body: fmt.Sprintf(
				`{"name":"deploy","env":{"TAG":%q,"TARGET":%q},"run":"./deploy.sh"}`,
				e, expressions[(i+3)%len(expressions)]),
		})
	}

	// Whole job definitions: steps and expressions together, which is how they
	// actually arrive.
	for i := range 40 {
		a := steps[i%len(steps)]
		b := steps[(i*7+3)%len(steps)]
		e := expressions[i%len(expressions)]
		emit(request{
			Name:   fmt.Sprintf("job definition %d", i),
			Method: "PUT",
			Target: fmt.Sprintf("/api/v1/pipelines/%d", 500+i),
			Headers: map[string]string{
				"Content-Type": "application/json",
				"User-Agent":   cicdAgents[i%len(cicdAgents)],
			},
			Body: fmt.Sprintf(
				`{"stages":["build","test","deploy"],`+
					`"jobs":[{"stage":"build","run":%q},{"stage":"test","run":%q}],`+
					`"variables":{"IMAGE_TAG":%q,"CACHE_DIR":"/tmp/.cache"}}`,
				a, b, e),
		})
	}

	// Log queries, where an operator greps their own build output.
	logQueries := []string{
		"error", "FAILED", "exit code 1", "panic:", "npm ERR!",
		"cannot find module", "permission denied", "connection refused",
		"go: cannot find main module", "make: *** [build] Error 2",
		"undefined reference to `main'", "SELECT", "DROP TABLE",
	}
	for i, q := range logQueries {
		emit(request{
			Name:    fmt.Sprintf("log search %d", i),
			Target:  fmt.Sprintf("/api/v1/jobs/%d/logs?q=%s", 900+i, urlEncode(q)),
			Args:    map[string]string{"q": q},
			Headers: map[string]string{"User-Agent": cicdAgents[i%len(cicdAgents)]},
		})
	}

	// Artefact paths, which carry the dots and slashes traversal rules read.
	artefacts := []string{
		"dist/app-linux-amd64.tar.gz", "build/reports/junit.xml",
		"coverage/lcov.info", "target/release/app", "out/bundle.min.js.map",
		"artifacts/v1.2.3/checksums.txt",
	}
	for i, a := range artefacts {
		emit(request{
			Name:    fmt.Sprintf("artefact %d", i),
			Target:  "/api/v1/jobs/42/artifacts?path=" + urlEncode(a),
			Args:    map[string]string{"path": a},
			Headers: map[string]string{"User-Agent": cicdAgents[i%len(cicdAgents)]},
		})
	}
}

var cicdAgents = []string{
	"GitLab-Runner/16.9.0",
	"GitHub-Hookshot/f4a2c1d",
	"actions/runner/2.313.0",
	"Jenkins/2.440.1",
	"buildkite-agent/3.65.0",
	"argocd/2.10.1",
	"curl/8.4.0",
	"Go-http-client/2.0",
}
