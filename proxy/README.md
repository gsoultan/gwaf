# gwaf-proxy — reference reverse proxy

Puts gwaf in front of an application that **does not have to be written in Go**.

```
go build -o gwaf-proxy ./proxy

./gwaf-proxy -upstream http://127.0.0.1:8080 -listen :8443 \
             -tls-cert cert.pem -tls-key key.pem
```

gwaf is a library, and a library protects only the process that imports it. A
PHP shop, a Node service, or a WordPress install cannot import a Go package — so
without something in front of them, gwaf's detection is unreachable to the
applications that need it most. This binary is that something.

## Protecting WordPress

```
# WordPress on :8080, proxy terminating traffic on :80
./gwaf-proxy -upstream http://127.0.0.1:8080 -listen :80 -health-path /healthz
```

That blocks, verified end to end: SQLi in a query parameter, XSS, path
traversal, `wp-config.php` disclosure, Log4Shell in a `User-Agent`, web-shell
uploads through the multipart parser, and **requests for a `.php` file under
`wp-content/uploads/`** — the request that turns a shell already on disk into
running code.

A WAF is not remediation. If files are already being written, find the entry
point (usually an outdated plugin), reinstall core and plugins from source, and
rotate credentials. The proxy buys time; it does not clean a compromise.

## Roll it out safely

Start in detect-only, measure, then enforce:

```
./gwaf-proxy -upstream http://127.0.0.1:8080 -detect-only -v
```

Every request is forwarded and every decision is logged, so you see what *would*
be blocked against your real traffic before anything breaks. Drop `-detect-only`
when the log is clean.

## Flags

| Flag | Default | What |
|---|---|---|
| `-upstream` | *(required)* | base URL to forward to |
| `-listen` | `:8080` | address to listen on |
| `-detect-only` | off | evaluate and log, never block — the rollout path |
| `-fail-open` | off | forward requests that could not be fully analysed |
| `-block-status` | `403` | status returned for a blocked request |
| `-response-inspection` | `0` | buffer up to N bytes per response for leak detection |
| `-health-path` | *(off)* | path answered locally, without gwaf or upstream |
| `-tls-cert` / `-tls-key` | *(off)* | serve HTTPS |
| `-log-json` | off | JSON logs instead of text |
| `-v` | off | log allows too, and return the rule ID in `X-Gwaf-Rule` |
| `-read-timeout` / `-write-timeout` / `-upstream-timeout` | 15s / 30s / 30s | |

**`-fail-open` is a real trade.** The default fails closed: a request gwaf could
not fully analyse is rejected, because forwarding it asserts something about
bytes nobody inspected. Fail open when availability outranks the residual risk —
and know that is the choice you made.

## What this is not

It is **tier 3** in [CLAUDE.md](../CLAUDE.md) §1: pure glue, ~325 lines, capped
at ~500. Every line parses a flag, builds a gwaf option, or wires `net/http`. It
has **no detection logic, no rules of its own, no config file it discovers, no
plugin system, and no metrics endpoint**.

Those absences are load-bearing. If this proxy ever needs one of them, the
*library* is missing an API and the fix goes there — a PR that adds non-glue code
here should be read as a design bug report against gwaf. It is also its own
module, so an embedder importing gwaf never inherits `httputil` or these flags,
and the proxy cannot reach gwaf's internals even by accident.

For anything beyond these flags, copy this file and embed the library directly.
That is the point of gwaf being a library, and this binary is the proof that the
library is complete enough to build one on.

## Notes

- **Never buffers by default.** Requests and responses stream, which keeps
  server-sent events and time-to-first-byte intact. Response inspection is
  explicit opt-in via `-response-inspection`.
- **`X-Forwarded-*` are set from the observed connection**, overwriting whatever
  the client sent, so a client cannot forge its own address into the upstream's
  logs or access rules.
- **Blocked responses say nothing.** Naming the rule tells an attacker what to
  work around; the rule ID goes to the log, and to `X-Gwaf-Rule` only under `-v`.
- **`clientIP` does not trust `X-Forwarded-For`.** Which proxy hop to believe is
  deployment policy the operator owns, and a naive trust is a spoofable audit
  record.
