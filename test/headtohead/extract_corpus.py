#!/usr/bin/env python3
"""Extract real attack requests from projectdiscovery/nuclei-templates.

Usage:

    git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates /tmp/nuclei-templates
    python3 extract_corpus.py /tmp/nuclei-templates/http > corpus.json

nuclei-templates is the industry's maintained corpus of real exploit requests
for real CVEs, which is why it is the input rather than payloads somebody wrote
for this benchmark. Two things about the extraction matter when reading the
numbers it produces:

  * Templates are multi-step, and roughly 47% of the requests carry no payload
    at all -- they are the version probe that precedes the exploit
    ("GET /wp-content/plugins/x/readme.txt"). No per-request WAF can or should
    block those, so they are separated out rather than counted as misses.

  * Multipart bodies are CRLF-delimited by RFC 7578. Normalising them to LF
    makes every parser correctly refuse to read them, and the upload, its
    filename and its content all become invisible -- which measures a path no
    real client takes.


Nuclei templates are the industry-standard, community-maintained corpus of
real exploit requests for real CVEs. We replay them verbatim through each WAF
rather than inventing payloads, so the comparison is on traffic that actually
appeared in the wild.
"""
import json, os, re, sys

try:
    import yaml
except ImportError:
    sys.exit("pyyaml required: pip install pyyaml")

ATTACK_TAGS = {"xss", "sqli", "lfi", "rfi", "rce", "traversal", "injection", "xxe",
               "ssrf", "ssti", "fileupload", "deserialization", "redirect",
               "auth-bypass", "lfr", "crlf", "log4j"}

# nuclei resolves these at runtime; the corpus needs a request that is
# well-formed without a running scanner.
SUBS = {"{{BaseURL}}": "", "{{RootURL}}": "", "{{Hostname}}": "target.local",
        "{{Host}}": "target.local", "{{interactsh-url}}": "oast.example.com",
        "{{randstr}}": "abc123", "{{rand_base(6)}}": "abcdef"}

# A request carries a payload when something in its query or body is an attack
# rather than a path. The alternative -- counting version probes as misses --
# understates every engine by roughly the same 20 points and says nothing.
PAYLOAD = [r"<script", r"onerror\s*=", r"onload\s*=", r"javascript:", r"\.\.", r"%2e%2e",
           r"union\s", r"select\s", r"'\s*or\s", r"sleep\(", r"benchmark\(", r"<\?php",
           r"system\(", r"passthru", r"shell_exec", r"eval\(", r"base64", r"\$\(", r"\{\{",
           r"<!entity", r"file://", r"php://", r"gopher://", r"etc/passwd", r"%2fetc", r"/etc/",
           r"win\.ini", r"wp-config", r"<svg", r"<img", r"alert\(", r"%3cscript", r"%3cimg",
           r"%00", r"\bcmd=", r"curl\s", r"wget\s", r"\|\s*\w+", r"jndi:", r"169\.254",
           r"onfocus", r"formaction", r"!doctype", r"%0a", r"%0d", r"url=https?://",
           r"redirect.*https?://", r'filename="[^"]*\.(php|phtml|phar|jsp|asp)', r"\\u00"]


def subst(s):
    for k, v in SUBS.items():
        s = s.replace(k, v)
    return re.sub(r"\{\{[^}]*\}\}", "X", s)


def parse_raw(raw):
    raw = raw.replace("\r\n", "\n")
    head, _, body = raw.partition("\n\n")
    lines = [l for l in head.split("\n") if l.strip()]
    if not lines:
        return None
    m = re.match(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)", lines[0].strip())
    if not m:
        return None
    headers = {}
    for l in lines[1:]:
        if ":" in l:
            k, v = l.split(":", 1)
            if k.strip().lower() not in ("host", "content-length"):
                headers[k.strip()] = subst(v.strip())
    body = subst(body).strip("\n")
    if body.lstrip().startswith("--"):
        body = body.replace("\r\n", "\n").replace("\n", "\r\n")
    return {"method": m.group(1), "path": subst(m.group(2)), "headers": headers, "body": body}


def has_payload(c):
    q = c["path"].split("?", 1)[1] if "?" in c["path"] else ""
    blob = (q + " " + c.get("body", "")).lower()
    return bool(blob.strip()) and any(re.search(p, blob) for p in PAYLOAD)


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    root = sys.argv[1]
    out, seen = [], set()
    for dp, _, fs in os.walk(root):
        for fn in fs:
            if not fn.endswith((".yaml", ".yml")):
                continue
            try:
                doc = yaml.safe_load(open(os.path.join(dp, fn), errors="ignore"))
            except Exception:
                continue
            if not isinstance(doc, dict):
                continue
            info = doc.get("info") or {}
            tags = info.get("tags") or ""
            if isinstance(tags, list):
                tags = ",".join(tags)
            hit = ATTACK_TAGS & {t.strip().lower() for t in str(tags).split(",")}
            if not hit:
                continue
            cls, tid = sorted(hit)[0], doc.get("id", fn)
            sev = info.get("severity", "unknown")
            for b in (doc.get("http") or doc.get("requests") or []):
                if not isinstance(b, dict):
                    continue
                reqs = []
                if "raw" in b:
                    reqs = [r for r in (parse_raw(x) for x in b["raw"]) if r]
                else:
                    hdrs = {k: subst(str(v)) for k, v in (b.get("headers") or {}).items()
                            if k.lower() not in ("host", "content-length")}
                    for path in (b.get("path") or []):
                        pp = subst(str(path))
                        reqs.append({"method": b.get("method", "GET"),
                                     "path": pp if pp.startswith("/") else "/" + pp.lstrip("/"),
                                     "headers": hdrs, "body": subst(str(b.get("body") or ""))})
                for r in reqs:
                    key = (r["method"], r["path"], r["body"][:200])
                    if key in seen:
                        continue
                    seen.add(key)
                    r.update({"id": tid, "class": cls, "severity": sev,
                              "payload": has_payload(r)})
                    out.append(r)

    payload = [c for c in out if c["payload"]]
    json.dump({"note": "Extracted from projectdiscovery/nuclei-templates. "
                       "'payload' marks requests carrying an attack rather than a version probe.",
               "total": len(out), "payload_bearing": len(payload), "cases": out},
              sys.stdout, indent=1)
    print("", file=sys.stderr)
    print(f"{len(out)} requests, {len(payload)} payload-bearing", file=sys.stderr)


main()
