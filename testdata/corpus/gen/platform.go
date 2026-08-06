// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package main

import "fmt"

// SaaS admin: regexes, CIDRs, secrets, and paths stored as configuration.
//
// Adversarial to detect/shelli, detect/ldapi, and the traversal rules all at
// once. A directory-sync configuration legitimately contains an LDAP filter —
// `(&(objectClass=user)(memberOf=cn=eng,ou=groups,dc=example,dc=com))` — which
// is the exact grammar detect/ldapi reads. It is balanced and opens no clause
// it did not close, and that is the whole distinction the detector makes.
func emitSaaS(emit func(request)) {
	// Directory integration: real LDAP filters, written by an admin.
	ldapFilters := []string{
		"(&(objectClass=user)(memberOf=cn=engineering,ou=groups,dc=example,dc=com))",
		"(&(objectClass=person)(|(department=Sales)(department=Marketing)))",
		"(objectClass=groupOfNames)",
		"(&(uid=*)(!(accountStatus=disabled)))",
		"(|(mail=*@example.com)(mail=*@example.co.uk))",
		"(&(objectCategory=person)(objectClass=user)(givenName=*))",
		"(memberOf:1.2.840.113556.1.4.1941:=cn=admins,ou=groups,dc=example,dc=com)",
		"(&(objectClass=inetOrgPerson)(employeeType=contractor))",
	}
	dns := []string{
		"cn=svc-directory,ou=service-accounts,dc=example,dc=com",
		"ou=People,dc=example,dc=com",
		"dc=example,dc=com",
		"cn=O'Brien\\, Siobhán,ou=People,dc=example,dc=com",
	}
	for i, f := range ldapFilters {
		for j, d := range dns {
			emit(request{
				Name:   fmt.Sprintf("directory sync %d/%d", i, j),
				Method: "PUT",
				Target: "/admin/api/v1/integrations/directory",
				Headers: map[string]string{
					"Content-Type":  "application/json",
					"Authorization": "Bearer adm_" + fmt.Sprintf("%032x", i*104729+j),
					"User-Agent":    platformAgents[(i+j)%len(platformAgents)],
				},
				Body: fmt.Sprintf(
					`{"provider":"ldap","url":"ldaps://dc01.example.com:636",`+
						`"bind_dn":%q,"base_dn":%q,"user_filter":%q,"tls":{"verify":true}}`,
					d, dns[(j+1)%len(dns)], f),
			})
		}
	}

	// Team and permission management, the other half of an admin surface.
	roles := []string{"owner", "admin", "member", "billing", "read-only", "auditor"}
	scopes := []string{
		"routes:read", "routes:write", "secrets:read", "audit:read",
		"billing:manage", "members:invite", "integrations:write",
	}
	emails := []string{
		"alice@example.com", "s.o'brien@example.co.uk", "josé@example.es",
		"team+ci@example.com", "admin@sub.example.internal", "山田@example.jp",
	}
	for i, r := range roles {
		for j, sc := range scopes {
			for k, em := range emails {
				emit(request{
					Name:   fmt.Sprintf("invite %d/%d/%d", i, j, k),
					Method: "POST",
					Target: "/admin/api/v1/members",
					Headers: map[string]string{
						"Content-Type": "application/json",
						"User-Agent":   platformAgents[(i+j+k)%len(platformAgents)],
					},
					Body: fmt.Sprintf(`{"email":%q,"role":%q,"scopes":[%q],"expires_in":"7d"}`,
						em, r, sc),
				})
			}
		}
	}

	// Access rules: CIDRs, regexes, and paths.
	patterns := []string{
		"^/api/v[0-9]+/public/.*$",
		"^(?i)/admin/.*",
		"\\.(js|css|png|jpg|svg|woff2)$",
		"^/health$|^/ready$|^/metrics$",
		"^/users/(?P<id>[0-9]+)/profile$",
		"^https?://([a-z0-9-]+\\.)*example\\.com/",
		"[a-zA-Z0-9._%+-]+@example\\.(com|co\\.uk)",
	}
	cidrs := []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
		"2001:db8::/32", "fd00::/8", "203.0.113.0/24",
	}
	for i, p := range patterns {
		for j, c := range cidrs {
			emit(request{
				Name:   fmt.Sprintf("access rule %d/%d", i, j),
				Method: "POST",
				Target: "/admin/api/v1/access-rules",
				Headers: map[string]string{
					"Content-Type": "application/json",
					"User-Agent":   platformAgents[(i+j)%len(platformAgents)],
				},
				Body: fmt.Sprintf(
					`{"name":"rule-%d-%d","path_pattern":%q,"source_cidr":%q,`+
						`"action":"allow","priority":%d}`, i, j, p, c, 100+i*10+j),
			})
		}
	}

	// Secrets and credentials, which are long opaque strings.
	for i := range 240 {
		emit(request{
			Name:   fmt.Sprintf("secret %d", i),
			Method: "POST",
			Target: "/admin/api/v1/secrets",
			Headers: map[string]string{
				"Content-Type": "application/json",
				"User-Agent":   platformAgents[i%len(platformAgents)],
			},
			Body: fmt.Sprintf(
				`{"name":"SVC_%d_TOKEN","value":%q,"scope":"workspace","rotates_at":"2026-07-01T00:00:00Z"}`,
				i, secretValues[i%len(secretValues)]),
		})
	}

	// Audit-log queries, where an operator searches for the very things a WAF
	// would flag.
	auditQueries := []string{
		"actor:alice@example.com action:delete",
		"resource:/admin/users status:403",
		"ip:203.0.113.42",
		"action:login AND result:failure",
		"user_agent:curl*",
		"path:/api/v1/secrets*",
		"message:\"permission denied\"",
		"actor:svc-deploy action:update resource:route",
	}
	for i, q := range auditQueries {
		for j := range 30 {
			emit(request{
				Name: fmt.Sprintf("audit %d/%d", i, j),
				Target: fmt.Sprintf("/admin/api/v1/audit?q=%s&from=2026-0%d-01&to=2026-0%d-28&limit=100",
					urlEncode(q), 1+j%6, 2+j%6),
				Args: map[string]string{
					"q":    q,
					"from": fmt.Sprintf("2026-0%d-01", 1+j%6),
					"to":   fmt.Sprintf("2026-0%d-28", 2+j%6),
				},
				Headers: map[string]string{"User-Agent": platformAgents[(i+j)%len(platformAgents)]},
			})
		}
	}
}

// Webhooks: third-party payloads nobody controls the shape of.
//
// These arrive from Stripe, GitHub, Slack, and Twilio exactly as those vendors
// send them, signature headers and all. An embedder cannot negotiate the shape,
// so a firewall that mishandles it breaks an integration the customer paid for.
func emitWebhooks(emit func(request)) {
	events := []struct{ vendor, path, ctype, body string }{
		{"stripe", "/webhooks/stripe", "application/json",
			`{"id":"evt_1Ox2Yz","object":"event","type":"payment_intent.succeeded",` +
				`"data":{"object":{"id":"pi_3Ox","amount":4999,"currency":"gbp",` +
				`"metadata":{"order_id":"ord-88231","note":"gift — leave at door"}}}}`},
		{"github", "/webhooks/github", "application/json",
			`{"action":"opened","number":42,"pull_request":{"title":"fix: don't drop the ' in names",` +
				"\"body\":\"Closes #41.\\n\\n" + "```" + "go\\nname := O'Brien\\n" + "```" + "\",\"head\":{\"ref\":\"fix/quotes\"}}}"},
		{"github-push", "/webhooks/github", "application/json",
			`{"ref":"refs/heads/main","commits":[{"id":"a1b2c3","message":"chore: run make build && make test",` +
				`"author":{"name":"Siobhán O'Brien","email":"s@example.com"}}]}`},
		{"slack", "/webhooks/slack", "application/x-www-form-urlencoded",
			"token=abc&team_id=T001&command=%2Fdeploy&text=production+--force&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2F123"},
		{"twilio", "/webhooks/twilio/sms", "application/x-www-form-urlencoded",
			"MessageSid=SM123&From=%2B442079460958&To=%2B441234567890&Body=Order+%2388231+shipped+%E2%80%94+track+at+https%3A%2F%2Fex.com%2Ft%2Fabc"},
		{"shopify", "/webhooks/shopify", "application/json",
			`{"id":820982911946154508,"email":"jon@example.com","line_items":[{"sku":"SKU-4471","title":"Levi's 501","quantity":1}],` +
				`"shipping_address":{"address1":"12 St. John's Wood Rd","city":"London","country_code":"GB"}}`},
		{"sentry", "/webhooks/sentry", "application/json",
			`{"action":"created","data":{"issue":{"title":"TypeError: Cannot read property 'id' of undefined",` +
				`"culprit":"app/routes/orders.tsx in loader","metadata":{"value":"Cannot read property 'id' of undefined"}}}}`},
		{"pagerduty", "/webhooks/pagerduty", "application/json",
			`{"event":{"event_type":"incident.triggered","data":{"title":"p99 > 500ms on /api/v2/search",` +
				`"service":{"summary":"search-api"},"urgency":"high"}}}`},
		{"docker", "/webhooks/registry", "application/json",
			`{"events":[{"action":"push","target":{"repository":"example/app","tag":"v1.2.3",` +
				`"digest":"sha256:9f2c1a0b3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8"}}]}`},
	}

	sigHeaders := []map[string]string{
		{"Stripe-Signature": "t=1706745600,v1=5257a869e7ecebeda32affa62cdca3fa51cad7e77a0e56ff536d0ce8e108d8bd"},
		{"X-Hub-Signature-256": "sha256=7d38cdd689735b008b3c702edd92eea23791c5f6", "X-GitHub-Event": "pull_request", "X-GitHub-Delivery": "72d3162e-cc78-11e3-81ab-4c9367dc0958"},
		{"X-Slack-Signature": "v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503", "X-Slack-Request-Timestamp": "1706745600"},
		{"X-Twilio-Signature": "0h0FL7bLtoJ0uUEwFHnHtxeIYbY="},
		{"X-Shopify-Hmac-Sha256": "XWmrwMey6OsLMeiZKwP4FppHH3cmAiiJJAweH5Jo4bM=", "X-Shopify-Topic": "orders/create"},
	}

	for i, e := range events {
		for j, sig := range sigHeaders {
			// Deliveries differ by target and body, not only by headers: the
			// dedup key is (method, target, body, args), so header-only
			// variants would collapse into one and inflate nothing.
			for k := range 12 {
				h2 := map[string]string{
					"Content-Type":    e.ctype,
					"User-Agent":      webhookAgents[(i+j+k)%len(webhookAgents)],
					"X-Forwarded-For": fmt.Sprintf("203.0.113.%d, 198.51.100.%d", 1+k*7, 1+j*3),
				}
				for kk, vv := range sig {
					h2[kk] = vv
				}
				id := fmt.Sprintf("%s-%d-%d-%d", e.vendor, i, j, k)
				emit(request{
					Name:    fmt.Sprintf("%s sig%d delivery%d", e.vendor, j, k),
					Method:  "POST",
					Target:  e.path + "?delivery=" + id,
					Args:    map[string]string{"delivery": id},
					Headers: h2,
					Body:    e.body,
				})
			}
			h := map[string]string{
				"Content-Type": e.ctype,
				"User-Agent":   webhookAgents[(i+j)%len(webhookAgents)],
				"Accept":       "*/*",
			}
			for k, v := range sig {
				h[k] = v
			}
			emit(request{
				Name:    fmt.Sprintf("%s sig%d", e.vendor, j),
				Method:  "POST",
				Target:  e.path,
				Headers: h,
				Body:    e.body,
			})
		}
	}

	// Retries and replays, which is most of real webhook traffic.
	for i, e := range events {
		for attempt := 1; attempt <= 18; attempt++ {
			emit(request{
				Name:   fmt.Sprintf("%s retry %d", e.vendor, attempt),
				Method: "POST",
				Target: e.path + fmt.Sprintf("?attempt=%d", attempt),
				Args:   map[string]string{"attempt": fmt.Sprint(attempt)},
				Headers: map[string]string{
					"Content-Type":    e.ctype,
					"User-Agent":      webhookAgents[i%len(webhookAgents)],
					"Idempotency-Key": fmt.Sprintf("%s-%d-%d", e.vendor, i, attempt),
				},
				Body: e.body,
			})
		}
	}
}

// Mobile: compact clients, base64 blobs, and unusual header sets.
//
// Adversarial to internal/body's base64 handling: a phone uploads an avatar as
// a base64 field because multipart from a mobile SDK is awkward, and the
// decoded bytes are a JPEG rather than a web shell.
func emitMobile(emit func(request)) {
	// A small valid JPEG header followed by filler, base64-encoded, so the
	// decoded content is genuinely binary rather than text pretending to be.
	jpeg := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0x00, 0x01}
	for i := range 600 {
		jpeg = append(jpeg, byte(i*37%251), byte(i*11%253), byte(i*7%241))
	}
	avatar := base64Encode(jpeg)

	png := []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}
	for i := range 400 {
		png = append(png, byte(i*53%251))
	}
	thumb := base64Encode(png)

	devices := []struct{ ua, platform, version string }{
		{"ShopApp/4.12.0 (iOS 17.3.1; iPhone15,3; scale/3.00)", "ios", "4.12.0"},
		{"ShopApp/4.12.0 (Android 14; SM-S918B; scale/3.50)", "android", "4.12.0"},
		{"ShopApp/4.11.2 (iOS 16.7.5; iPhone12,1; scale/2.00)", "ios", "4.11.2"},
		{"ShopApp/4.10.0 (Android 13; Pixel 7; scale/2.63)", "android", "4.10.0"},
		{"Dart/3.3 (dart:io)", "flutter", "1.0.0"},
		{"okhttp/4.12.0", "android", "4.12.0"},
		{"CFNetwork/1494.0.7 Darwin/23.4.0", "ios", "4.12.0"},
	}

	for i, d := range devices {
		h := func() map[string]string {
			return map[string]string{
				"Content-Type":    "application/json",
				"User-Agent":      d.ua,
				"X-App-Version":   d.version,
				"X-Platform":      d.platform,
				"X-Device-Id":     fmt.Sprintf("%08x-%04x-4%03x-8%03x-%012x", i*99991, i*7, i*13, i*17, i*104729),
				"Accept-Encoding": "gzip, deflate, br",
				"Accept-Language": []string{"en-GB", "de-DE", "ja-JP", "id-ID", "pt-BR"}[i%5],
				"X-Request-Id":    fmt.Sprintf("%032x", i*15485863),
				"Authorization":   "Bearer eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ1c3ItNTUifQ.sig",
			}
		}

		emit(request{Name: fmt.Sprintf("avatar upload %d", i), Method: "PUT",
			Target: "/api/v2/me/avatar", Headers: h(),
			Body: fmt.Sprintf(`{"image":%q,"mime":"image/jpeg","width":320,"height":320}`, avatar)})

		emit(request{Name: fmt.Sprintf("thumb upload %d", i), Method: "POST",
			Target: "/api/v2/products/4471/images", Headers: h(),
			Body: fmt.Sprintf(`{"thumbnail":%q,"mime":"image/png","primary":%v}`, thumb, i%2 == 0)})

		// Telemetry batches: many small events in one body.
		emit(request{Name: fmt.Sprintf("telemetry %d", i), Method: "POST",
			Target: "/api/v2/telemetry/batch", Headers: h(),
			Body: fmt.Sprintf(
				`{"events":[{"t":"view","screen":"home","ts":%d},`+
					`{"t":"tap","target":"cart","ts":%d},`+
					`{"t":"search","term":"O'Brien tea","ts":%d},`+
					`{"t":"error","message":"NSURLErrorDomain -1009","ts":%d}]}`,
				1706745600+i, 1706745601+i, 1706745602+i, 1706745603+i)})

		// Product and cart traffic, which is most of what a phone actually
		// sends and where the app's own identifiers travel.
		for j := range 24 {
			emit(request{
				Name: fmt.Sprintf("catalog %d/%d", i, j),
				Target: fmt.Sprintf("/api/v2/products/%d?fields=%s&currency=%s",
					4000+j*7, []string{"summary", "full", "price,stock", "media"}[j%4],
					[]string{"GBP", "EUR", "USD", "JPY", "IDR"}[j%5]),
				Args: map[string]string{
					"fields":   []string{"summary", "full", "price,stock", "media"}[j%4],
					"currency": []string{"GBP", "EUR", "USD", "JPY", "IDR"}[j%5],
				},
				Headers: h(),
			})
			emit(request{
				Name:    fmt.Sprintf("cart update %d/%d", i, j),
				Method:  "PATCH",
				Target:  "/api/v2/cart/items/" + fmt.Sprint(200+j),
				Headers: h(),
				Body: fmt.Sprintf(`{"qty":%d,"gift_message":%q,"options":{"size":%q,"colour":%q}}`,
					1+j%5, mobileNotes[j%len(mobileNotes)],
					[]string{"S", "M", "L", "XL"}[j%4],
					[]string{"black", "navy", "off-white", "forest"}[j%4]),
			})
			emit(request{
				Name:    fmt.Sprintf("push register %d/%d", i, j),
				Method:  "POST",
				Target:  "/api/v2/devices/push",
				Headers: h(),
				Body: fmt.Sprintf(`{"token":%q,"provider":%q,"locale":%q,"tz":%q}`,
					base64Encode([]byte(fmt.Sprintf("push-token-%d-%d-%x", i, j, i*7919+j))),
					[]string{"apns", "fcm"}[j%2],
					[]string{"en-GB", "de-DE", "ja-JP", "id-ID", "pt-BR"}[j%5],
					[]string{"Europe/London", "Asia/Tokyo", "Asia/Jakarta", "America/Sao_Paulo"}[j%4]),
			})
		}

		// Sync: cursor-based, with an opaque token.
		for j := range 40 {
			emit(request{
				Name: fmt.Sprintf("sync %d/%d", i, j),
				Target: fmt.Sprintf("/api/v2/sync?cursor=%s&limit=%d",
					urlEncode(base64Encode([]byte(fmt.Sprintf("ts:%d|id:%d", 1706745600+j*60, 1000+j)))), 50),
				Args: map[string]string{
					"cursor": base64Encode([]byte(fmt.Sprintf("ts:%d|id:%d", 1706745600+j*60, 1000+j))),
					"limit":  "50",
				},
				Headers: h(),
			})
		}
	}
}

var platformAgents = []string{
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	"Terraform/1.7.3 (+https://www.terraform.io)",
	"pulumi-go/3.107.0",
	"admin-cli/2.4.0",
	"python-requests/2.31.0",
	"Go-http-client/2.0",
}

var webhookAgents = []string{
	"Stripe/1.0 (+https://stripe.com/docs/webhooks)",
	"GitHub-Hookshot/f4a2c1d",
	"Slackbot 1.0 (+https://api.slack.com/robots)",
	"TwilioProxy/1.1",
	"Shopify-Captain-Hook",
	"Sentry/1.0",
	"PagerDuty-Webhook/3.0",
}

// secretValues populates the saas/secret archetype: a legitimate request that
// POSTs a credential to a secrets-management API, which a WAF must not block.
//
// These deliberately carry *no vendor prefix*. They used to be Stripe, GitHub,
// Slack, AWS, DigitalOcean, and npm formats, and that was a mistake with a cost
// and no benefit. The cost: GitHub push protection rejects the repository, and
// every clone, fork, and mirror trips secret scanning forever. The benefit was
// zero, because no gwaf rule keys on a vendor format -- what the corpus needs is
// an opaque, high-entropy, credential-shaped string, which is exactly what these
// are. Same lengths as the originals, same character class, no fingerprint.
//
// Keep it that way. A security library whose test corpus sets off every secret
// scanner on the internet is teaching the wrong lesson.
var secretValues = []string{
	"tok_SPkc47MsBxJnTi3FDbhUHq7j4bAZcuGyFQ9vKBV78niBcah",
	"tok_txKABJWVRaRsQrDrgW38mK2XJ3S3hZv2MbhB",
	"tok_qR3bcyrAtTn5WEBegh2ZCGsDGr4xWuHEhHJWK57Qt5k",
	"tok_nXY779M7WJYKtByj",
	"tok_ZjKS2HZqDF5pzjFginDfw5Q92myBQHscMvyMMGNN4QrGF5f4XgXCk",
	"tok_eMGNqbMNbNbzdPGaoomqBisYoZGvyc3cHoPe",
}

var mobileNotes = []string{
	"Happy birthday! — from all of us",
	"Please don't include a receipt",
	"For Siobhán, with love",
	"Gift wrap in the blue paper if you can",
	"Congratulations on the new house!",
	"お誕生日おめでとう",
	"",
}
