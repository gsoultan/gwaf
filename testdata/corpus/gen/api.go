// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package main

import "fmt"

// GraphQL: one endpoint, a whole query language in the body.
//
// Adversarial to detect/sqli and detect/xss, because a GraphQL document is
// dense with braces, parentheses, quotes, and colons, and to detect/nosqli,
// because variable definitions are written `$id` — a dollar-prefixed name in a
// place that looks like a key.
func emitGraphQL(emit func(request)) {
	queries := []string{
		`query GetUser($id: ID!) { user(id: $id) { id name email } }`,
		`query ListOrders($first: Int!, $after: String) { orders(first: $first, after: $after) { edges { node { id total status } } pageInfo { hasNextPage endCursor } } }`,
		`mutation CreateOrder($input: OrderInput!) { createOrder(input: $input) { id status } }`,
		`mutation UpdateProfile($name: String!, $bio: String) { updateProfile(name: $name, bio: $bio) { id } }`,
		`query Search($term: String!, $limit: Int = 20) { search(term: $term, limit: $limit) { __typename ... on Product { sku price } ... on Article { title } } }`,
		`query { viewer { id permissions roles { name scopes } } }`,
		`subscription OnOrderUpdate($orderId: ID!) { orderUpdated(orderId: $orderId) { id status updatedAt } }`,
		`query WithFragment { orders { ...OrderFields } } fragment OrderFields on Order { id total customer { name } }`,
		`query Aliased { a: user(id: "1") { name } b: user(id: "2") { name } }`,
		`mutation { deleteSession(id: "sess-abc") { success } }`,
		`query Deep { org { teams { members { user { profile { avatar { url } } } } } } }`,
		`query WithDirective($withEmail: Boolean!) { user(id: "1") { name email @include(if: $withEmail) } }`,
	}

	variables := []string{
		`{"id":"usr-1024"}`,
		`{"first":20,"after":"Y3Vyc29yOjIw"}`,
		`{"input":{"sku":"SKU-4471","qty":2,"note":"leave at door"}}`,
		`{"name":"Siobhán O'Brien","bio":"Engineer. Tea drinker. <3 Go."}`,
		`{"term":"price < 50","limit":10}`,
		`{"term":"Marks & Spencer","limit":25}`,
		`{"orderId":"ord-88231"}`,
		`{"withEmail":true}`,
		`{}`,
	}

	endpoints := []string{"/graphql", "/api/graphql", "/v1/graphql", "/query"}
	for i, q := range queries {
		for j, v := range variables {
			for k, ep := range endpoints {
				emit(request{
					Name:   fmt.Sprintf("query %d vars %d ep%d", i, j, k),
					Method: "POST",
					Target: ep,
					Headers: map[string]string{
						"Content-Type": "application/json",
						"User-Agent":   apiAgents[(i+j+k)%len(apiAgents)],
					},
					Body: fmt.Sprintf(`{"operationName":"Op%d_%d","query":%q,"variables":%s}`, i, k, q, v),
				})
			}
			emit(request{
				Name:   fmt.Sprintf("query %d vars %d", i, j),
				Method: "POST",
				Target: "/graphql",
				Headers: map[string]string{
					"Content-Type":              "application/json",
					"Authorization":             "Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c3ItMTAyNCJ9.sig",
					"User-Agent":                apiAgents[(i+j)%len(apiAgents)],
					"Apollographql-Client-Name": "web",
				},
				Body: fmt.Sprintf(`{"operationName":"Op%d","query":%q,"variables":%s}`, i, q, v),
			})
		}
	}

	// Persisted queries: a hash instead of a document, plus GET-borne queries.
	for i := range 24 {
		emit(request{
			Name:   fmt.Sprintf("persisted %d", i),
			Method: "POST",
			Target: "/graphql",
			Headers: map[string]string{
				"Content-Type": "application/json",
				"User-Agent":   apiAgents[i%len(apiAgents)],
			},
			Body: fmt.Sprintf(
				`{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"%064x"}},"variables":{"id":"usr-%d"}}`,
				i*7919, 1000+i),
		})
	}
	for i, q := range queries[:8] {
		emit(request{
			Name:    fmt.Sprintf("graphql GET %d", i),
			Target:  "/graphql?query=" + urlEncode(q),
			Args:    map[string]string{"query": q},
			Headers: map[string]string{"User-Agent": apiAgents[i%len(apiAgents)]},
		})
	}
}

// gRPC-web: binary framing a text detector must not read as prose.
//
// The measured failure this guards against: 1.2% of random protobuf payloads
// were blocked because a two-byte shell literal appears by chance about once
// per hundred requests in binary data.
func emitGRPCWeb(emit func(request)) {
	services := []string{
		"catalog.v1.CatalogService", "order.v1.OrderService",
		"user.v1.UserService", "billing.v1.BillingService",
		"search.v1.SearchService", "inventory.v1.InventoryService",
	}
	methods := []string{
		"Get", "List", "Create", "Update", "Delete", "Watch",
		"BatchGet", "Search", "Count", "Export",
	}

	for i, s := range services {
		for j, m := range methods {
			for k := range 14 {
				emit(request{
					Name:   fmt.Sprintf("%s/%s frame %d", s, m, k),
					Method: "POST",
					Target: "/" + s + "/" + m,
					Headers: map[string]string{
						"Content-Type": []string{
							"application/grpc-web+proto",
							"application/grpc-web-text",
							"application/connect+proto",
							"application/proto",
						}[k%4],
						"X-Grpc-Web":               "1",
						"Grpc-Timeout":             "30S",
						"Connect-Protocol-Version": "1",
						"User-Agent":               apiAgents[(i+j+k)%len(apiAgents)],
					},
					Body: grpcBody(i+k, j),
				})
			}
		}
	}
}

// OData: $filter and friends, which collide head-on with MongoDB operators.
//
// This archetype exists because detect/nosqli resolves that collision toward
// benign, and a decision like that has to be held to traffic rather than to a
// comment.
func emitOData(emit func(request)) {
	filters := []string{
		"Price gt 20",
		"Price le 100 and Category eq 'Electronics'",
		"contains(Name, 'shoe')",
		"startswith(Sku, 'SKU-')",
		"Created ge 2026-01-01T00:00:00Z",
		"Status eq 'Active' or Status eq 'Pending'",
		"not (Discontinued eq true)",
		"Items/any(i: i/Qty gt 2)",
		"Customer/Country eq 'GB'",
		"year(Created) eq 2026",
		"tolower(Name) eq 'widget'",
		"Rating ge 4 and Reviews/$count gt 10",
	}
	selects := []string{"Name,Price", "Id,Sku,Price,Stock", "*", "Name,Category/Name"}
	orders := []string{"Price desc", "Created desc", "Name asc", "Rating desc,Price asc"}
	entities := []string{"Products", "Orders", "Customers", "Invoices", "Categories"}

	for i, e := range entities {
		for j, f := range filters {
			emit(request{
				Name: fmt.Sprintf("%s filter %d", e, j),
				Target: fmt.Sprintf("/odata/%s?$filter=%s&$select=%s&$top=%d&$skip=%d",
					e, urlEncode(f), urlEncode(selects[(i+j)%len(selects)]),
					10*(1+j%5), 20*(j%4)),
				Args: map[string]string{
					"$filter": f,
					"$select": selects[(i+j)%len(selects)],
					"$top":    fmt.Sprint(10 * (1 + j%5)),
					"$skip":   fmt.Sprint(20 * (j % 4)),
				},
				Headers: map[string]string{
					"OData-Version": "4.01",
					"Accept":        "application/json;odata.metadata=minimal",
					"User-Agent":    apiAgents[(i+j)%len(apiAgents)],
				},
			})
		}
		for j, f := range filters {
			for k, sel := range selects {
				for l, o := range orders {
					emit(request{
						Name: fmt.Sprintf("%s combo %d/%d/%d", e, j, k, l),
						Target: fmt.Sprintf("/odata/%s?$filter=%s&$select=%s&$orderby=%s&$top=%d",
							e, urlEncode(f), urlEncode(sel), urlEncode(o), 5*(1+l)),
						Args: map[string]string{
							"$filter": f, "$select": sel, "$orderby": o,
							"$top": fmt.Sprint(5 * (1 + l)),
						},
						Headers: map[string]string{
							"OData-Version": "4.01",
							"User-Agent":    apiAgents[(j+k+l)%len(apiAgents)],
						},
					})
				}
			}
		}
		for j, o := range orders {
			emit(request{
				Name: fmt.Sprintf("%s orderby %d", e, j),
				Target: fmt.Sprintf("/odata/%s?$orderby=%s&$count=true&$expand=%s",
					e, urlEncode(o), "Items($select=Sku)"),
				Args: map[string]string{
					"$orderby": o, "$count": "true",
					"$expand": "Items($select=Sku)",
				},
				Headers: map[string]string{"OData-Version": "4.01"},
			})
		}
		emit(request{
			Name:    fmt.Sprintf("%s search", e),
			Target:  fmt.Sprintf("/odata/%s?$search=%s", e, urlEncode("blue OR green")),
			Args:    map[string]string{"$search": "blue OR green"},
			Headers: map[string]string{"OData-Version": "4.01"},
		})
	}

	emit(request{Name: "metadata", Target: "/odata/$metadata",
		Headers: map[string]string{"Accept": "application/xml"}})
	emit(request{Name: "batch", Method: "POST", Target: "/odata/$batch",
		Headers: map[string]string{"Content-Type": "application/json"},
		Body:    `{"requests":[{"id":"1","method":"GET","url":"Products?$top=5"}]}`})
}

// JSON:API: bracketed parameter names, which collide with NoSQL injection.
//
// `filter[price][gte]=10` is the JSON:API convention and `filter[price][$gte]`
// is the attack, and the difference is one character. That is precisely the
// discrimination detect/nosqli claims to make.
func emitJSONAPI(emit func(request)) {
	resources := []string{"articles", "people", "comments", "orders", "tags"}
	filterKeys := []string{"title", "author", "status", "created", "price", "rating"}
	ops := []string{"eq", "ne", "gt", "gte", "lt", "lte", "like", "in"}

	for i, r := range resources {
		for j, k := range filterKeys {
			for l, op := range ops {
				name := fmt.Sprintf("filter[%s][%s]", k, op)
				val := []string{"published", "10", "2026-01-01", "alice", "4.5", "a,b,c"}[(i+j+l)%6]
				for m, srt := range []string{"-created", "title", "-rating,title", "author.name"} {
					emit(request{
						Name: fmt.Sprintf("%s %s sort%d", r, name, m),
						Target: fmt.Sprintf("/api/%s?%s=%s&sort=%s&page[size]=%d",
							r, urlEncode(name), urlEncode(val), urlEncode(srt), 10*(1+m)),
						Args: map[string]string{
							name: val, "sort": srt,
							"page[size]": fmt.Sprint(10 * (1 + m)),
						},
						Headers: map[string]string{
							"Accept":     "application/vnd.api+json",
							"User-Agent": apiAgents[(i+j+l+m)%len(apiAgents)],
						},
					})
				}
			}
		}
		// Sparse fieldsets, includes, and sorting, all bracketed.
		for j := range 8 {
			emit(request{
				Name: fmt.Sprintf("%s sparse %d", r, j),
				Target: fmt.Sprintf("/api/%s?fields[%s]=%s&include=%s&sort=%s&page[number]=%d&page[size]=%d",
					r, r, "title,body", "author,comments", "-created,title", 1+j, 25),
				Args: map[string]string{
					"fields[" + r + "]": "title,body",
					"include":           "author,comments",
					"sort":              "-created,title",
					"page[number]":      fmt.Sprint(1 + j),
					"page[size]":        "25",
				},
				Headers: map[string]string{"Accept": "application/vnd.api+json"},
			})
		}
		// Resource bodies, which carry the type/id/attributes envelope.
		for j := range 6 {
			emit(request{
				Name:   fmt.Sprintf("%s create %d", r, j),
				Method: "POST",
				Target: "/api/" + r,
				Headers: map[string]string{
					"Content-Type": "application/vnd.api+json",
					"Accept":       "application/vnd.api+json",
				},
				Body: fmt.Sprintf(
					`{"data":{"type":%q,"attributes":{"title":%q,"body":%q},`+
						`"relationships":{"author":{"data":{"type":"people","id":"%d"}}}}}`,
					r, jsonapiTitles[j%len(jsonapiTitles)],
					jsonapiBodies[(i+j)%len(jsonapiBodies)], 100+j),
			})
		}
	}
}

var jsonapiTitles = []string{
	"JSON:API considered useful", "O'Brien's guide to pagination",
	"Rate limits & you", "Why price < cost is a bug",
	"Migrating from v1 (a retrospective)", "The <details> element",
}

var jsonapiBodies = []string{
	"We moved to cursor pagination because offset pagination broke at scale.",
	"The spec says `filter` is reserved but doesn't define its grammar, so everyone invented one.",
	"Set `page[size]` no higher than 100; beyond that the query planner gives up.",
	"See the appendix for a comparison of `include` depth limits across implementations.",
}

var apiAgents = []string{
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	"axios/1.6.7",
	"okhttp/4.12.0",
	"python-requests/2.31.0",
	"Go-http-client/2.0",
	"grpc-web-javascript/1.5.0",
	"connect-es/1.3.0",
	"PostmanRuntime/7.36.3",
	"Apache-HttpClient/5.3.1 (Java/21)",
	"Dart/3.3 (dart:io)",
}
