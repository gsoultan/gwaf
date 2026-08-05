// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package main

import "fmt"

// The commerce archetype: free text at volume.
//
// A storefront is where apostrophes, ampersands, comparison operators, and
// non-ASCII names arrive in bulk from people who are not attacking anything.
// "O'Brien", "Marks & Spencer", "price < 50", "40% off", "l'Oréal" — every one
// of them is somebody shopping, and every one of them is a shape a naive
// matcher reads as SQL injection.
//
// Volume matters here more than anywhere else: a false-positive rate below one
// in ten thousand is a claim about traffic like this, because this is the
// traffic there is most of.
func emitCommerce(emit func(request)) {
	searches := []string{
		// Names with apostrophes: the single most common SQLi false positive.
		"O'Brien", "l'Oréal", "d'Angelo", "Levi's", "Reese's",
		"Kellogg's", "McDonald's", "Hershey's", "Campbell's",
		"children's shoes", "women's coats", "men's watches",

		// Ampersands and company names.
		"Marks & Spencer", "Johnson & Johnson", "AT&T", "Barnes & Noble",
		"Procter & Gamble", "Dolce & Gabbana", "H&M", "M&S",

		// Comparison and arithmetic in prose.
		"price < 50", "rating > 4", "size = large", "under $100",
		"40% off", "buy 2 get 1", "3 for 2", "50/50 blend",

		// Ordinary product searches.
		"running shoes", "wireless headphones", "cast iron skillet",
		"linen shirt", "espresso machine", "standing desk", "yoga mat",
		"laptop stand aluminium", "usb-c hub 4k", "noise cancelling",
		"organic cotton towels", "cordless drill 18v", "air fryer 5l",
		"mechanical keyboard brown switches", "4k monitor 27 inch",

		// International, which is what an ASCII-only assumption breaks on.
		"café au lait", "jalapeño", "crème brûlée", "Müsli", "Škoda",
		"日本茶", "한국 김치", "чай", "قهوة", "ชาไทย", "cà phê sữa",

		// SQL words used as English, which is the classic false positive.
		"union jack flag", "select committee report", "table lamp",
		"drop leaf table", "order of the phoenix", "insert cushion",
		"delete key keyboard", "update kit", "grant park print",
		"having a party supplies", "where the wild things are",
		"join the club membership", "null hypothesis book",

		// Markup-shaped text a shopper might type.
		"<3 gifts", "size <M>", "a > b comparison", "50 < x < 100",

		// Codes and identifiers.
		"SKU-4471-BLK", "ISBN 978-0-13-235088-4", "EAN 5012345678900",
		"model#XR-200", "part no. 1/4-20",
	}

	categories := []string{
		"electronics", "home-kitchen", "clothing", "books", "sports-outdoors",
		"beauty", "toys-games", "automotive", "garden", "pet-supplies",
	}
	sorts := []string{"relevance", "price_asc", "price_desc", "newest", "rating"}

	// Search, the highest-volume and highest-risk surface.
	for i, q := range searches {
		for j, c := range categories {
			emit(request{
				Name: fmt.Sprintf("search %d in %s", i, c),
				Target: fmt.Sprintf("/api/v2/search?q=%s&category=%s&sort=%s&page=%d",
					urlEncode(q), c, sorts[(i+j)%len(sorts)], 1+(i+j)%5),
				Args: map[string]string{
					"q": q, "category": c,
					"sort": sorts[(i+j)%len(sorts)],
					"page": fmt.Sprint(1 + (i+j)%5),
				},
				Headers: shopperHeaders(i + j),
			})
		}
	}

	// Faceted filtering: numeric ranges and multi-select, which produce the
	// bracketed and repeated parameter names that trip naive parsers.
	for i, c := range categories {
		for j := range 12 {
			lo, hi := 10*(j+1), 50*(j+2)
			emit(request{
				Name: fmt.Sprintf("facet %s %d", c, j),
				Target: fmt.Sprintf(
					"/api/v2/categories/%s/products?price_min=%d&price_max=%d&brand=%s&in_stock=true",
					c, lo, hi, brands[(i+j)%len(brands)]),
				Args: map[string]string{
					"price_min": fmt.Sprint(lo), "price_max": fmt.Sprint(hi),
					"brand": brands[(i+j)%len(brands)], "in_stock": "true",
				},
				Headers: shopperHeaders(i + j),
			})
		}
	}

	// Checkout: addresses and names, where apostrophes and non-ASCII live in
	// bodies rather than query strings.
	addresses := []struct{ name, street, city, country string }{
		{"Siobhán O'Brien", "12 St. John's Wood Rd", "London", "GB"},
		{"José Álvarez", "Calle de Alcalá 42, 3º B", "Madrid", "ES"},
		{"François Lefèvre", "8 rue de l'Église", "Lyon", "FR"},
		{"Müller-Schmidt", "Königsallee 1a", "Düsseldorf", "DE"},
		{"山田 太郎", "1-2-3 千代田区", "東京", "JP"},
		{"Ayşe Yılmaz", "Atatürk Cad. No:5/7", "İstanbul", "TR"},
		{"Nguyễn Thị Hoa", "45 Đường Lê Lợi", "Hồ Chí Minh", "VN"},
		{"Anna Kowalska", "ul. Świętokrzyska 12/4", "Warszawa", "PL"},
		{"Budi Santoso", "Jl. Sudirman Kav. 52-53", "Jakarta", "ID"},
		{"D'Angelo Russo", "Via dell'Orso 7", "Milano", "IT"},
	}
	for i, a := range addresses {
		for j := range 6 {
			emit(request{
				Name:   fmt.Sprintf("checkout %d variant %d", i, j),
				Method: "POST",
				Target: "/api/v2/checkout",
				Headers: map[string]string{
					"Content-Type": "application/json",
					"User-Agent":   shopperAgents[(i+j)%len(shopperAgents)],
					"Accept":       "application/json",
				},
				Body: fmt.Sprintf(
					`{"shipping":{"name":%q,"street":%q,"city":%q,"country":%q,`+
						`"postcode":"%s"},"items":[{"sku":"SKU-%04d","qty":%d}],`+
						`"note":%q}`,
					a.name, a.street, a.city, a.country,
					postcodes[(i+j)%len(postcodes)], 1000+i*10+j, 1+j,
					deliveryNotes[(i+j)%len(deliveryNotes)]),
			})
		}
	}

	// Reviews: the longest free text on the site.
	for i, r := range reviews {
		emit(request{
			Name:   fmt.Sprintf("review %d", i),
			Method: "POST",
			Target: fmt.Sprintf("/api/v2/products/%d/reviews", 3000+i),
			Headers: map[string]string{
				"Content-Type": "application/json",
				"User-Agent":   shopperAgents[i%len(shopperAgents)],
			},
			Body: fmt.Sprintf(`{"rating":%d,"title":%q,"body":%q,"verified":true}`,
				1+i%5, reviewTitles[i%len(reviewTitles)], r),
		})
	}
}

func shopperHeaders(i int) map[string]string {
	return map[string]string{
		"User-Agent":      shopperAgents[i%len(shopperAgents)],
		"Accept":          "application/json, text/plain, */*",
		"Accept-Language": []string{"en-GB,en;q=0.9", "de-DE,de;q=0.9,en;q=0.8", "ja-JP,ja;q=0.9", "id-ID,id;q=0.9,en;q=0.8"}[i%4],
		"Referer":         "https://shop.example.com/c/" + []string{"electronics", "home", "clothing"}[i%3],
	}
}

var shopperAgents = []string{
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
	"ShopApp/4.12.0 (iOS 17.3; iPhone15,3)",
	"ShopApp/4.12.0 (Android 14; SM-S918B)",
}

var brands = []string{
	"acme", "northwind", "contoso", "globex", "initech", "umbrella",
	"stark-industries", "wayne-enterprises", "tyrell", "cyberdyne",
}

var postcodes = []string{
	"SW1A 1AA", "28014", "69002", "40212", "100-0001", "34367",
	"70000", "00-050", "12190", "20121",
}

var deliveryNotes = []string{
	"Leave with the neighbour at no. 14",
	"Ring the bell twice — it's broken",
	"Don't leave in the rain, please",
	"Buzzer #3B, name is O'Connor",
	"Gate code 1234#, then left",
	"Call on arrival: +44 20 7946 0958",
}

var reviewTitles = []string{
	"Exactly what I needed", "Good but the strap broke",
	"Would buy again", "Not as pictured", "Five stars",
	"Arrived quickly, well packed", "Does the job",
}

var reviews = []string{
	"Arrived two days early and the packaging was excellent. The size runs a little small — I'd order one up.",
	"I've had this for 3 months now. The battery lasts about 8 hours, which is less than the 12 advertised, but it's fine for my commute.",
	"Bought as a gift for my daughter's birthday; she loves it. The colour is slightly darker than the photo.",
	"Doesn't fit my 2019 model. Check the compatibility table before ordering — I didn't and had to return it.",
	"Great value at 40% off. Would have been overpriced at full RRP.",
	"The instructions are terrible (translated badly) but the product itself is solid.",
	"Compared this against the Bosch and the Makita — this one is quieter but has less torque.",
	"L'emballage était parfait et la livraison rapide. Je recommande.",
	"Sehr gute Qualität, aber der Preis ist etwas hoch. Trotzdem 4 Sterne.",
	"品質は良いですが、説明書が分かりにくいです。",
	"Update after 6 months: still going strong. Changed my rating from 3 to 5.",
	"Careful — the listing says \"includes batteries\" but mine didn't have any.",
	"If you're choosing between this and the cheaper one: spend the extra £20.",
	"Works with my setup (Ubuntu 24.04, kernel 6.8). No driver needed.",
	"The stitching came apart after ~30 washes. Customer service replaced it without fuss.",
}
