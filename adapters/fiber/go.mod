// Fiber is built on fasthttp and has no net/http types, so this adapter drives
// the transaction API directly rather than wrapping the net/http middleware.
//
// That is what the transaction API is for. gwaf's core takes strings and byte
// slices and knows nothing about net/http; the middleware package is one
// integration built on it and this is another. If the API could not support a
// non-net/http server cleanly, that would be a tier-1 gap.
module github.com/gsoultan/gwaf/adapters/fiber

go 1.26.5

require (
	github.com/gofiber/fiber/v2 v2.52.5
	github.com/gsoultan/gwaf v0.0.0
)

require (
	github.com/andybalholm/brotli v1.0.5 // indirect
	github.com/google/uuid v1.5.0 // indirect
	github.com/klauspost/compress v1.17.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-runewidth v0.0.15 // indirect
	github.com/rivo/uniseg v0.2.0 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasthttp v1.51.0 // indirect
	github.com/valyala/tcplisten v1.0.0 // indirect
	golang.org/x/sys v0.15.0 // indirect
)

replace github.com/gsoultan/gwaf => ../../
