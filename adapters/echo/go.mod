// Echo is a dependency somebody chose for their router, not one they should
// inherit from a firewall. Anyone on chi, gorilla/mux, connect-go, or the
// standard library needs nothing from here: middleware.HTTP is already a
// func(http.Handler) http.Handler and composes with all of them directly.
module github.com/gsoultan/gwaf/adapters/echo

go 1.26.5

require (
	github.com/gsoultan/gwaf v0.0.0
	github.com/gsoultan/gwaf/middleware v0.0.0
	github.com/labstack/echo/v4 v4.12.0
)

require (
	github.com/labstack/gommon v0.4.2 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasttemplate v1.2.2 // indirect
	golang.org/x/crypto v0.22.0 // indirect
	golang.org/x/net v0.24.0 // indirect
	golang.org/x/sys v0.19.0 // indirect
	golang.org/x/text v0.14.0 // indirect
)

replace (
	github.com/gsoultan/gwaf => ../../
	github.com/gsoultan/gwaf/middleware => ../../middleware
)
