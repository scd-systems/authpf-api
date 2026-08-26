module github.com/scd-systems/authpf-api

go 1.25.5

require (
	github.com/fsnotify/fsnotify v1.10.1
	github.com/golang-jwt/jwt/v5 v5.3.0
	github.com/labstack/echo/v5 v5.3.1
	github.com/rs/zerolog v1.34.0
	github.com/scd-systems/authpf-api-extensions v0.0.0-20260826125852-8bde31c54b48
	github.com/stretchr/testify v1.11.1
	golang.org/x/crypto v0.46.0
	golang.org/x/term v0.38.0
	gopkg.in/yaml.v3 v3.0.1
)

replace github.com/scd-systems/authpf-api-extensions => ../authpf-api-extensions

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
	golang.org/x/time v0.15.0 // indirect
)
