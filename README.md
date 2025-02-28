
# connect-oauth2

[![Go Reference](https://pkg.go.dev/badge/github.com/altipla-consulting/connect-oauth2.svg)](https://pkg.go.dev/github.com/altipla-consulting/connect-oauth2)

Utilities to call Connect services in Go using OAuth2 authentication.


## Install

```shell
go get github.com/altipla-consulting/connect-oauth2
```


## Usage

Authenticate with the default ID token to call Cloud Run services.

```go
var client = fooconnect.NewFooServiceClient(
  http.DefaultClient,
  "https://www.example.com",
  connect.WithInterceptors(oauth2.GoogleIDToken(env.IsProduction(), "https://www.example.com")),
)
```


## Contributing

You can make pull requests or create issues in GitHub. Any code you send should be formatted using `make gofmt`.


## License

[MIT License](LICENSE)
