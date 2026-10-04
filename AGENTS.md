# Agent Guidelines for kmscsr

## Build/Lint/Test Commands
- Build: `go build ./...`
- Run all tests: `go test ./...`
- Run tests with coverage: `go test -cover ./...`
- Run single test: `go test -v -run TestName`
- Run specific package tests: `go test -v ./path/to/package`
- Vet: `go vet ./...`
- Lint: `go tool golangci-lint run ./...`
- Vulnerability scan: `go tool govulncheck ./...`
- Format: `go tool golangci-lint fmt ./...` (gofmt + goimports + golines, as the linter enforces)
- Apply fixers: `go fix ./...` (use `go fix -diff ./...` to preview)
- Tidy dependencies: `go mod tidy`
- Run example: `go run example/main.go`

## Dev Tools
- golangci-lint and govulncheck are pinned by `tool` directives in `go.mod`, so
  `go tool` always builds the pinned version with the module's Go toolchain.
- Upgrade a tool: `go get -tool <module>/cmd/<tool>@<version> && go mod tidy`.
- When upgrading golangci-lint, replace `.golangci.yml` with the matching release of
  https://github.com/maratori/golangci-lint-config and re-apply the overrides listed
  in its header.
- Line endings are LF everywhere; gofmt rejects CRLF. `.gitattributes` normalizes
  commits and checkouts (overriding `core.autocrlf`), `.editorconfig` sets editor
  defaults, and CI fails if a CRLF file is committed. Fix one with
  `git add --renormalize .`.

## Code Style
- **Go Version**: Go 1.27.1+ (the `go` directive pins a patch release so builds
  always include standard-library security fixes for `crypto/x509`)
- **Formatting**: Use `gofmt` standard formatting (enforced); tabs for indentation
- **Naming**: Follow Go conventions (camelCase for private, PascalCase for exported)
- **Errors**: Return errors, don't panic; wrap errors with context using `fmt.Errorf` with `%w`
- **Comments**: Exported functions/types must have doc comments starting with the name
- **Imports**: Group imports (stdlib, external, internal) with blank lines between groups (enforced by goimports `local-prefixes`)
- **Tests**: Call `t.Parallel()` in every test and subtest (enforced by `paralleltest`)
- **Context**: Pass `context.Context` as first parameter for functions making AWS calls
- **Types**: Use explicit type conversions; avoid implicit conversions
- **Error messages**: Start with lowercase, no trailing punctuation except for proper nouns
- **Dependencies**: AWS SDK v2, standard library crypto/x509 - minimize external dependencies

## Key Architecture
- Main struct: `Builder` - builds CSRs using AWS KMS keys (constructed by the `NewKMSCSRBuilder*` functions)
- KMS integration: Uses AWS SDK v2 for KMS operations (GetPublicKey, Sign)
- Certificate generation: Uses Go's crypto/x509 package for CSR creation
- Signer interface: Implements `crypto.Signer` via `kmsSigner` for KMS signing
- No cfssl dependency: Uses standard Go crypto/x509 for all certificate operations
- Extension handling: Custom ASN.1 encoding for BasicConstraints, KeyUsage, ExtKeyUsage
