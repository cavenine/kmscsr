# Agent Guidelines for kmscsr

## Build/Lint/Test Commands
- Build: `go build ./...`
- Run all tests: `go test ./...`
- Run tests with coverage: `go test -cover ./...`
- Run single test: `go test -v -run TestName`
- Run specific package tests: `go test -v ./path/to/package`
- Lint: `go vet ./...`
- Format: `go fmt ./...`
- Tidy dependencies: `go mod tidy`
- Run example: `go run example/main.go`

## Code Style
- **Go Version**: Go 1.25+
- **Formatting**: Use `gofmt` standard formatting (enforced); tabs for indentation
- **Naming**: Follow Go conventions (camelCase for private, PascalCase for exported)
- **Errors**: Return errors, don't panic; wrap errors with context using `fmt.Errorf` with `%w`
- **Comments**: Exported functions/types must have doc comments starting with the name
- **Imports**: Group imports (stdlib, external, internal) with blank lines between groups
- **Context**: Pass `context.Context` as first parameter for functions making AWS calls
- **Types**: Use explicit type conversions; avoid implicit conversions
- **Error messages**: Start with lowercase, no trailing punctuation except for proper nouns
- **Dependencies**: AWS SDK v2, standard library crypto/x509 - minimize external dependencies

## Key Architecture
- Main struct: `KMSCSRBuilder` - builds CSRs using AWS KMS keys
- KMS integration: Uses AWS SDK v2 for KMS operations (GetPublicKey, Sign)
- Certificate generation: Uses Go's crypto/x509 package for CSR creation
- Signer interface: Implements `crypto.Signer` via `kmsSigner` for KMS signing
- No cfssl dependency: Uses standard Go crypto/x509 for all certificate operations
- Extension handling: Custom ASN.1 encoding for BasicConstraints, KeyUsage, ExtKeyUsage
