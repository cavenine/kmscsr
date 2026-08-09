# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- `NewKMSCSRBuilderWithClient` for supplying a preconfigured KMS client
- Validation of subject alternative names before signing: DNS entries must be
  non-empty and unpadded, IP addresses must be 4 or 16 bytes
- Rejection of control characters in every subject field
- Rejection of non-ASCII subject alternative DNS names, which cannot be encoded
  as an `IA5String` (supply internationalized names in A-label form)
- `docs/e2e-testing.md` recording an end-to-end run against real AWS KMS, with
  instructions and cleanup steps for repeating it

### Changed
- Basic constraints are now requested on every CSR. A non-CA request states
  `cA=FALSE` (non-critical) instead of omitting the extension, matching the
  `csrbuilder` reference implementation
- The subject alternative name extension is now marked critical when the subject
  is empty, as required by RFC 5280 section 4.2.1.6
- Upgraded all dependencies, notably AWS SDK for Go v2 (`service/kms` v1.49.2 →
  v1.55.4) and cobra (v1.10.1 → v1.10.2)
- golangci-lint is now a `tool` dependency in `go.mod`, so `go tool
  golangci-lint run ./...` always builds it against the module's Go toolchain

### Fixed
- Empty or whitespace-only `--san-dns` entries produced a CSR with a malformed
  SAN extension instead of an error
- Malformed SAN IP addresses failed with an opaque parse error naming the
  generated request rather than the offending address
- `--kms-arn ""` and `--common-name ""` satisfied the CLI's required-flag check
- CLI runtime failures printed the full usage text after the error message, and
  a command construction failure exited silently
- Key usage encoding no longer emits a bit string whose declared length
  contradicts its content when no usage bits are set

## [0.0.1] - 2025-12-02

### Added
- Initial release of kmscsr
- Support for creating X.509 Certificate Signing Requests (CSRs) with AWS KMS keys
- AWS KMS integration using AWS SDK for Go v2
- Support for RSA and ECDSA key types
- Subject Distinguished Name configuration
- Subject Alternative Names (DNS and IP addresses)
- Key Usage and Extended Key Usage extensions
- Basic Constraints extension for CA certificates
- PEM encoding of CSRs
- Complete API documentation
- Usage examples
- AGENTS.md for AI coding assistants

### Features
- Automatic public key retrieval from AWS KMS
- KMS key validation (SIGN_VERIFY usage requirement)
- Support for SHA256, SHA384, and SHA512 signing algorithms
- crypto.Signer interface implementation for KMS signing
- Context-aware AWS API calls
- Comprehensive error handling and validation
