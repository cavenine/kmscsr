# Changelog

All notable changes to this project will be documented in this file.

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
