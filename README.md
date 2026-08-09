# kmscsr

A Go library and CLI tool for creating and signing X.509 certificate signing requests (CSRs) with AWS KMS keys.

## Features

- Create X.509 CSRs signed by AWS KMS keys
- Support for RSA and ECDSA key types
- Subject Alternative Names (DNS and IP addresses)
- Configurable key usage and extended key usage extensions
- Full support for CA and non-CA certificate requests
- Pure Go implementation using Go 1.26
- Command-line interface for easy CSR generation

## Installation

### As a Library

```bash
go get github.com/cavenine/kmscsr
```

### As a CLI Tool

```bash
go install github.com/cavenine/kmscsr/cmd/kmscsr@latest
```

Or build from source:

```bash
git clone https://github.com/cavenine/kmscsr
cd kmscsr
go build ./cmd/kmscsr
```

## Dependencies

- AWS SDK for Go v2 (`github.com/aws/aws-sdk-go-v2`)
- Cobra CLI framework (`github.com/spf13/cobra`)
- Go 1.26.5 or later

## Usage

### Command Line Interface

Generate a CSR using the CLI:

```bash
# Basic CSR
kmscsr --kms-arn "arn:aws:kms:us-east-1:xxxx:key/yyyy" \
  --common-name "example.com" \
  --organization "Example Inc" \
  --country "US" \
  --state "Florida" \
  --locality "Tampa" \
  --output example.csr

# CSR with Subject Alternative Names
kmscsr --kms-arn "arn:aws:kms:us-east-1:xxxx:key/yyyy" \
  --common-name "example.com" \
  --san-dns "www.example.com" \
  --san-dns "api.example.com" \
  --san-ip "192.168.1.1" \
  --output example.csr

# CA certificate request
kmscsr --kms-arn "arn:aws:kms:us-east-1:xxxx:key/yyyy" \
  --common-name "Example CA" \
  --organization "Example Inc" \
  --ca \
  --output ca.csr

# Output to stdout
kmscsr --kms-arn "arn:aws:kms:us-east-1:xxxx:key/yyyy" \
  --common-name "example.com" \
  > example.csr
```

#### CLI Flags

**Required:**
- `--kms-arn` - AWS KMS key ARN
- `--common-name` - Common Name (CN) for the certificate

**Subject Fields (Optional):**
- `--country` - Country Name (C)
- `--state` - State or Province Name (ST)
- `--locality` - Locality Name (L)
- `--organization` - Organization Name (O)
- `--org-unit` - Organizational Unit Name (OU)
- `--email` - Email Address
- `--street` - Street Address
- `--postal-code` - Postal Code

**Certificate Options:**
- `--san-dns` - Subject Alternative Name DNS entries (can be specified multiple times)
- `--san-ip` - Subject Alternative Name IP addresses (can be specified multiple times)
- `--ca` - Generate a CA certificate request
- `-o, --output` - Output file path (default: stdout)
- `--timeout` - Maximum time for AWS KMS operations (default: `30s`; `0` disables the timeout)
- `-v, --version` - Print version, commit, build date, and Go version

### Library Usage

See [examples](example/main.go) for programmatic usage.

For cancellable AWS operations, prefer `NewKMSCSRBuilderWithContext` and pass
the same bounded context to `BuildWithKMS`. The legacy `NewKMSCSRBuilder`
constructor remains available for compatibility.

To control the region, endpoint, or credentials of the KMS client yourself, use
`NewKMSCSRBuilderWithClient` and pass any value satisfying the `KMSClient`
interface.

### Input Validation

Requests that would encode into a malformed CSR are rejected before any signing
call is made:

- Subject fields must not contain control characters (such as NUL or a line
  break), which downstream certificate tooling may truncate or misparse.
- The email address must contain only ASCII characters.
- Subject alternative DNS names must be non-empty, ASCII-only, and free of
  leading or trailing whitespace. Supply internationalized names in A-label
  form.
- Subject alternative IP addresses must be 4-byte or 16-byte addresses.

## AWS Configuration

Make sure your AWS credentials are configured. The library uses the AWS SDK's default credential chain:

```bash
export AWS_REGION=us-east-1
export AWS_ACCESS_KEY_ID=your-access-key
export AWS_SECRET_ACCESS_KEY=your-secret-key
```

Or use AWS profiles, IAM roles, or other credential providers supported by the AWS SDK.

## KMS Key Requirements

The KMS key must have:
- Key usage: `SIGN_VERIFY`
- Key spec: RSA or ECC key types
- Appropriate IAM permissions for `kms:GetPublicKey` and `kms:Sign`

## License

MIT License - see the [LICENSE](LICENSE) file for details.

## Documentation

- [API Documentation](docs/api.md) — detailed API reference
- [End-to-End Testing](docs/e2e-testing.md) — results of the last run against
  real AWS KMS, and how to repeat it

## Version

Current version: 1.0.0
