# kmscsr

A Go library and CLI tool for creating and signing X.509 certificate signing requests (CSRs) with AWS KMS keys.

## Features

- Create X.509 CSRs signed by AWS KMS keys
- Support for RSA and ECDSA key types
- Subject Alternative Names (DNS and IP addresses)
- Configurable key usage and extended key usage extensions
- Full support for CA and non-CA certificate requests
- Pure Go implementation using Go 1.25
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
- Go 1.25 or later

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

### Library Usage

See [examples](example/main.go) for programmatic usage.

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

See [API Documentation](docs/api.md) for detailed API reference.

## Version

Current version: 1.0.0
