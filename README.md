# kmscsr

A Go library for creating and signing X.509 certificate signing requests (CSRs) with AWS KMS keys.

## Features

- Create X.509 CSRs signed by AWS KMS keys
- Support for RSA and ECDSA key types
- Subject Alternative Names (DNS and IP addresses)
- Configurable key usage and extended key usage extensions
- Full support for CA and non-CA certificate requests
- Pure Go implementation using Go 1.25

## Installation

```bash
go get github.com/cavenine/kmscsr
```

## Dependencies

- AWS SDK for Go v2 (`github.com/aws/aws-sdk-go-v2`)
- Go 1.25 or later

## Usage

see [examples](example/main.go)

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
