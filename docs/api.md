# kmscsr API Documentation

## Overview

`kmscsr` provides a high-level interface for creating X.509 Certificate Signing Requests (CSRs) signed by AWS KMS keys.

## Types

### `SubjectInfo`

Holds the subject distinguished name fields for the CSR.

```go
type SubjectInfo struct {
    CountryName            string  // Country (C)
    StateOrProvinceName    string  // State or Province (ST)
    LocalityName           string  // Locality/City (L)
    OrganizationName       string  // Organization (O)
    CommonName             string  // Common Name (CN)
    OrganizationalUnitName string  // Organizational Unit (OU)
    EmailAddress           string  // Email address
    StreetAddress          string  // Street address
    PostalCode             string  // Postal code
}
```

### `Builder`

The main builder type for creating CSRs with KMS signing.

```go
type Builder struct {
    Subject           *pkix.Name                // Subject DN information
    KMSArn            string                    // AWS KMS Key ARN
    HashAlgo          types.SigningAlgorithmSpec // Complete KMS signing algorithm
    CA                bool                      // Is this a CA certificate request
    SubjectAltDomains []string                  // DNS names for SAN extension
    SubjectAltIPs     []net.IP                  // IP addresses for SAN extension
    KeyUsage          x509.KeyUsage             // Key usage flags
    ExtKeyUsage       []x509.ExtKeyUsage        // Extended key usage
}
```

## Functions

### `NewKMSCSRBuilder`

Creates a new CSR builder with AWS KMS integration.

```go
func NewKMSCSRBuilder(subject *SubjectInfo, kmsArn string) (*Builder, error)
```

**Parameters:**
- `subject`: Subject information for the certificate request
- `kmsArn`: AWS KMS Key ARN (must have SIGN_VERIFY usage)

**Returns:**
- `*Builder`: Initialized builder instance
- `error`: Error if initialization fails

**Example:**
```go
subject := &kmscsr.SubjectInfo{
    CountryName:         "US",
    StateOrProvinceName: "California",
    LocalityName:        "San Francisco",
    OrganizationName:    "Example Corp",
    CommonName:          "example.com",
}

builder, err := kmscsr.NewKMSCSRBuilder(subject, kmsArn)
if err != nil {
    log.Fatal(err)
}
```

### `NewKMSCSRBuilderWithContext`

Creates a new CSR builder while applying cancellation and deadlines to AWS
configuration loading and KMS public-key retrieval. Prefer this constructor in
servers and command-line applications.

```go
func NewKMSCSRBuilderWithContext(ctx context.Context, subject *SubjectInfo, kmsArn string) (*Builder, error)
```

```go
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

builder, err := kmscsr.NewKMSCSRBuilderWithContext(ctx, subject, kmsArn)
```

### `NewKMSCSRBuilderWithClient`

Creates a new CSR builder that signs with a caller-supplied KMS client instead
of one constructed from the ambient AWS configuration. Use it to control the
region, endpoint, or credentials of the client, or to substitute a fake in
tests.

```go
func NewKMSCSRBuilderWithClient(ctx context.Context, subject *SubjectInfo, kmsArn string, kmsClient KMSClient) (*Builder, error)
```

`KMSClient` is satisfied by `*kms.Client` and by any type providing
`GetPublicKey` and `Sign`:

```go
type KMSClient interface {
    GetPublicKey(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
    Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
}
```

```go
cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("eu-west-1"))
if err != nil {
    log.Fatal(err)
}

builder, err := kmscsr.NewKMSCSRBuilderWithClient(ctx, subject, kmsArn, kms.NewFromConfig(cfg))
```

### `PEMEncode`

Encodes a DER-formatted CSR into PEM format.

```go
func PEMEncode(csrDER []byte) []byte
```

**Parameters:**
- `csrDER`: DER-encoded certificate request bytes

**Returns:**
- `[]byte`: PEM-encoded certificate request

**Example:**
```go
csrDER, _ := builder.BuildWithKMS(ctx)
csrPEM := kmscsr.PEMEncode(csrDER)
os.WriteFile("request.csr", csrPEM, 0644)
```

## Methods

### `SetCA`

Sets whether this is a CA certificate request. This automatically configures appropriate key usage extensions.

```go
func (b *Builder) SetCA(isCA bool)
```

**Parameters:**
- `isCA`: `true` for CA certificate requests, `false` for end-entity certificates

**Effects:**
- When `true`: Sets KeyUsage to `CertSign | CRLSign` and ExtKeyUsage to `OCSPSigning`
- When `false`: Sets KeyUsage to `DigitalSignature | KeyEncipherment` and ExtKeyUsage to `ServerAuth | ClientAuth`

**Example:**
```go
builder.SetCA(true)  // Configure as CA certificate
```

### Signing algorithm selection

`Builder.HashAlgo` is retained for API compatibility but represents a complete
AWS KMS `SigningAlgorithmSpec`, such as
`types.SigningAlgorithmSpecRsassaPkcs1V15Sha384`. The selected algorithm must be
advertised by the KMS key and compatible with its public key. Unsupported or
incompatible values cause `BuildWithKMS` to return an error.

### `BuildWithKMS`

Constructs and signs the CSR using AWS KMS.

```go
func (b *Builder) BuildWithKMS(ctx context.Context) ([]byte, error)
```

**Parameters:**
- `ctx`: Context for AWS API calls

**Returns:**
- `[]byte`: DER-encoded certificate request
- `error`: Error if CSR creation or signing fails

**Example:**
```go
ctx := context.Background()
csrDER, err := builder.BuildWithKMS(ctx)
if err != nil {
    log.Fatal(err)
}
```

## Supported Key Usage Values

The library supports standard X.509 key usage flags:

- `x509.KeyUsageDigitalSignature`
- `x509.KeyUsageContentCommitment`
- `x509.KeyUsageKeyEncipherment`
- `x509.KeyUsageDataEncipherment`
- `x509.KeyUsageKeyAgreement`
- `x509.KeyUsageCertSign`
- `x509.KeyUsageCRLSign`
- `x509.KeyUsageEncipherOnly`
- `x509.KeyUsageDecipherOnly`

## Supported Extended Key Usage Values

- `x509.ExtKeyUsageServerAuth`
- `x509.ExtKeyUsageClientAuth`
- `x509.ExtKeyUsageCodeSigning`
- `x509.ExtKeyUsageEmailProtection`
- `x509.ExtKeyUsageTimeStamping`
- `x509.ExtKeyUsageOCSPSigning`
- `x509.ExtKeyUsageAny`

## Complete Example

```go
package main

import (
    "context"
    "log"
    "net"
    "os"
    "time"

    "github.com/cavenine/kmscsr"
)

func main() {
    kmsArn := "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"

    subject := &kmscsr.SubjectInfo{
        CountryName:            "US",
        StateOrProvinceName:    "California",
        LocalityName:           "San Francisco",
        OrganizationName:       "Example Corp",
        OrganizationalUnitName: "Engineering",
        CommonName:             "example.com",
    }

    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    builder, err := kmscsr.NewKMSCSRBuilderWithContext(ctx, subject, kmsArn)
    if err != nil {
        log.Fatal(err)
    }

    // Add subject alternative names
    builder.SubjectAltDomains = []string{"www.example.com", "api.example.com"}
    builder.SubjectAltIPs = []net.IP{net.ParseIP("192.168.1.1")}

    // Build and sign the CSR
    csrDER, err := builder.BuildWithKMS(ctx)
    if err != nil {
        log.Fatal(err)
    }

    // Save as PEM
    csrPEM := kmscsr.PEMEncode(csrDER)
    os.WriteFile("example.csr", csrPEM, 0644)
}
```

## Generated Extensions

Every request carries a basic constraints extension, and the remaining
extensions appear when the corresponding builder field is set. Criticality
follows RFC 5280.

| Extension | OID | When present | Critical |
| --- | --- | --- | --- |
| Basic Constraints | 2.5.29.19 | Always (`cA=TRUE` after `SetCA(true)`, otherwise `cA=FALSE`) | Only when `cA=TRUE` |
| Key Usage | 2.5.29.15 | `KeyUsage != 0` | Yes |
| Extended Key Usage | 2.5.29.37 | `len(ExtKeyUsage) > 0` | No |
| Subject Alternative Name | 2.5.29.17 | Any `SubjectAltDomains` or `SubjectAltIPs` | Only when the subject is empty (RFC 5280 §4.2.1.6) |

A default non-CA request therefore contains basic constraints (`cA=FALSE`), key
usage (`digitalSignature`, `keyEncipherment`), and extended key usage
(`serverAuth`, `clientAuth`) — matching the
[csrbuilder](https://github.com/wbond/csrbuilder) reference implementation this
library was rewritten from.

## Input Validation

The library rejects inputs that would encode into a malformed CSR. Subject
validation happens at construction; subject alternative name validation happens
at the start of `BuildWithKMS`, before any signing call is made.

| Input | Rule |
| --- | --- |
| Any subject field | Must not contain control characters (NUL, line breaks, and similar), which downstream certificate tooling may truncate or misparse |
| `EmailAddress` | Must contain only ASCII characters, as it is encoded as an `IA5String` |
| `SubjectAltDomains` entries | Must be non-empty, ASCII-only, and free of leading or trailing whitespace |
| `SubjectAltIPs` entries | Must be 4-byte or 16-byte addresses |
| `KeyUsage` | Must set at least one of the nine supported bits and no others |
| `ExtKeyUsage` | Must contain only the supported usages listed above |

Non-ASCII characters are accepted in subject fields other than the email
address, so names such as `Müller GmbH` round-trip correctly.

## Error Handling

The library returns descriptive errors for common failure scenarios:

- Invalid or missing KMS ARN
- KMS key with incorrect usage (must be SIGN_VERIFY)
- AWS authentication failures
- KMS signing failures
- Invalid subject information
- Malformed subject alternative names
- Certificate request creation errors

`BuildWithKMS` additionally re-parses and verifies the signature of every CSR it
produces, so a successful return means the request is well-formed and correctly
signed by the KMS key.

Always check errors returned by functions and methods.
