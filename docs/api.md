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
    HashAlgo          types.SigningAlgorithmSpec // Hash algorithm
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

## Complete Example

```go
package main

import (
    "context"
    "log"
    "net"
    "os"

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

    builder, err := kmscsr.NewKMSCSRBuilder(subject, kmsArn)
    if err != nil {
        log.Fatal(err)
    }

    // Add subject alternative names
    builder.SubjectAltDomains = []string{"www.example.com", "api.example.com"}
    builder.SubjectAltIPs = []net.IP{net.ParseIP("192.168.1.1")}

    // Build and sign the CSR
    ctx := context.Background()
    csrDER, err := builder.BuildWithKMS(ctx)
    if err != nil {
        log.Fatal(err)
    }

    // Save as PEM
    csrPEM := kmscsr.PEMEncode(csrDER)
    os.WriteFile("example.csr", csrPEM, 0644)
}
```

## Error Handling

The library returns descriptive errors for common failure scenarios:

- Invalid or missing KMS ARN
- KMS key with incorrect usage (must be SIGN_VERIFY)
- AWS authentication failures
- KMS signing failures
- Invalid subject information
- Certificate request creation errors

Always check errors returned by functions and methods.
