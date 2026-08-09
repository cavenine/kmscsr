package kmscsr //nolint:testpackage // testing internals

import (
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// Extension OIDs asserted by the parity tests. These are functions rather than
// package variables because asn1.ObjectIdentifier is a slice and cannot be a
// constant.
func oidBasicConstraints() asn1.ObjectIdentifier { return asn1.ObjectIdentifier{2, 5, 29, 19} }
func oidKeyUsage() asn1.ObjectIdentifier         { return asn1.ObjectIdentifier{2, 5, 29, 15} }
func oidExtKeyUsage() asn1.ObjectIdentifier      { return asn1.ObjectIdentifier{2, 5, 29, 37} }
func oidSubjectAltName() asn1.ObjectIdentifier   { return asn1.ObjectIdentifier{2, 5, 29, 17} }

// findExtension returns the extension carrying oid.
func findExtension(t *testing.T, csr *x509.CertificateRequest, oid asn1.ObjectIdentifier) pkix.Extension {
	t.Helper()

	for _, extension := range csr.Extensions {
		if extension.Id.Equal(oid) {
			return extension
		}
	}
	t.Fatalf("extension %v not found in %#v", oid, csr.Extensions)

	return pkix.Extension{}
}

// decodeIsCA reads the cA field of a BasicConstraints extension value.
func decodeIsCA(t *testing.T, value []byte) bool {
	t.Helper()

	var constraints struct {
		IsCA bool `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(value, &constraints); err != nil {
		t.Fatalf("failed to decode basic constraints: %v", err)
	}

	return constraints.IsCA
}

// TestParity_BuildBasic mirrors csrbuilder's test_build_basic, the reference
// implementation this library was rewritten from. It pins the shape of a
// default non-CA request: four extensions, with the criticality RFC 5280
// prescribes for each.
func TestParity_BuildBasic(t *testing.T) {
	publicKeyDER, privateKey := generateMockECDSAPublicKeyOnCurve(t, elliptic.P256())
	builder := newSigningBuilder(
		t,
		&SubjectInfo{
			CountryName:         "US",
			StateOrProvinceName: "Massachusetts",
			LocalityName:        "Newbury",
			OrganizationName:    "Codex Non Sufficit LC",
			CommonName:          "Will Bond",
		},
		publicKeyDER,
		types.KeySpecEccNistP256,
		types.SigningAlgorithmSpecEcdsaSha256,
		privateKey,
	)
	builder.SubjectAltDomains = []string{"codexns.io", "codexns.com"}

	csrDER, err := builder.BuildWithKMS(t.Context())
	if err != nil {
		t.Fatalf("failed to build CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("failed to parse CSR: %v", err)
	}
	if signatureErr := csr.CheckSignature(); signatureErr != nil {
		t.Fatalf("signature verification failed: %v", signatureErr)
	}

	// sha256_ecdsa in the reference.
	if csr.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Errorf("expected ECDSA-SHA256, got: %v", csr.SignatureAlgorithm)
	}
	if len(csr.Extensions) != 4 {
		t.Fatalf("expected 4 extensions as in the reference, got %d: %#v", len(csr.Extensions), csr.Extensions)
	}

	basicConstraints := findExtension(t, csr, oidBasicConstraints())
	if basicConstraints.Critical {
		t.Error("basic constraints must be non-critical for a non-CA request")
	}
	if decodeIsCA(t, basicConstraints.Value) {
		t.Error("expected cA to be FALSE")
	}

	if keyUsage := findExtension(t, csr, oidKeyUsage()); !keyUsage.Critical {
		t.Error("key usage must be critical")
	} else if decoded := decodeKeyUsage(t, keyUsage.Value); decoded !=
		x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment {
		t.Errorf("expected digital_signature|key_encipherment, got: %v", decoded)
	}

	if extKeyUsage := findExtension(t, csr, oidExtKeyUsage()); extKeyUsage.Critical {
		t.Error("extended key usage must be non-critical")
	}
	assertExtKeyUsage(t, csr, []asn1.ObjectIdentifier{
		{1, 3, 6, 1, 5, 5, 7, 3, 1}, // server_auth
		{1, 3, 6, 1, 5, 5, 7, 3, 2}, // client_auth
	})

	if san := findExtension(t, csr, oidSubjectAltName()); san.Critical {
		t.Error("subject alternative name must be non-critical when the subject is populated")
	}
	if len(csr.DNSNames) != 2 || csr.DNSNames[0] != "codexns.io" || csr.DNSNames[1] != "codexns.com" {
		t.Errorf("unexpected DNS names: %#v", csr.DNSNames)
	}
}

// TestParity_CARequestBasicConstraints pins the CA variant: the reference marks
// basic constraints critical only when cA is TRUE.
func TestParity_CARequestBasicConstraints(t *testing.T) {
	builder := newRSASigningBuilder(t, &SubjectInfo{CommonName: "ca.example.com"})
	builder.SetCA(true)

	csrDER, err := builder.BuildWithKMS(t.Context())
	if err != nil {
		t.Fatalf("failed to build CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("failed to parse CSR: %v", err)
	}

	basicConstraints := findExtension(t, csr, oidBasicConstraints())
	if !basicConstraints.Critical {
		t.Error("basic constraints must be critical for a CA request")
	}
	if !decodeIsCA(t, basicConstraints.Value) {
		t.Error("expected cA to be TRUE")
	}
}

// TestParity_SANCriticalWhenSubjectEmpty covers RFC 5280 section 4.2.1.6: with
// an empty subject the SAN is the only identity, so it must be critical.
func TestParity_SANCriticalWhenSubjectEmpty(t *testing.T) {
	tests := []struct {
		name     string
		subject  SubjectInfo
		critical bool
	}{
		{"empty subject", SubjectInfo{}, true},
		{"populated subject", SubjectInfo{CommonName: "example.com"}, false},
		{"subject with only an email", SubjectInfo{EmailAddress: "admin@example.com"}, false},
		{"subject with only a country", SubjectInfo{CountryName: "US"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := newRSASigningBuilder(t, &tt.subject)
			builder.SubjectAltDomains = []string{"example.com"}

			csrDER, err := builder.BuildWithKMS(t.Context())
			if err != nil {
				t.Fatalf("failed to build CSR: %v", err)
			}
			csr, err := x509.ParseCertificateRequest(csrDER)
			if err != nil {
				t.Fatalf("failed to parse CSR: %v", err)
			}

			if san := findExtension(t, csr, oidSubjectAltName()); san.Critical != tt.critical {
				t.Errorf("expected SAN critical=%v, got: %v", tt.critical, san.Critical)
			}
		})
	}
}

// TestParity_SANEncodesIPv4AsFourBytes guards the encoding choice that keeps
// IPv4 addresses comparing equal after a round trip.
func TestParity_SANEncodesIPv4AsFourBytes(t *testing.T) {
	builder := newRSASigningBuilder(t, &SubjectInfo{CommonName: "example.com"})
	builder.SubjectAltIPs = []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("2001:db8::1")}

	csrDER, err := builder.BuildWithKMS(t.Context())
	if err != nil {
		t.Fatalf("failed to build CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("failed to parse CSR: %v", err)
	}

	if len(csr.IPAddresses) != 2 {
		t.Fatalf("expected 2 IP addresses, got: %#v", csr.IPAddresses)
	}
	if got := len(csr.IPAddresses[0]); got != net.IPv4len {
		t.Errorf("expected IPv4 to encode in 4 bytes, got %d", got)
	}
	if got := len(csr.IPAddresses[1]); got != net.IPv6len {
		t.Errorf("expected IPv6 to encode in 16 bytes, got %d", got)
	}
}

// TestParity_RejectsNonASCIIDNSName keeps the IA5String rule enforced now that
// the SAN extension is built here rather than by crypto/x509.
func TestParity_RejectsNonASCIIDNSName(t *testing.T) {
	builder := newRSASigningBuilder(t, &SubjectInfo{CommonName: "example.com"})
	builder.SubjectAltDomains = []string{"exämple.com"}

	_, err := builder.BuildWithKMS(t.Context())
	if err == nil || !strings.Contains(err.Error(), "ASCII") {
		t.Fatalf("expected non-ASCII DNS name error, got: %v", err)
	}
}
