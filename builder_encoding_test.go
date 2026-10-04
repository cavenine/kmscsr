package kmscsr //nolint:testpackage // testing internals

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"testing"
)

// The extension encoders are hand-rolled, so these tests hold them to the exact
// DER that crypto/x509 produces for the same input, rather than only checking
// that the output decodes.

// stdlibCertificateExtension returns the extension crypto/x509 encodes for
// template when it issues a certificate from it.
func stdlibCertificateExtension(
	t *testing.T,
	key *ecdsa.PrivateKey,
	template *x509.Certificate,
	oid asn1.ObjectIdentifier,
) pkix.Extension {
	t.Helper()

	template.SerialNumber = big.NewInt(1)
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("crypto/x509 failed to create reference certificate: %v", err)
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		t.Fatalf("failed to parse reference certificate: %v", err)
	}
	for _, extension := range certificate.Extensions {
		if extension.Id.Equal(oid) {
			return extension
		}
	}
	t.Fatalf("crypto/x509 did not encode extension %v", oid)

	return pkix.Extension{}
}

// stdlibRequestExtension returns the extension crypto/x509 encodes for template
// when it creates a certificate request from it.
func stdlibRequestExtension(
	t *testing.T,
	key *ecdsa.PrivateKey,
	template *x509.CertificateRequest,
	oid asn1.ObjectIdentifier,
) pkix.Extension {
	t.Helper()

	requestDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatalf("crypto/x509 failed to create reference request: %v", err)
	}
	request, err := x509.ParseCertificateRequest(requestDER)
	if err != nil {
		t.Fatalf("failed to parse reference request: %v", err)
	}

	return findExtension(t, request, oid)
}

func TestKeyUsageExtension_GoldenDER(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		usage x509.KeyUsage
		der   []byte
	}{
		// The RSA leaf default: bits 0 and 2, so five unused trailing bits.
		{
			"RSA leaf default",
			x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			[]byte{0x03, 0x02, 0x05, 0xa0},
		},
		// The ECDSA leaf default: bit 0 alone, so seven unused trailing bits.
		{"ECDSA leaf default", x509.KeyUsageDigitalSignature, []byte{0x03, 0x02, 0x07, 0x80}},
		// The CA default: bits 5 and 6, so one unused trailing bit.
		{"CA default", x509.KeyUsageCertSign | x509.KeyUsageCRLSign, []byte{0x03, 0x02, 0x01, 0x06}},
		// decipherOnly is bit 8, the only one that needs a second byte.
		{"decipher only", x509.KeyUsageDecipherOnly, []byte{0x03, 0x03, 0x07, 0x00, 0x80}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			extension, err := keyUsageExtension(tt.usage)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !bytes.Equal(extension.Value, tt.der) {
				t.Fatalf("expected %x, got: %x", tt.der, extension.Value)
			}
		})
	}
}

func TestBasicConstraintsExtension_GoldenDER(t *testing.T) {
	t.Parallel()

	tests := []struct {
		isCA     bool
		der      []byte
		critical bool
	}{
		// cA is DEFAULT FALSE, and DER forbids encoding a default value, so a
		// non-CA request carries an empty SEQUENCE.
		{false, []byte{0x30, 0x00}, false},
		// cA TRUE and no pathLenConstraint.
		{true, []byte{0x30, 0x03, 0x01, 0x01, 0xff}, true},
	}

	for _, tt := range tests {
		extension, err := basicConstraintsExtension(tt.isCA)
		if err != nil {
			t.Fatalf("isCA=%v: unexpected error: %v", tt.isCA, err)
		}
		if !extension.Id.Equal(oidBasicConstraints()) {
			t.Errorf("isCA=%v: unexpected OID %v", tt.isCA, extension.Id)
		}
		if !bytes.Equal(extension.Value, tt.der) || extension.Critical != tt.critical {
			t.Errorf("isCA=%v: expected %x (critical=%v), got: %x (critical=%v)",
				tt.isCA, tt.der, tt.critical, extension.Value, extension.Critical)
		}
	}
}

func TestExtKeyUsageExtension_MatchesCryptoX509(t *testing.T) {
	t.Parallel()

	_, key := generateMockECDSAPublicKeyOnCurve(t, elliptic.P256())
	tests := []struct {
		name   string
		usages []x509.ExtKeyUsage
	}{
		{"leaf default", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}},
		{"OCSP signing", []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}},
		{"every supported usage", []x509.ExtKeyUsage{
			x509.ExtKeyUsageAny,
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageCodeSigning,
			x509.ExtKeyUsageEmailProtection,
			x509.ExtKeyUsageTimeStamping,
			x509.ExtKeyUsageOCSPSigning,
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			extension, err := extKeyUsageExtension(tt.usages)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			reference := stdlibCertificateExtension(t, key, &x509.Certificate{ExtKeyUsage: tt.usages}, oidExtKeyUsage())
			if !bytes.Equal(extension.Value, reference.Value) || extension.Critical != reference.Critical {
				t.Fatalf("got %x (critical=%v), crypto/x509 encodes %x (critical=%v)",
					extension.Value, extension.Critical, reference.Value, reference.Critical)
			}
		})
	}
}

func TestSubjectAltNameExtension_MatchesCryptoX509(t *testing.T) {
	t.Parallel()

	_, key := generateMockECDSAPublicKeyOnCurve(t, elliptic.P256())
	tests := []struct {
		name    string
		domains []string
		ips     []net.IP
	}{
		{"DNS names keep their order", []string{"www.example.com", "*.example.com", "example.com."}, nil},
		{"IPv4 parsed into 16 bytes", nil, []net.IP{net.ParseIP("192.0.2.1")}},
		{"IPv4 already 4 bytes", nil, []net.IP{net.IPv4(192, 0, 2, 1).To4()}},
		{"IPv4-mapped IPv6", nil, []net.IP{net.ParseIP("::ffff:192.0.2.1")}},
		{"IPv6", nil, []net.IP{net.ParseIP("2001:db8::1")}},
		{
			"DNS names before IP addresses",
			[]string{"www.example.com"},
			[]net.IP{net.ParseIP("2001:db8::1"), net.ParseIP("192.0.2.1")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			extension, err := subjectAltNameExtension(tt.domains, tt.ips, false)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			reference := stdlibRequestExtension(t, key, &x509.CertificateRequest{
				DNSNames:    tt.domains,
				IPAddresses: tt.ips,
			}, oidSubjectAltName())
			if !bytes.Equal(extension.Value, reference.Value) {
				t.Fatalf("got %x, crypto/x509 encodes %x", extension.Value, reference.Value)
			}
		})
	}
}
