package kmscsr //nolint:testpackage // testing internals

import (
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"slices"
	"strings"
	"testing"
	"unicode"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// FuzzBuildWithKMS_SubjectAndSAN holds the input validation and the encoders to
// one contract: BuildWithKMS either rejects its input before anything is sent
// to KMS Sign, or returns a request whose signature verifies, whose fields
// parse back exactly as given, and which carries no control characters. The
// seed corpus runs as part of the normal test suite.
func FuzzBuildWithKMS_SubjectAndSAN(f *testing.F) {
	seeds := []struct{ commonName, organization, email, dnsName string }{
		{"example.com", "Example Corp", "admin@example.com", "www.example.com"},
		{"Müller", "Ünïcode GmbH", "", "xn--mller-kva.example"},
		{"*.example.com", "A & B", "a@b", "*.example.com"},
		{"", "", "", "example.com"},
		{"x\x00y", "", "", ""},
		{"example.com", "Evil\nCorp", "", ""},
		{"example.com", "", "admin@exämple.com", ""},
		{"example.com", "", "", "www.bank.com\x00.evil.com"},
		{"example.com", "", "", " padded.example.com"},
		{"bad\xffutf8", "", "", ""},
	}
	for _, seed := range seeds {
		f.Add(seed.commonName, seed.organization, seed.email, seed.dnsName)
	}

	publicKeyDER, privateKey := generateMockECDSAPublicKeyOnCurve(f, elliptic.P256())
	base := newSigningBuilder(
		f,
		&SubjectInfo{CommonName: "base.example.com"},
		publicKeyDER,
		types.KeySpecEccNistP256,
		types.SigningAlgorithmSpecEcdsaSha256,
		privateKey,
	)
	f.Fuzz(func(t *testing.T, commonName, organization, email, dnsName string) {
		subject := &SubjectInfo{CommonName: commonName, OrganizationName: organization, EmailAddress: email}
		// The constructor would refuse this subject, so no builder could exist.
		if validateBuilderInputs(t.Context(), subject, testARN) != nil {
			return
		}
		name, err := subjectName(subject)
		if err != nil {
			t.Fatalf("subjectName failed on validated input: %v", err)
		}

		client := &mockSigningKMSClient{signer: privateKey}
		builder := *base
		builder.kmsClient = client
		builder.Subject = name
		builder.SubjectAltDomains = nil
		if dnsName != "" {
			builder.SubjectAltDomains = []string{dnsName}
		}

		csrDER, err := builder.BuildWithKMS(t.Context())
		if err != nil {
			if client.signInput != nil {
				t.Fatalf("failed only after KMS signed: %v", err)
			}

			return
		}
		assertRoundTrip(t, csrDER, subject, dnsName)
	})
}

// assertRoundTrip checks that a signed request verifies, carries exactly the
// subject and DNS name it was built from, and contains no control characters.
func assertRoundTrip(t *testing.T, csrDER []byte, subject *SubjectInfo, dnsName string) {
	t.Helper()

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("failed to parse CSR: %v", err)
	}
	if signatureErr := csr.CheckSignature(); signatureErr != nil {
		t.Fatalf("signature verification failed: %v", signatureErr)
	}

	for _, value := range []string{subject.CommonName, subject.OrganizationName, subject.EmailAddress, dnsName} {
		if strings.ContainsFunc(value, unicode.IsControl) {
			t.Fatalf("signed a request containing a control character: %q", value)
		}
	}
	if csr.Subject.CommonName != subject.CommonName {
		t.Errorf("common name: expected %q, got %q", subject.CommonName, csr.Subject.CommonName)
	}
	if !slices.Equal(csr.Subject.Organization, nonEmpty(subject.OrganizationName)) {
		t.Errorf("organization: expected %q, got %q", subject.OrganizationName, csr.Subject.Organization)
	}
	if !slices.Equal(csr.DNSNames, nonEmpty(dnsName)) {
		t.Errorf("DNS names: expected %q, got %q", dnsName, csr.DNSNames)
	}

	emailOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
	var emails []string
	for _, attribute := range csr.Subject.Names {
		if value, ok := attribute.Value.(string); ok && attribute.Type.Equal(emailOID) {
			emails = append(emails, value)
		}
	}
	if !slices.Equal(emails, nonEmpty(subject.EmailAddress)) {
		t.Errorf("email: expected %q, got %q", subject.EmailAddress, emails)
	}
}

// nonEmpty returns value as a one-element slice, or nil if it is empty.
func nonEmpty(value string) []string {
	if value == "" {
		return nil
	}

	return []string{value}
}
