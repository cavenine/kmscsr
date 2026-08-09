package kmscsr //nolint:testpackage // testing internals

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

const testARN = "arn:aws:kms:us-east-1:123456789012:key/test-key-id"

// generateMockECDSAPublicKeyOnCurve builds a DER public key and signer for curve.
func generateMockECDSAPublicKeyOnCurve(t *testing.T, curve elliptic.Curve) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate %s key: %v", curve.Params().Name, err)
	}
	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal %s public key: %v", curve.Params().Name, err)
	}

	return publicKeyDER, privateKey
}

// newSigningBuilder returns a builder backed by a KMS mock that really signs.
func newSigningBuilder(
	t *testing.T,
	subject *SubjectInfo,
	publicKeyDER []byte,
	keySpec types.KeySpec,
	signAlgo types.SigningAlgorithmSpec,
	signer crypto.Signer,
) *Builder {
	t.Helper()

	builder, err := newKMSCSRBuilderWithMock(subject, testARN, &mockSigningKMSClient{
		publicKey: publicKeyDER,
		keyUsage:  types.KeyUsageTypeSignVerify,
		keySpec:   keySpec,
		signAlgo:  signAlgo,
		signer:    signer,
	})
	if err != nil {
		t.Fatalf("failed to create builder: %v", err)
	}

	return builder
}

// newRSASigningBuilder returns a builder over a freshly generated RSA key.
func newRSASigningBuilder(t *testing.T, subject *SubjectInfo) *Builder {
	t.Helper()

	publicKeyDER, privateKey, err := generateMockRSAPublicKey()
	if err != nil {
		t.Fatalf("failed to generate mock public key: %v", err)
	}

	return newSigningBuilder(
		t,
		subject,
		publicKeyDER,
		types.KeySpecRsa2048,
		types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
		privateKey,
	)
}

func TestNewKMSCSRBuilder_NilClient(t *testing.T) {
	_, err := newKMSCSRBuilder(t.Context(), &SubjectInfo{CommonName: "test.example.com"}, testARN, nil)
	if err == nil || err.Error() != "KMS client cannot be nil" {
		t.Fatalf("expected nil client error, got: %v", err)
	}
}

func TestNewKMSCSRBuilderWithClient(t *testing.T) {
	publicKeyDER, _, err := generateMockRSAPublicKey()
	if err != nil {
		t.Fatalf("failed to generate mock public key: %v", err)
	}

	builder, err := NewKMSCSRBuilderWithClient(
		t.Context(),
		&SubjectInfo{CommonName: "client.example.com"},
		testARN,
		&mockKMSClient{
			publicKey: publicKeyDER,
			keyUsage:  types.KeyUsageTypeSignVerify,
			keySpec:   types.KeySpecRsa2048,
			signAlgo:  types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if builder.Subject.CommonName != "client.example.com" {
		t.Fatalf("unexpected common name: %s", builder.Subject.CommonName)
	}
	if builder.HashAlgo != types.SigningAlgorithmSpecRsassaPkcs1V15Sha256 {
		t.Fatalf("unexpected default algorithm: %s", builder.HashAlgo)
	}

	if _, nilSubjectErr := NewKMSCSRBuilderWithClient(
		t.Context(), nil, testARN, &mockKMSClient{},
	); nilSubjectErr == nil {
		t.Fatal("expected nil subject error")
	}
}

func TestBuildWithKMS_ReportsKeyUsageExtensionFailure(t *testing.T) {
	builder := newRSASigningBuilder(t, &SubjectInfo{CommonName: "test.example.com"})
	builder.KeyUsage = x509.KeyUsage(1 << 15)

	_, err := builder.BuildWithKMS(t.Context())
	if err == nil || !strings.Contains(err.Error(), "failed to create key usage extension") {
		t.Fatalf("expected key usage extension error, got: %v", err)
	}
}

func TestResolveSigningAlgorithm_UnmappableAlgorithm(t *testing.T) {
	builder := newRSASigningBuilder(t, &SubjectInfo{CommonName: "test.example.com"})
	// Advertised by KMS but deliberately unimplemented here.
	builder.HashAlgo = types.SigningAlgorithmSpecRsassaPssSha256
	builder.supportedSigningAlgorithms = []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecRsassaPssSha256}

	_, _, err := builder.resolveSigningAlgorithm()
	if err == nil || !strings.Contains(err.Error(), "unsupported signing algorithm") {
		t.Fatalf("expected unsupported signing algorithm error, got: %v", err)
	}
}

func TestValidateBuilderInputs_RejectsNonASCIIEmail(t *testing.T) {
	err := validateBuilderInputs(t.Context(), &SubjectInfo{EmailAddress: "admin@exämple.com"}, testARN)
	if err == nil || !strings.Contains(err.Error(), "ASCII") {
		t.Fatalf("expected non-ASCII email error, got: %v", err)
	}
}

func TestValidateBuilderInputs_RejectsControlCharacters(t *testing.T) {
	// field is both the subtest name and the label expected in the error.
	tests := []struct {
		field   string
		subject SubjectInfo
	}{
		{"country name", SubjectInfo{CountryName: "U\x00S"}},
		{"state or province name", SubjectInfo{StateOrProvinceName: "CA\n"}},
		{"locality name", SubjectInfo{LocalityName: "San\rFrancisco"}},
		{"organization name", SubjectInfo{OrganizationName: "Acme\x1b"}},
		{"common name", SubjectInfo{CommonName: "example.com\n"}},
		{"organizational unit name", SubjectInfo{OrganizationalUnitName: "Eng\t"}},
		{"email address", SubjectInfo{EmailAddress: "admin@example.com\x00"}},
		{"street address", SubjectInfo{StreetAddress: "1 Main\x7f"}},
		{"postal code", SubjectInfo{PostalCode: "12\x0b345"}},
	}

	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			err := validateBuilderInputs(t.Context(), &tt.subject, testARN)
			if err == nil || !strings.Contains(err.Error(), tt.field) {
				t.Fatalf("expected %s control character error, got: %v", tt.field, err)
			}
		})
	}
}

func TestValidateBuilderInputs_AllowsNonASCIISubjectFields(t *testing.T) {
	// Non-ASCII is legitimate in a DN; only the email attribute is IA5-limited.
	err := validateBuilderInputs(t.Context(), &SubjectInfo{OrganizationName: "Müller GmbH"}, testARN)
	if err != nil {
		t.Fatalf("expected UTF-8 organization name to be accepted, got: %v", err)
	}
}

func TestSubjectName_NilSubject(t *testing.T) {
	if _, err := subjectName(nil); err == nil {
		t.Fatal("expected nil subject error")
	}
}

func TestLoadPublicKey_GetPublicKeyError(t *testing.T) {
	sentinel := errors.New("kms unavailable")
	_, err := newKMSCSRBuilderWithMock(
		&SubjectInfo{CommonName: "test.example.com"},
		testARN,
		&mockKMSClient{getPublicKeyErr: sentinel},
	)
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected wrapped KMS error, got: %v", err)
	}
}

func TestLoadPublicKey_RejectsNonSigningKey(t *testing.T) {
	publicKeyDER, _, err := generateMockRSAPublicKey()
	if err != nil {
		t.Fatalf("failed to generate mock public key: %v", err)
	}

	_, err = newKMSCSRBuilderWithMock(
		&SubjectInfo{CommonName: "test.example.com"},
		testARN,
		&mockKMSClient{
			publicKey: publicKeyDER,
			keyUsage:  types.KeyUsageTypeEncryptDecrypt,
			keySpec:   types.KeySpecRsa2048,
			signAlgo:  types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
		},
	)
	if err == nil || !strings.Contains(err.Error(), "SIGN_VERIFY") {
		t.Fatalf("expected SIGN_VERIFY usage error, got: %v", err)
	}
}

func TestLoadPublicKey_RejectsUnparsablePublicKey(t *testing.T) {
	_, err := newKMSCSRBuilderWithMock(
		&SubjectInfo{CommonName: "test.example.com"},
		testARN,
		&mockKMSClient{
			publicKey: []byte("not-a-der-public-key"),
			keyUsage:  types.KeyUsageTypeSignVerify,
			keySpec:   types.KeySpecRsa2048,
			signAlgo:  types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
		},
	)
	if err == nil || !strings.Contains(err.Error(), "failed to parse public key") {
		t.Fatalf("expected public key parse error, got: %v", err)
	}
}

func TestLoadPublicKey_RejectsUnsupportedKeyType(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}
	publicKeyDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("failed to marshal ed25519 public key: %v", err)
	}

	_, err = newKMSCSRBuilderWithMock(
		&SubjectInfo{CommonName: "test.example.com"},
		testARN,
		&mockKMSClient{
			publicKey: publicKeyDER,
			keyUsage:  types.KeyUsageTypeSignVerify,
			signAlgo:  types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
		},
	)
	if err == nil || !strings.Contains(err.Error(), "unsupported public key type") {
		t.Fatalf("expected unsupported key type error, got: %v", err)
	}
}

func TestLoadPublicKey_RejectsUnadvertisedAlgorithms(t *testing.T) {
	publicKeyDER, _, err := generateMockRSAPublicKey()
	if err != nil {
		t.Fatalf("failed to generate mock public key: %v", err)
	}

	// KMS advertises only PSS, which this library does not implement.
	_, err = newKMSCSRBuilderWithMock(
		&SubjectInfo{CommonName: "test.example.com"},
		testARN,
		&mockKMSClient{
			publicKey: publicKeyDER,
			keyUsage:  types.KeyUsageTypeSignVerify,
			keySpec:   types.KeySpecRsa2048,
			signAlgo:  types.SigningAlgorithmSpecRsassaPssSha256,
		},
	)
	if err == nil || !strings.Contains(err.Error(), "does not advertise") {
		t.Fatalf("expected unadvertised algorithm error, got: %v", err)
	}
}

func TestBuildWithKMS_ECDSACurves(t *testing.T) {
	tests := []struct {
		name     string
		curve    elliptic.Curve
		keySpec  types.KeySpec
		signAlgo types.SigningAlgorithmSpec
		expected x509.SignatureAlgorithm
	}{
		{
			"P-384", elliptic.P384(), types.KeySpecEccNistP384,
			types.SigningAlgorithmSpecEcdsaSha384, x509.ECDSAWithSHA384,
		},
		{
			"P-521", elliptic.P521(), types.KeySpecEccNistP521,
			types.SigningAlgorithmSpecEcdsaSha512, x509.ECDSAWithSHA512,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			publicKeyDER, privateKey := generateMockECDSAPublicKeyOnCurve(t, tt.curve)
			builder := newSigningBuilder(
				t,
				&SubjectInfo{CommonName: "ecdsa.example.com"},
				publicKeyDER,
				tt.keySpec,
				tt.signAlgo,
				privateKey,
			)
			if builder.HashAlgo != tt.signAlgo {
				t.Fatalf("expected default algorithm %s, got: %s", tt.signAlgo, builder.HashAlgo)
			}

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
			if csr.SignatureAlgorithm != tt.expected {
				t.Fatalf("expected %v, got: %v", tt.expected, csr.SignatureAlgorithm)
			}
		})
	}
}

func TestBuildWithKMS_NilContext(t *testing.T) {
	builder := newRSASigningBuilder(t, &SubjectInfo{CommonName: "test.example.com"})

	//nolint:staticcheck // explicitly verifies rejection of a nil context
	if _, err := builder.BuildWithKMS(nil); err == nil || err.Error() != "context cannot be nil" {
		t.Fatalf("expected nil context error, got: %v", err)
	}
}

func TestBuildWithKMS_NilSubject(t *testing.T) {
	builder := newRSASigningBuilder(t, &SubjectInfo{CommonName: "test.example.com"})
	builder.Subject = nil

	if _, err := builder.BuildWithKMS(t.Context()); err == nil || err.Error() != "subject cannot be nil" {
		t.Fatalf("expected nil subject error, got: %v", err)
	}
}

func TestBuildWithKMS_RejectsMalformedSANs(t *testing.T) {
	tests := []struct {
		name    string
		domains []string
		ips     []net.IP
		wantErr string
	}{
		{"empty domain", []string{""}, nil, "cannot be empty"},
		{"whitespace domain", []string{"   "}, nil, "cannot be empty"},
		{"padded domain", []string{" example.com"}, nil, "whitespace"},
		{"trailing space domain", []string{"example.com "}, nil, "whitespace"},
		{"nil ip", nil, []net.IP{nil}, "invalid subject alternative IP"},
		{"short ip", nil, []net.IP{{1, 2, 3}}, "invalid subject alternative IP"},
		{"odd length ip", nil, []net.IP{{1, 2, 3, 4, 5}}, "invalid subject alternative IP"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := newRSASigningBuilder(t, &SubjectInfo{CommonName: "test.example.com"})
			builder.SubjectAltDomains = tt.domains
			builder.SubjectAltIPs = tt.ips

			_, err := builder.BuildWithKMS(t.Context())
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected %q, got: %v", tt.wantErr, err)
			}
		})
	}
}

func TestBuildWithKMS_AcceptsValidSANs(t *testing.T) {
	builder := newRSASigningBuilder(t, &SubjectInfo{CommonName: "test.example.com"})
	builder.SubjectAltDomains = []string{"www.example.com"}
	builder.SubjectAltIPs = []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("2001:db8::1")}

	csrDER, err := builder.BuildWithKMS(t.Context())
	if err != nil {
		t.Fatalf("failed to build CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("failed to parse CSR: %v", err)
	}
	if len(csr.DNSNames) != 1 || csr.DNSNames[0] != "www.example.com" {
		t.Fatalf("unexpected DNS names: %#v", csr.DNSNames)
	}
	if len(csr.IPAddresses) != 2 {
		t.Fatalf("expected 2 IP addresses, got: %#v", csr.IPAddresses)
	}
	if !csr.IPAddresses[0].Equal(net.ParseIP("192.0.2.1")) ||
		!csr.IPAddresses[1].Equal(net.ParseIP("2001:db8::1")) {
		t.Fatalf("unexpected IP addresses: %#v", csr.IPAddresses)
	}
}

func TestBuildWithKMS_CAExtensionEncoding(t *testing.T) {
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

	basicConstraintsOID := asn1.ObjectIdentifier{2, 5, 29, 19}
	found := false
	for _, extension := range csr.Extensions {
		if !extension.Id.Equal(basicConstraintsOID) {
			continue
		}
		found = true
		if !extension.Critical {
			t.Error("expected basic constraints to be critical")
		}
		var constraints struct {
			IsCA bool `asn1:"optional"`
		}
		if _, decodeErr := asn1.Unmarshal(extension.Value, &constraints); decodeErr != nil {
			t.Fatalf("failed to decode basic constraints: %v", decodeErr)
		}
		if !constraints.IsCA {
			t.Error("expected cA to be TRUE")
		}
	}
	if !found {
		t.Fatal("basic constraints extension not found")
	}

	assertExtKeyUsage(t, csr, []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 9}})
}

func TestBuildWithKMS_DefaultExtKeyUsage(t *testing.T) {
	builder := newRSASigningBuilder(t, &SubjectInfo{CommonName: "leaf.example.com"})

	csrDER, err := builder.BuildWithKMS(t.Context())
	if err != nil {
		t.Fatalf("failed to build CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("failed to parse CSR: %v", err)
	}

	assertExtKeyUsage(t, csr, []asn1.ObjectIdentifier{
		{1, 3, 6, 1, 5, 5, 7, 3, 1},
		{1, 3, 6, 1, 5, 5, 7, 3, 2},
	})
}

func TestBuildWithKMS_PropagatesKMSSignError(t *testing.T) {
	publicKeyDER, privateKey, err := generateMockRSAPublicKey()
	if err != nil {
		t.Fatalf("failed to generate mock public key: %v", err)
	}
	sentinel := errors.New("access denied")

	builder, err := newKMSCSRBuilderWithMock(&SubjectInfo{CommonName: "test.example.com"}, testARN,
		&mockSigningKMSClient{
			publicKey: publicKeyDER,
			keyUsage:  types.KeyUsageTypeSignVerify,
			keySpec:   types.KeySpecRsa2048,
			signAlgo:  types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
			signer:    privateKey,
		})
	if err != nil {
		t.Fatalf("failed to create builder: %v", err)
	}
	builder.kmsClient = &mockSigningKMSClient{signErr: sentinel}

	if _, buildErr := builder.BuildWithKMS(t.Context()); !errors.Is(buildErr, sentinel) {
		t.Fatalf("expected wrapped KMS sign error, got: %v", buildErr)
	}
}

func TestKMSSigner_RejectsMismatchedOptions(t *testing.T) {
	signer := &kmsSigner{signAlgo: types.SigningAlgorithmSpecRsassaPkcs1V15Sha256}
	digest := make([]byte, crypto.SHA256.Size())

	if _, err := signer.Sign(rand.Reader, digest, nil); err == nil ||
		!strings.Contains(err.Error(), "does not match") {
		t.Fatalf("expected hash mismatch error for nil opts, got: %v", err)
	}
	if _, err := signer.Sign(rand.Reader, digest, crypto.SHA512); err == nil ||
		!strings.Contains(err.Error(), "does not match") {
		t.Fatalf("expected hash mismatch error, got: %v", err)
	}
}

func TestKMSSigner_RejectsWrongDigestLength(t *testing.T) {
	signer := &kmsSigner{signAlgo: types.SigningAlgorithmSpecEcdsaSha256}

	_, err := signer.Sign(rand.Reader, []byte("short"), crypto.SHA256)
	if err == nil || !strings.Contains(err.Error(), "digest length") {
		t.Fatalf("expected digest length error, got: %v", err)
	}
}

func TestKMSSigner_RejectsUnsupportedAlgorithm(t *testing.T) {
	signer := &kmsSigner{signAlgo: types.SigningAlgorithmSpec("UNSUPPORTED")}

	if _, err := signer.Sign(rand.Reader, nil, crypto.SHA256); err == nil ||
		!strings.Contains(err.Error(), "unsupported signing algorithm") {
		t.Fatalf("expected unsupported algorithm error, got: %v", err)
	}
}

func TestKMSSigner_Public(t *testing.T) {
	_, privateKey, err := generateMockRSAPublicKey()
	if err != nil {
		t.Fatalf("failed to generate mock public key: %v", err)
	}
	signer := &kmsSigner{publicKey: &privateKey.PublicKey}

	if signer.Public() != crypto.PublicKey(&privateKey.PublicKey) {
		t.Fatal("Public did not return the configured public key")
	}
}

func TestKMSSigner_RejectsEmptySignOutput(t *testing.T) {
	signer := &kmsSigner{
		ctx:       context.Background(),
		kmsClient: &nilOutputKMSClient{},
		signAlgo:  types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
	}

	_, err := signer.Sign(rand.Reader, make([]byte, crypto.SHA256.Size()), crypto.SHA256)
	if err == nil || !strings.Contains(err.Error(), "empty signature") {
		t.Fatalf("expected empty signature error, got: %v", err)
	}
}

func TestKeyUsageExtension_RejectsZero(t *testing.T) {
	if _, err := keyUsageExtension(0); err == nil || !strings.Contains(err.Error(), "at least one bit") {
		t.Fatalf("expected zero key usage error, got: %v", err)
	}
}

func TestKeyUsageExtension_CombinedBits(t *testing.T) {
	usage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageDecipherOnly
	extension, err := keyUsageExtension(usage)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decoded := decodeKeyUsage(t, extension.Value); decoded != usage {
		t.Fatalf("expected %v, got: %v", usage, decoded)
	}
	if !extension.Critical {
		t.Error("expected key usage extension to be critical")
	}
}

func TestExtKeyUsageExtension_RejectsEmpty(t *testing.T) {
	if _, err := extKeyUsageExtension(nil); err == nil || !strings.Contains(err.Error(), "cannot be empty") {
		t.Fatalf("expected empty extended key usage error, got: %v", err)
	}
}

func TestExtKeyUsageOID_AllSupportedUsages(t *testing.T) {
	tests := []struct {
		usage x509.ExtKeyUsage
		oid   asn1.ObjectIdentifier
	}{
		{x509.ExtKeyUsageAny, asn1.ObjectIdentifier{2, 5, 29, 37, 0}},
		{x509.ExtKeyUsageServerAuth, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}},
		{x509.ExtKeyUsageClientAuth, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}},
		{x509.ExtKeyUsageCodeSigning, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}},
		{x509.ExtKeyUsageEmailProtection, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}},
		{x509.ExtKeyUsageTimeStamping, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}},
		{x509.ExtKeyUsageOCSPSigning, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}},
	}

	for _, tt := range tests {
		oid, ok := extKeyUsageOID(tt.usage)
		if !ok || !oid.Equal(tt.oid) {
			t.Errorf("usage %d: expected %v, got %v (ok=%v)", tt.usage, tt.oid, oid, ok)
		}
	}

	if _, ok := extKeyUsageOID(x509.ExtKeyUsage(999)); ok {
		t.Error("expected unsupported extended key usage to be rejected")
	}
}

func TestGetSignatureAlgorithm_Unsupported(t *testing.T) {
	_, err := getSignatureAlgorithm(types.SigningAlgorithmSpecRsassaPssSha256)
	if err == nil || !strings.Contains(err.Error(), "unsupported signing algorithm") {
		t.Fatalf("expected unsupported signing algorithm error, got: %v", err)
	}
}

func TestHashForSigningAlgorithm(t *testing.T) {
	tests := []struct {
		algo     types.SigningAlgorithmSpec
		expected crypto.Hash
	}{
		{types.SigningAlgorithmSpecRsassaPkcs1V15Sha256, crypto.SHA256},
		{types.SigningAlgorithmSpecRsassaPkcs1V15Sha384, crypto.SHA384},
		{types.SigningAlgorithmSpecRsassaPkcs1V15Sha512, crypto.SHA512},
		{types.SigningAlgorithmSpecEcdsaSha256, crypto.SHA256},
		{types.SigningAlgorithmSpecEcdsaSha384, crypto.SHA384},
		{types.SigningAlgorithmSpecEcdsaSha512, crypto.SHA512},
	}

	for _, tt := range tests {
		hash, err := hashForSigningAlgorithm(tt.algo)
		if err != nil || hash != tt.expected {
			t.Errorf("%s: expected %v, got %v (err=%v)", tt.algo, tt.expected, hash, err)
		}
	}

	if _, err := hashForSigningAlgorithm(types.SigningAlgorithmSpecRsassaPssSha512); err == nil {
		t.Error("expected unsupported signing algorithm error")
	}
}

func TestDefaultSigningAlgorithm(t *testing.T) {
	_, rsaKey, err := generateMockRSAPublicKey()
	if err != nil {
		t.Fatalf("failed to generate mock public key: %v", err)
	}
	tests := []struct {
		name      string
		publicKey crypto.PublicKey
		supported []types.SigningAlgorithmSpec
		expected  types.SigningAlgorithmSpec
	}{
		{
			name:      "RSA prefers SHA-256",
			publicKey: &rsaKey.PublicKey,
			supported: []types.SigningAlgorithmSpec{
				types.SigningAlgorithmSpecRsassaPkcs1V15Sha512,
				types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
			},
			expected: types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
		},
		{
			name:      "RSA falls back to SHA-384",
			publicKey: &rsaKey.PublicKey,
			supported: []types.SigningAlgorithmSpec{
				types.SigningAlgorithmSpecRsassaPkcs1V15Sha512,
				types.SigningAlgorithmSpecRsassaPkcs1V15Sha384,
			},
			expected: types.SigningAlgorithmSpecRsassaPkcs1V15Sha384,
		},
		{
			name:      "RSA falls back to SHA-512",
			publicKey: &rsaKey.PublicKey,
			supported: []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecRsassaPkcs1V15Sha512},
			expected:  types.SigningAlgorithmSpecRsassaPkcs1V15Sha512,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			algo, algoErr := defaultSigningAlgorithm(tt.publicKey, tt.supported)
			if algoErr != nil {
				t.Fatalf("unexpected error: %v", algoErr)
			}
			if algo != tt.expected {
				t.Fatalf("expected %s, got: %s", tt.expected, algo)
			}
		})
	}
}

func TestDefaultSigningAlgorithm_ECDSACurves(t *testing.T) {
	tests := []struct {
		curve    elliptic.Curve
		expected types.SigningAlgorithmSpec
	}{
		{elliptic.P256(), types.SigningAlgorithmSpecEcdsaSha256},
		{elliptic.P384(), types.SigningAlgorithmSpecEcdsaSha384},
		{elliptic.P521(), types.SigningAlgorithmSpecEcdsaSha512},
	}
	all := []types.SigningAlgorithmSpec{
		types.SigningAlgorithmSpecEcdsaSha256,
		types.SigningAlgorithmSpecEcdsaSha384,
		types.SigningAlgorithmSpecEcdsaSha512,
	}

	for _, tt := range tests {
		t.Run(tt.curve.Params().Name, func(t *testing.T) {
			_, privateKey := generateMockECDSAPublicKeyOnCurve(t, tt.curve)
			algo, err := defaultSigningAlgorithm(&privateKey.PublicKey, all)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if algo != tt.expected {
				t.Fatalf("expected %s, got: %s", tt.expected, algo)
			}
		})
	}
}

func TestDefaultSigningAlgorithm_UnsupportedCurve(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate P-224 key: %v", err)
	}

	_, err = defaultSigningAlgorithm(&privateKey.PublicKey, []types.SigningAlgorithmSpec{
		types.SigningAlgorithmSpecEcdsaSha256,
	})
	if err == nil || !strings.Contains(err.Error(), "unsupported ECDSA curve size") {
		t.Fatalf("expected unsupported curve error, got: %v", err)
	}
}

func TestDefaultSigningAlgorithm_NoAdvertisedAlgorithms(t *testing.T) {
	_, rsaKey, err := generateMockRSAPublicKey()
	if err != nil {
		t.Fatalf("failed to generate mock public key: %v", err)
	}

	_, err = defaultSigningAlgorithm(&rsaKey.PublicKey, nil)
	if err == nil || !strings.Contains(err.Error(), "does not advertise") {
		t.Fatalf("expected unadvertised algorithm error, got: %v", err)
	}
}

func TestResolveSigningAlgorithm_Errors(t *testing.T) {
	rsaBuilder := newRSASigningBuilder(t, &SubjectInfo{CommonName: "test.example.com"})

	t.Run("empty algorithm", func(t *testing.T) {
		builder := *rsaBuilder
		builder.HashAlgo = ""
		if _, _, err := builder.resolveSigningAlgorithm(); err == nil ||
			!strings.Contains(err.Error(), "cannot be empty") {
			t.Fatalf("expected empty algorithm error, got: %v", err)
		}
	})

	t.Run("algorithm not advertised by KMS", func(t *testing.T) {
		builder := *rsaBuilder
		builder.HashAlgo = types.SigningAlgorithmSpecRsassaPkcs1V15Sha512
		if _, _, err := builder.resolveSigningAlgorithm(); err == nil ||
			!strings.Contains(err.Error(), "does not support") {
			t.Fatalf("expected unsupported algorithm error, got: %v", err)
		}
	})

	t.Run("ECDSA algorithm on RSA key", func(t *testing.T) {
		builder := *rsaBuilder
		builder.HashAlgo = types.SigningAlgorithmSpecEcdsaSha256
		builder.supportedSigningAlgorithms = []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEcdsaSha256}
		if _, _, err := builder.resolveSigningAlgorithm(); err == nil ||
			!strings.Contains(err.Error(), "incompatible with RSA") {
			t.Fatalf("expected RSA incompatibility error, got: %v", err)
		}
	})

	t.Run("RSA algorithm on ECDSA key", func(t *testing.T) {
		publicKeyDER, privateKey := generateMockECDSAPublicKeyOnCurve(t, elliptic.P256())
		builder := newSigningBuilder(
			t,
			&SubjectInfo{CommonName: "test.example.com"},
			publicKeyDER,
			types.KeySpecEccNistP256,
			types.SigningAlgorithmSpecEcdsaSha256,
			privateKey,
		)
		builder.HashAlgo = types.SigningAlgorithmSpecRsassaPkcs1V15Sha256
		builder.supportedSigningAlgorithms = []types.SigningAlgorithmSpec{
			types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
		}
		if _, _, err := builder.resolveSigningAlgorithm(); err == nil ||
			!strings.Contains(err.Error(), "incompatible with ECDSA") {
			t.Fatalf("expected ECDSA incompatibility error, got: %v", err)
		}
	})

	t.Run("unsupported public key type", func(t *testing.T) {
		builder := *rsaBuilder
		builder.publicKey = "not-a-key"
		if _, _, err := builder.resolveSigningAlgorithm(); err == nil ||
			!strings.Contains(err.Error(), "unsupported public key type") {
			t.Fatalf("expected unsupported key type error, got: %v", err)
		}
	})
}

// nilOutputKMSClient returns a nil SignOutput to exercise the empty-signature guard.
type nilOutputKMSClient struct{}

func (c *nilOutputKMSClient) GetPublicKey(
	_ context.Context,
	_ *kms.GetPublicKeyInput,
	_ ...func(*kms.Options),
) (*kms.GetPublicKeyOutput, error) {
	return nil, errors.New("not implemented")
}

func (c *nilOutputKMSClient) Sign(
	_ context.Context,
	_ *kms.SignInput,
	_ ...func(*kms.Options),
) (*kms.SignOutput, error) {
	return nil, nil //nolint:nilnil // intentionally simulates a malformed SDK response
}

func assertExtKeyUsage(t *testing.T, csr *x509.CertificateRequest, expected []asn1.ObjectIdentifier) {
	t.Helper()

	extKeyUsageOIDValue := asn1.ObjectIdentifier{2, 5, 29, 37}
	for _, extension := range csr.Extensions {
		if !extension.Id.Equal(extKeyUsageOIDValue) {
			continue
		}
		if extension.Critical {
			t.Error("expected extended key usage to be non-critical")
		}

		var oids []asn1.ObjectIdentifier
		rest, err := asn1.Unmarshal(extension.Value, &oids)
		if err != nil {
			t.Fatalf("failed to decode extended key usage: %v", err)
		}
		if len(rest) != 0 {
			t.Fatalf("unexpected trailing extended key usage data: %x", rest)
		}
		if len(oids) != len(expected) {
			t.Fatalf("expected %d OIDs, got: %#v", len(expected), oids)
		}
		for i, oid := range oids {
			if !oid.Equal(expected[i]) {
				t.Fatalf("OID %d: expected %v, got %v", i, expected[i], oid)
			}
		}

		return
	}

	t.Fatal("extended key usage extension not found")
}
