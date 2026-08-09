package kmscsr //nolint:testpackage // testing internals

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// mockKMSClient implements a mock KMS client for testing.
type mockKMSClient struct {
	publicKey       []byte
	keyUsage        types.KeyUsageType
	keySpec         types.KeySpec
	signAlgo        types.SigningAlgorithmSpec
	signResponse    []byte
	getPublicKeyErr error
	signErr         error
	nilPublicKey    bool
}

func (m *mockKMSClient) GetPublicKey(
	_ context.Context,
	_ *kms.GetPublicKeyInput,
	_ ...func(*kms.Options),
) (*kms.GetPublicKeyOutput, error) {
	if m.getPublicKeyErr != nil {
		return nil, m.getPublicKeyErr
	}
	if m.nilPublicKey {
		return nil, nil //nolint:nilnil // intentionally simulates a malformed SDK response
	}

	return &kms.GetPublicKeyOutput{
		PublicKey:         m.publicKey,
		KeyUsage:          m.keyUsage,
		KeySpec:           m.keySpec,
		SigningAlgorithms: []types.SigningAlgorithmSpec{m.signAlgo},
	}, nil
}

func (m *mockKMSClient) Sign(_ context.Context, _ *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	if m.signErr != nil {
		return nil, m.signErr
	}

	return &kms.SignOutput{
		Signature: m.signResponse,
	}, nil
}

// mockSigningKMSClient implements a mock KMS client that performs real signing.
type mockSigningKMSClient struct {
	publicKey       []byte
	keyUsage        types.KeyUsageType
	keySpec         types.KeySpec
	signAlgo        types.SigningAlgorithmSpec
	signer          crypto.Signer
	getPublicKeyErr error
	signErr         error
	signInput       *kms.SignInput
}

func (m *mockSigningKMSClient) GetPublicKey(
	_ context.Context,
	_ *kms.GetPublicKeyInput,
	_ ...func(*kms.Options),
) (*kms.GetPublicKeyOutput, error) {
	if m.getPublicKeyErr != nil {
		return nil, m.getPublicKeyErr
	}

	return &kms.GetPublicKeyOutput{
		PublicKey:         m.publicKey,
		KeyUsage:          m.keyUsage,
		KeySpec:           m.keySpec,
		SigningAlgorithms: []types.SigningAlgorithmSpec{m.signAlgo},
	}, nil
}

func (m *mockSigningKMSClient) Sign(
	_ context.Context,
	params *kms.SignInput,
	_ ...func(*kms.Options),
) (*kms.SignOutput, error) {
	if m.signErr != nil {
		return nil, m.signErr
	}

	m.signInput = params

	hash, err := hashForSigningAlgorithm(params.SigningAlgorithm)
	if err != nil {
		return nil, err
	}

	// Use the real signer to create a valid signature.
	signature, err := m.signer.Sign(rand.Reader, params.Message, hash)
	if err != nil {
		return nil, err
	}

	return &kms.SignOutput{
		Signature: signature,
	}, nil
}

type cancelAwareKMSClient struct {
	publicKey  []byte
	signCalled chan context.Context
}

func (m *cancelAwareKMSClient) GetPublicKey(
	ctx context.Context,
	_ *kms.GetPublicKeyInput,
	_ ...func(*kms.Options),
) (*kms.GetPublicKeyOutput, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return &kms.GetPublicKeyOutput{
		PublicKey:         m.publicKey,
		KeyUsage:          types.KeyUsageTypeSignVerify,
		KeySpec:           types.KeySpecRsa2048,
		SigningAlgorithms: []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecRsassaPkcs1V15Sha256},
	}, nil
}

func (m *cancelAwareKMSClient) Sign(
	ctx context.Context,
	_ *kms.SignInput,
	_ ...func(*kms.Options),
) (*kms.SignOutput, error) {
	m.signCalled <- ctx
	<-ctx.Done()

	return nil, ctx.Err()
}

// generateMockRSAPublicKey generates a mock RSA public key in DER format.
func generateMockRSAPublicKey() ([]byte, *rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	return publicKeyDER, privateKey, nil
}

// generateMockECDSAPublicKey generates a mock ECDSA public key in DER format.
func generateMockECDSAPublicKey() ([]byte, *ecdsa.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	return publicKeyDER, privateKey, nil
}

func TestNewKMSCSRBuilder_Success(t *testing.T) {
	publicKeyDER, _, err := generateMockRSAPublicKey()
	if err != nil {
		t.Fatalf("failed to generate mock public key: %v", err)
	}

	subject := &SubjectInfo{
		CountryName:         "US",
		StateOrProvinceName: "California",
		LocalityName:        "San Francisco",
		OrganizationName:    "Test Corp",
		CommonName:          "test.example.com",
	}

	builder, err := newKMSCSRBuilderWithMock(
		subject,
		"arn:aws:kms:us-east-1:123456789012:key/test-key-id",
		&mockKMSClient{
			publicKey: publicKeyDER,
			keyUsage:  types.KeyUsageTypeSignVerify,
			keySpec:   types.KeySpecRsa2048,
			signAlgo:  types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
		},
	)

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if builder == nil {
		t.Fatal("expected builder to be non-nil")

		return
	}

	if builder.Subject.CommonName != "test.example.com" {
		t.Errorf("expected CommonName 'test.example.com', got: %s", builder.Subject.CommonName)
	}

	if builder.CA {
		t.Error("expected CA to be false by default")
	}

	if builder.KeyUsage != (x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment) {
		t.Errorf("expected default non-CA key usage, got: %v", builder.KeyUsage)
	}
}

func TestNewKMSCSRBuilder_NilSubject(t *testing.T) {
	_, err := NewKMSCSRBuilder(nil, "arn:aws:kms:us-east-1:123456789012:key/test-key-id")
	if err == nil {
		t.Fatal("expected error for nil subject, got nil")
	}

	if err.Error() != "subject cannot be nil" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestNewKMSCSRBuilder_EmptyKMSArn(t *testing.T) {
	subject := &SubjectInfo{
		CommonName: "test.example.com",
	}

	_, err := NewKMSCSRBuilder(subject, "")
	if err == nil {
		t.Fatal("expected error for empty KMS ARN, got nil")
	}

	if err.Error() != "kmsArn cannot be empty" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestNewKMSCSRBuilderWithContext_Canceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := newKMSCSRBuilder(
		ctx,
		&SubjectInfo{CommonName: "test.example.com"},
		"arn:aws:kms:us-east-1:123456789012:key/test-key-id",
		&cancelAwareKMSClient{},
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got: %v", err)
	}
}

func TestNewKMSCSRBuilderWithContext_NilContext(t *testing.T) {
	_, err := NewKMSCSRBuilderWithContext(
		nil, //nolint:staticcheck // explicitly verifies rejection of a nil context
		&SubjectInfo{CommonName: "test.example.com"},
		"arn:aws:kms:us-east-1:123456789012:key/test-key-id",
	)
	if err == nil || err.Error() != "context cannot be nil" {
		t.Fatalf("expected nil context error, got: %v", err)
	}
}

func TestNewKMSCSRBuilder_RejectsEmptyKMSResponse(t *testing.T) {
	_, err := newKMSCSRBuilderWithMock(
		&SubjectInfo{CommonName: "test.example.com"},
		"arn:aws:kms:us-east-1:123456789012:key/test-key-id",
		&mockKMSClient{nilPublicKey: true},
	)
	if err == nil || !strings.Contains(err.Error(), "empty response") {
		t.Fatalf("expected empty KMS response error, got: %v", err)
	}
}

func TestSetCA(t *testing.T) {
	publicKeyDER, _, err := generateMockRSAPublicKey()
	if err != nil {
		t.Fatalf("failed to generate mock public key: %v", err)
	}

	subject := &SubjectInfo{
		CommonName: "test-ca.example.com",
	}

	builder, err := newKMSCSRBuilderWithMock(
		subject,
		"arn:aws:kms:us-east-1:123456789012:key/test-key-id",
		&mockKMSClient{
			publicKey: publicKeyDER,
			keyUsage:  types.KeyUsageTypeSignVerify,
			keySpec:   types.KeySpecRsa2048,
			signAlgo:  types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
		},
	)

	if err != nil {
		t.Fatalf("failed to create builder: %v", err)
	}

	// Test setting CA to true
	builder.SetCA(true)

	if !builder.CA {
		t.Error("expected CA to be true")
	}

	if builder.KeyUsage != (x509.KeyUsageCertSign | x509.KeyUsageCRLSign) {
		t.Errorf("expected CA key usage, got: %v", builder.KeyUsage)
	}

	// Test setting CA back to false
	builder.SetCA(false)

	if builder.CA {
		t.Error("expected CA to be false")
	}

	if builder.KeyUsage != (x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment) {
		t.Errorf("expected non-CA key usage, got: %v", builder.KeyUsage)
	}
}

func TestBuildWithKMS_RSA(t *testing.T) {
	publicKeyDER, privateKey, err := generateMockRSAPublicKey()
	if err != nil {
		t.Fatalf("failed to generate mock public key: %v", err)
	}

	subject := &SubjectInfo{
		CountryName:      "US",
		CommonName:       "rsa-test.example.com",
		OrganizationName: "Test Corp",
	}

	// Create a mock client that will use the real private key to sign
	mockClient := &mockSigningKMSClient{
		publicKey: publicKeyDER,
		keyUsage:  types.KeyUsageTypeSignVerify,
		keySpec:   types.KeySpecRsa2048,
		signAlgo:  types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
		signer:    privateKey,
	}

	builder, err := newKMSCSRBuilderWithMock(
		subject,
		"arn:aws:kms:us-east-1:123456789012:key/test-key-id",
		mockClient,
	)

	if err != nil {
		t.Fatalf("failed to create builder: %v", err)
	}

	builder.SubjectAltDomains = []string{"www.example.com", "api.example.com"}

	ctx := context.Background()
	csrDER, err := builder.BuildWithKMS(ctx)
	if err != nil {
		t.Fatalf("failed to build CSR: %v", err)
	}

	if len(csrDER) == 0 {
		t.Fatal("expected non-empty CSR DER data")
	}

	// Parse the CSR to verify it's valid
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("failed to parse CSR: %v", err)
	}
	if signatureErr := csr.CheckSignature(); signatureErr != nil {
		t.Fatalf("failed to verify CSR signature: %v", signatureErr)
	}

	if csr.Subject.CommonName != "rsa-test.example.com" {
		t.Errorf("expected CommonName 'rsa-test.example.com', got: %s", csr.Subject.CommonName)
	}

	if len(csr.DNSNames) != 2 {
		t.Errorf("expected 2 DNS names, got: %d", len(csr.DNSNames))
	}

	// Verify public key type
	if _, ok := csr.PublicKey.(*rsa.PublicKey); !ok {
		t.Errorf("expected RSA public key, got: %T", csr.PublicKey)
	}

	// Compare public keys
	csrPubKey, ok := csr.PublicKey.(*rsa.PublicKey)
	if ok && csrPubKey.N.Cmp(privateKey.PublicKey.N) != 0 {
		t.Error("public key in CSR does not match expected public key")
	}
}

func TestBuildWithKMS_ECDSA(t *testing.T) {
	publicKeyDER, privateKey, err := generateMockECDSAPublicKey()
	if err != nil {
		t.Fatalf("failed to generate mock public key: %v", err)
	}

	subject := &SubjectInfo{
		CommonName:       "ecdsa-test.example.com",
		OrganizationName: "Test Corp",
	}

	mockClient := &mockSigningKMSClient{
		publicKey: publicKeyDER,
		keyUsage:  types.KeyUsageTypeSignVerify,
		keySpec:   types.KeySpecEccNistP256,
		signAlgo:  types.SigningAlgorithmSpecEcdsaSha256,
		signer:    privateKey,
	}

	builder, err := newKMSCSRBuilderWithMock(
		subject,
		"arn:aws:kms:us-east-1:123456789012:key/test-key-id",
		mockClient,
	)

	if err != nil {
		t.Fatalf("failed to create builder: %v", err)
	}

	ctx := context.Background()
	csrDER, err := builder.BuildWithKMS(ctx)
	if err != nil {
		t.Fatalf("failed to build CSR: %v", err)
	}

	if len(csrDER) == 0 {
		t.Fatal("expected non-empty CSR DER data")
	}

	// Parse the CSR to verify it's valid
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("failed to parse CSR: %v", err)
	}
	if signatureErr := csr.CheckSignature(); signatureErr != nil {
		t.Fatalf("failed to verify CSR signature: %v", signatureErr)
	}

	if csr.Subject.CommonName != "ecdsa-test.example.com" {
		t.Errorf("expected CommonName 'ecdsa-test.example.com', got: %s", csr.Subject.CommonName)
	}

	// Verify public key type
	if _, ok := csr.PublicKey.(*ecdsa.PublicKey); !ok {
		t.Errorf("expected ECDSA public key, got: %T", csr.PublicKey)
	}
}

func TestBuildWithKMS_WithCAExtensions(t *testing.T) {
	publicKeyDER, privateKey, err := generateMockRSAPublicKey()
	if err != nil {
		t.Fatalf("failed to generate mock public key: %v", err)
	}

	subject := &SubjectInfo{
		CommonName:       "ca-test.example.com",
		OrganizationName: "Test CA",
	}

	mockClient := &mockSigningKMSClient{
		publicKey: publicKeyDER,
		keyUsage:  types.KeyUsageTypeSignVerify,
		keySpec:   types.KeySpecRsa2048,
		signAlgo:  types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
		signer:    privateKey,
	}

	builder, err := newKMSCSRBuilderWithMock(
		subject,
		"arn:aws:kms:us-east-1:123456789012:key/test-key-id",
		mockClient,
	)

	if err != nil {
		t.Fatalf("failed to create builder: %v", err)
	}

	builder.SetCA(true)

	ctx := context.Background()
	csrDER, err := builder.BuildWithKMS(ctx)
	if err != nil {
		t.Fatalf("failed to build CSR: %v", err)
	}

	// Parse the CSR
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("failed to parse CSR: %v", err)
	}

	// Verify extensions are present
	if len(csr.Extensions) == 0 {
		t.Error("expected extensions in CA CSR")
	}

	assertCSRKeyUsage(t, csr, x509.KeyUsageCertSign|x509.KeyUsageCRLSign)
}

func TestBuildWithKMS_KeyUsageEncoding(t *testing.T) {
	publicKeyDER, privateKey, err := generateMockRSAPublicKey()
	if err != nil {
		t.Fatalf("failed to generate mock public key: %v", err)
	}

	builder, err := newKMSCSRBuilderWithMock(
		&SubjectInfo{CommonName: "usage-test.example.com"},
		"arn:aws:kms:us-east-1:123456789012:key/test-key-id",
		&mockSigningKMSClient{
			publicKey: publicKeyDER,
			keyUsage:  types.KeyUsageTypeSignVerify,
			keySpec:   types.KeySpecRsa2048,
			signAlgo:  types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
			signer:    privateKey,
		},
	)
	if err != nil {
		t.Fatalf("failed to create builder: %v", err)
	}

	csrDER, err := builder.BuildWithKMS(context.Background())
	if err != nil {
		t.Fatalf("failed to build CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("failed to parse CSR: %v", err)
	}

	assertCSRKeyUsage(t, csr, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment)
}

func TestKeyUsageExtension_AllSupportedBits(t *testing.T) {
	for bit := range 9 {
		expected := x509.KeyUsage(1 << uint(bit))
		extension, err := keyUsageExtension(expected)
		if err != nil {
			t.Fatalf("bit %d: unexpected error: %v", bit, err)
		}
		actual := decodeKeyUsage(t, extension.Value)
		if actual != expected {
			t.Fatalf("bit %d: expected %v, got: %v", bit, expected, actual)
		}
	}
}

func TestKeyUsageExtension_RejectsUnsupportedBits(t *testing.T) {
	if _, extensionErr := keyUsageExtension(x509.KeyUsage(1 << 9)); extensionErr == nil {
		t.Fatal("expected unsupported key usage error")
	}
}

func TestBuildWithKMS_PropagatesCancellationToSign(t *testing.T) {
	publicKeyDER, _, err := generateMockRSAPublicKey()
	if err != nil {
		t.Fatalf("failed to generate mock public key: %v", err)
	}

	client := &cancelAwareKMSClient{
		publicKey:  publicKeyDER,
		signCalled: make(chan context.Context, 1),
	}
	builder, err := newKMSCSRBuilder(
		context.Background(),
		&SubjectInfo{CommonName: "cancel-test.example.com"},
		"arn:aws:kms:us-east-1:123456789012:key/test-key-id",
		client,
	)
	if err != nil {
		t.Fatalf("failed to create builder: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	buildDone := make(chan error, 1)
	go func() {
		_, buildErr := builder.BuildWithKMS(ctx)
		buildDone <- buildErr
	}()

	select {
	case signCtx := <-client.signCalled:
		if signCtx != ctx {
			t.Error("KMS Sign did not receive the BuildWithKMS context")
		}
		cancel()
	case <-time.After(time.Second):
		t.Fatal("KMS Sign was not called")
	}

	select {
	case buildErr := <-buildDone:
		if !errors.Is(buildErr, context.Canceled) {
			t.Fatalf("expected context cancellation, got: %v", buildErr)
		}
	case <-time.After(time.Second):
		t.Fatal("BuildWithKMS did not return after cancellation")
	}
}

func TestBuildWithKMS_UsesConfiguredSigningAlgorithm(t *testing.T) {
	publicKeyDER, privateKey, err := generateMockRSAPublicKey()
	if err != nil {
		t.Fatalf("failed to generate mock public key: %v", err)
	}

	client := &mockSigningKMSClient{
		publicKey: publicKeyDER,
		keyUsage:  types.KeyUsageTypeSignVerify,
		keySpec:   types.KeySpecRsa2048,
		signAlgo:  types.SigningAlgorithmSpecRsassaPkcs1V15Sha384,
		signer:    privateKey,
	}
	builder, err := newKMSCSRBuilderWithMock(
		&SubjectInfo{CommonName: "sha384-test.example.com"},
		"arn:aws:kms:us-east-1:123456789012:key/test-key-id",
		client,
	)
	if err != nil {
		t.Fatalf("failed to create builder: %v", err)
	}
	builder.HashAlgo = types.SigningAlgorithmSpecRsassaPkcs1V15Sha384

	csrDER, err := builder.BuildWithKMS(context.Background())
	if err != nil {
		t.Fatalf("failed to build CSR: %v", err)
	}
	if client.signInput == nil ||
		client.signInput.SigningAlgorithm != types.SigningAlgorithmSpecRsassaPkcs1V15Sha384 {
		t.Fatalf("expected KMS RSA SHA-384 signing input, got: %#v", client.signInput)
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("failed to parse CSR: %v", err)
	}
	if csr.SignatureAlgorithm != x509.SHA384WithRSA {
		t.Fatalf("expected SHA384WithRSA, got: %v", csr.SignatureAlgorithm)
	}
}

func TestBuildWithKMS_RejectsUnsupportedSigningAlgorithm(t *testing.T) {
	publicKeyDER, privateKey, err := generateMockRSAPublicKey()
	if err != nil {
		t.Fatalf("failed to generate mock public key: %v", err)
	}

	builder, err := newKMSCSRBuilderWithMock(
		&SubjectInfo{CommonName: "algorithm-test.example.com"},
		"arn:aws:kms:us-east-1:123456789012:key/test-key-id",
		&mockSigningKMSClient{
			publicKey: publicKeyDER,
			keyUsage:  types.KeyUsageTypeSignVerify,
			keySpec:   types.KeySpecRsa2048,
			signAlgo:  types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
			signer:    privateKey,
		},
	)
	if err != nil {
		t.Fatalf("failed to create builder: %v", err)
	}
	builder.HashAlgo = types.SigningAlgorithmSpec("UNSUPPORTED")

	if _, buildErr := builder.BuildWithKMS(context.Background()); buildErr == nil {
		t.Fatal("expected unsupported signing algorithm error")
	}
}

func TestBuildWithKMS_RejectsUnsupportedExtKeyUsage(t *testing.T) {
	publicKeyDER, privateKey, err := generateMockRSAPublicKey()
	if err != nil {
		t.Fatalf("failed to generate mock public key: %v", err)
	}

	builder, err := newKMSCSRBuilderWithMock(
		&SubjectInfo{CommonName: "eku-test.example.com"},
		"arn:aws:kms:us-east-1:123456789012:key/test-key-id",
		&mockSigningKMSClient{
			publicKey: publicKeyDER,
			keyUsage:  types.KeyUsageTypeSignVerify,
			keySpec:   types.KeySpecRsa2048,
			signAlgo:  types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
			signer:    privateKey,
		},
	)
	if err != nil {
		t.Fatalf("failed to create builder: %v", err)
	}
	builder.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsage(999)}

	if _, buildErr := builder.BuildWithKMS(context.Background()); buildErr == nil {
		t.Fatal("expected unsupported extended key usage error")
	}
}

func TestExtKeyUsageExtension_SupportsAny(t *testing.T) {
	extension, err := extKeyUsageExtension([]x509.ExtKeyUsage{x509.ExtKeyUsageAny})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var oids []asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(extension.Value, &oids)
	if err != nil {
		t.Fatalf("failed to decode extended key usage: %v", err)
	}
	if len(rest) != 0 || len(oids) != 1 || !oids[0].Equal(asn1.ObjectIdentifier{2, 5, 29, 37, 0}) {
		t.Fatalf("unexpected extended key usage encoding: %#v, trailing: %x", oids, rest)
	}
}

func TestBuildWithKMS_RejectsEmptyKMSSignature(t *testing.T) {
	publicKeyDER, _, err := generateMockRSAPublicKey()
	if err != nil {
		t.Fatalf("failed to generate mock public key: %v", err)
	}

	builder, err := newKMSCSRBuilderWithMock(
		&SubjectInfo{CommonName: "empty-signature.example.com"},
		"arn:aws:kms:us-east-1:123456789012:key/test-key-id",
		&mockKMSClient{
			publicKey: publicKeyDER,
			keyUsage:  types.KeyUsageTypeSignVerify,
			keySpec:   types.KeySpecRsa2048,
			signAlgo:  types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
		},
	)
	if err != nil {
		t.Fatalf("failed to create builder: %v", err)
	}

	_, err = builder.BuildWithKMS(context.Background())
	if err == nil || !strings.Contains(err.Error(), "empty signature") {
		t.Fatalf("expected empty KMS signature error, got: %v", err)
	}
}

func TestNewKMSCSRBuilder_SubjectRoundTrip(t *testing.T) {
	publicKeyDER, privateKey, err := generateMockRSAPublicKey()
	if err != nil {
		t.Fatalf("failed to generate mock public key: %v", err)
	}

	builder, err := newKMSCSRBuilderWithMock(
		&SubjectInfo{
			CommonName:    "subject-test.example.com",
			EmailAddress:  "admin@example.com",
			StreetAddress: "123 Example Street",
			PostalCode:    "12345",
		},
		"arn:aws:kms:us-east-1:123456789012:key/test-key-id",
		&mockSigningKMSClient{
			publicKey: publicKeyDER,
			keyUsage:  types.KeyUsageTypeSignVerify,
			keySpec:   types.KeySpecRsa2048,
			signAlgo:  types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
			signer:    privateKey,
		},
	)
	if err != nil {
		t.Fatalf("failed to create builder: %v", err)
	}

	csrDER, err := builder.BuildWithKMS(context.Background())
	if err != nil {
		t.Fatalf("failed to build CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("failed to parse CSR: %v", err)
	}
	if len(csr.Subject.StreetAddress) != 1 || csr.Subject.StreetAddress[0] != "123 Example Street" {
		t.Fatalf("street address was not preserved: %#v (names: %#v)", csr.Subject.StreetAddress, csr.Subject.Names)
	}
	if len(csr.Subject.PostalCode) != 1 || csr.Subject.PostalCode[0] != "12345" {
		t.Fatalf("postal code was not preserved: %#v", csr.Subject.PostalCode)
	}

	emailOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
	foundEmail := false
	for _, name := range csr.Subject.Names {
		if name.Type.Equal(emailOID) && name.Value == "admin@example.com" {
			foundEmail = true
			break
		}
	}
	if !foundEmail {
		t.Fatalf("email address was not preserved: %#v", csr.Subject.Names)
	}
}

func assertCSRKeyUsage(t *testing.T, csr *x509.CertificateRequest, expected x509.KeyUsage) {
	t.Helper()

	keyUsageOID := asn1.ObjectIdentifier{2, 5, 29, 15}
	for _, extension := range csr.Extensions {
		if !extension.Id.Equal(keyUsageOID) {
			continue
		}

		actual := decodeKeyUsage(t, extension.Value)
		if actual != expected {
			t.Fatalf("expected KeyUsage %v, got: %v", expected, actual)
		}

		return
	}

	t.Fatal("KeyUsage extension not found")
}

func decodeKeyUsage(t *testing.T, der []byte) x509.KeyUsage {
	t.Helper()

	var bitString asn1.BitString
	rest, err := asn1.Unmarshal(der, &bitString)
	if err != nil {
		t.Fatalf("failed to decode KeyUsage: %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("unexpected trailing KeyUsage data: %x", rest)
	}

	var usage x509.KeyUsage
	for bit := range 9 {
		if bitString.At(bit) != 0 {
			usage |= 1 << uint(bit)
		}
	}

	return usage
}

func TestPEMEncode(t *testing.T) {
	testData := []byte("test-csr-der-data")

	pemData := PEMEncode(testData)

	if len(pemData) == 0 {
		t.Fatal("expected non-empty PEM data")
	}

	// Decode PEM to verify format
	block, _ := pem.Decode(pemData)
	if block == nil {
		t.Fatal("failed to decode PEM block")

		return
	}

	if block.Type != "CERTIFICATE REQUEST" {
		t.Errorf("expected PEM type 'CERTIFICATE REQUEST', got: %s", block.Type)
	}

	if string(block.Bytes) != string(testData) {
		t.Error("PEM data does not match original data")
	}
}

func TestGetSignatureAlgorithm(t *testing.T) {
	tests := []struct {
		name     string
		algo     types.SigningAlgorithmSpec
		expected x509.SignatureAlgorithm
	}{
		{"RSA SHA256", types.SigningAlgorithmSpecRsassaPkcs1V15Sha256, x509.SHA256WithRSA},
		{"RSA SHA384", types.SigningAlgorithmSpecRsassaPkcs1V15Sha384, x509.SHA384WithRSA},
		{"RSA SHA512", types.SigningAlgorithmSpecRsassaPkcs1V15Sha512, x509.SHA512WithRSA},
		{"ECDSA SHA256", types.SigningAlgorithmSpecEcdsaSha256, x509.ECDSAWithSHA256},
		{"ECDSA SHA384", types.SigningAlgorithmSpecEcdsaSha384, x509.ECDSAWithSHA384},
		{"ECDSA SHA512", types.SigningAlgorithmSpecEcdsaSha512, x509.ECDSAWithSHA512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := getSignatureAlgorithm(tt.algo)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// newKMSCSRBuilderWithMock creates a builder with a mocked KMS client for testing.
//
//nolint:unparam // kmsArn is used for testing
func newKMSCSRBuilderWithMock(subject *SubjectInfo, kmsArn string, mockClient KMSClient) (*Builder, error) {
	return newKMSCSRBuilder(context.Background(), subject, kmsArn, mockClient)
}
