package kmscsr //nolint:testpackage // testing internals

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"testing"

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
}

func (m *mockKMSClient) GetPublicKey(
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

	// Use the real signer to create a valid signature
	signature, err := m.signer.Sign(rand.Reader, params.Message, crypto.SHA256)
	if err != nil {
		return nil, err
	}

	return &kms.SignOutput{
		Signature: signature,
	}, nil
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
			result := getSignatureAlgorithm(tt.algo)
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
	if subject == nil {
		return nil, errors.New("subject cannot be nil")
	}

	if kmsArn == "" {
		return nil, errors.New("kmsArn cannot be empty")
	}

	builder := &Builder{
		Subject: &pkix.Name{
			Country:            []string{subject.CountryName},
			Province:           []string{subject.StateOrProvinceName},
			Locality:           []string{subject.LocalityName},
			Organization:       []string{subject.OrganizationName},
			CommonName:         subject.CommonName,
			OrganizationalUnit: []string{subject.OrganizationalUnitName},
		},
		KMSArn:    kmsArn,
		kmsClient: mockClient,
		HashAlgo:  types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
		CA:        false,
	}

	// Retrieve public key from mock KMS
	ctx := context.TODO()
	if err := builder.loadPublicKey(ctx); err != nil {
		return nil, err
	}

	return builder, nil
}
