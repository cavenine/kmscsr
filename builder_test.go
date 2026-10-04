package kmscsr //nolint:testpackage // testing internals

import (
	"bytes"
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
	publicKey []byte
	keyUsage  types.KeyUsageType
	keySpec   types.KeySpec
	signAlgo  types.SigningAlgorithmSpec
	// signingAlgorithms, when set, is advertised instead of signAlgo alone.
	signingAlgorithms []types.SigningAlgorithmSpec
	signer            crypto.Signer
	getPublicKeyErr   error
	signErr           error
	getPublicKeyInput *kms.GetPublicKeyInput
	signInput         *kms.SignInput
}

func (m *mockSigningKMSClient) GetPublicKey(
	_ context.Context,
	params *kms.GetPublicKeyInput,
	_ ...func(*kms.Options),
) (*kms.GetPublicKeyOutput, error) {
	if m.getPublicKeyErr != nil {
		return nil, m.getPublicKeyErr
	}

	m.getPublicKeyInput = params
	algorithms := m.signingAlgorithms
	if algorithms == nil {
		algorithms = []types.SigningAlgorithmSpec{m.signAlgo}
	}

	return &kms.GetPublicKeyOutput{
		PublicKey:         m.publicKey,
		KeyUsage:          m.keyUsage,
		KeySpec:           m.keySpec,
		SigningAlgorithms: algorithms,
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
	t.Parallel()

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
	t.Parallel()

	_, err := NewKMSCSRBuilder(nil, "arn:aws:kms:us-east-1:123456789012:key/test-key-id")
	if err == nil {
		t.Fatal("expected error for nil subject, got nil")
	}

	if err.Error() != "subject cannot be nil" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestNewKMSCSRBuilder_EmptyKMSArn(t *testing.T) {
	t.Parallel()

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
	t.Parallel()

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
	t.Parallel()

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
	t.Parallel()

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
	t.Parallel()

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
	t.Parallel()

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

	if len(csr.DNSNames) != 2 || csr.DNSNames[0] != "www.example.com" || csr.DNSNames[1] != "api.example.com" {
		t.Errorf("expected DNS names in the order given, got: %#v", csr.DNSNames)
	}

	if !privateKey.PublicKey.Equal(csr.PublicKey) {
		t.Errorf("public key in CSR does not match the KMS key, got: %T", csr.PublicKey)
	}

	assertSignInput(t, mockClient.signInput, types.SigningAlgorithmSpecRsassaPkcs1V15Sha256, crypto.SHA256)
}

// assertSignInput checks the request BuildWithKMS sent to KMS Sign. KMS hashes
// the message itself unless told it is already a digest, so a wrong MessageType
// still yields a signature, just over the wrong data; the mocks cannot notice
// that, only a real key can.
func assertSignInput(t *testing.T, input *kms.SignInput, algo types.SigningAlgorithmSpec, hash crypto.Hash) {
	t.Helper()

	if input == nil {
		t.Fatal("KMS Sign was not called")

		return
	}
	if input.KeyId == nil || *input.KeyId != testARN {
		t.Errorf("expected KeyId %q, got: %v", testARN, input.KeyId)
	}
	if input.MessageType != types.MessageTypeDigest {
		t.Errorf("expected MessageType %s, got: %q", types.MessageTypeDigest, input.MessageType)
	}
	if input.SigningAlgorithm != algo {
		t.Errorf("expected SigningAlgorithm %s, got: %s", algo, input.SigningAlgorithm)
	}
	if len(input.Message) != hash.Size() {
		t.Errorf("expected a %d-byte %v digest, got %d bytes", hash.Size(), hash, len(input.Message))
	}
}

func TestBuildWithKMS_ECDSA(t *testing.T) {
	t.Parallel()

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
	t.Parallel()

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
	t.Parallel()

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

// TestKeyUsageExtension_AllSupportedBits checks every non-empty combination of
// the nine defined bits, byte for byte, against the encoding crypto/x509 itself
// produces. DER requires trailing zero bits to be dropped from a named bit
// list, which decoding alone would not notice.
func TestKeyUsageExtension_AllSupportedBits(t *testing.T) {
	t.Parallel()

	_, key := generateMockECDSAPublicKeyOnCurve(t, elliptic.P256())
	const allKeyUsages = x509.KeyUsage(1<<9 - 1)

	for usage := x509.KeyUsage(1); usage <= allKeyUsages; usage++ {
		extension, err := keyUsageExtension(usage)
		if err != nil {
			t.Fatalf("usage %#x: unexpected error: %v", usage, err)
		}
		if actual := decodeKeyUsage(t, extension.Value); actual != usage {
			t.Fatalf("usage %#x: decoded as %#x", usage, actual)
		}
		reference := stdlibCertificateExtension(t, key, &x509.Certificate{KeyUsage: usage}, oidKeyUsage())
		if !bytes.Equal(extension.Value, reference.Value) || extension.Critical != reference.Critical {
			t.Fatalf("usage %#x: got %x (critical=%v), crypto/x509 encodes %x (critical=%v)",
				usage, extension.Value, extension.Critical, reference.Value, reference.Critical)
		}
	}
}

func TestKeyUsageExtension_RejectsUnsupportedBits(t *testing.T) {
	t.Parallel()

	// The exact message matters: x509.KeyUsage implements fmt.Stringer, so
	// formatting it with %x hex-encodes "KeyUsage(512)" instead of the bits.
	tests := []struct {
		usage   x509.KeyUsage
		wantErr string
	}{
		{x509.KeyUsage(1 << 9), "unsupported key usage bits: 0x200"},
		{x509.KeyUsageDigitalSignature | x509.KeyUsage(1<<15), "unsupported key usage bits: 0x8000"},
	}

	for _, tt := range tests {
		if _, err := keyUsageExtension(tt.usage); err == nil || err.Error() != tt.wantErr {
			t.Errorf("usage %d: expected %q, got: %v", uint16(tt.usage), tt.wantErr, err)
		}
	}
}

func TestBuildWithKMS_PropagatesCancellationToSign(t *testing.T) {
	t.Parallel()

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
	t.Parallel()

	publicKeyDER, privateKey, err := generateMockRSAPublicKey()
	if err != nil {
		t.Fatalf("failed to generate mock public key: %v", err)
	}
	advertised := []types.SigningAlgorithmSpec{
		types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
		types.SigningAlgorithmSpecRsassaPkcs1V15Sha384,
		types.SigningAlgorithmSpecRsassaPkcs1V15Sha512,
	}

	tests := []struct {
		algo     types.SigningAlgorithmSpec
		hash     crypto.Hash
		expected x509.SignatureAlgorithm
	}{
		{types.SigningAlgorithmSpecRsassaPkcs1V15Sha256, crypto.SHA256, x509.SHA256WithRSA},
		{types.SigningAlgorithmSpecRsassaPkcs1V15Sha384, crypto.SHA384, x509.SHA384WithRSA},
		{types.SigningAlgorithmSpecRsassaPkcs1V15Sha512, crypto.SHA512, x509.SHA512WithRSA},
	}

	for _, tt := range tests {
		t.Run(string(tt.algo), func(t *testing.T) {
			t.Parallel()

			client := &mockSigningKMSClient{
				publicKey:         publicKeyDER,
				keyUsage:          types.KeyUsageTypeSignVerify,
				keySpec:           types.KeySpecRsa2048,
				signingAlgorithms: advertised,
				signer:            privateKey,
			}
			builder, builderErr := newKMSCSRBuilderWithMock(
				&SubjectInfo{CommonName: "algo.example.com"},
				testARN,
				client,
			)
			if builderErr != nil {
				t.Fatalf("failed to create builder: %v", builderErr)
			}
			builder.HashAlgo = tt.algo

			csrDER, buildErr := builder.BuildWithKMS(t.Context())
			if buildErr != nil {
				t.Fatalf("failed to build CSR: %v", buildErr)
			}
			assertSignInput(t, client.signInput, tt.algo, tt.hash)

			csr, parseErr := x509.ParseCertificateRequest(csrDER)
			if parseErr != nil {
				t.Fatalf("failed to parse CSR: %v", parseErr)
			}
			if csr.SignatureAlgorithm != tt.expected {
				t.Fatalf("expected %v, got: %v", tt.expected, csr.SignatureAlgorithm)
			}
			if signatureErr := csr.CheckSignature(); signatureErr != nil {
				t.Fatalf("signature verification failed: %v", signatureErr)
			}
		})
	}
}

func TestBuildWithKMS_RejectsUnsupportedSigningAlgorithm(t *testing.T) {
	t.Parallel()

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

	_, buildErr := builder.BuildWithKMS(t.Context())
	if buildErr == nil || buildErr.Error() != "KMS key does not support signing algorithm UNSUPPORTED" {
		t.Fatalf("expected unsupported signing algorithm error, got: %v", buildErr)
	}
	assertSignNotCalled(t, builder)
}

func TestBuildWithKMS_RejectsUnsupportedExtKeyUsage(t *testing.T) {
	t.Parallel()

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
	builder.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsage(999)}

	_, buildErr := builder.BuildWithKMS(t.Context())
	if buildErr == nil || buildErr.Error() !=
		"failed to create extended key usage extension: unsupported extended key usage: 999" {
		t.Fatalf("expected unsupported extended key usage error, got: %v", buildErr)
	}
	assertSignNotCalled(t, builder)
}

func TestExtKeyUsageExtension_SupportsAny(t *testing.T) {
	t.Parallel()

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
	t.Parallel()

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
	t.Parallel()

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
	t.Parallel()

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
	t.Parallel()

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
			t.Parallel()

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
