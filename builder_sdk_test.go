package kmscsr //nolint:testpackage // testing internals

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// These tests run the constructors that build a real SDK client from the
// default AWS configuration, against a local stand-in for the KMS JSON API.
// They are the only tests that see the requests as the SDK serializes them.
// They set environment variables, so they cannot run in parallel.

// kmsSignRequest is the part of a KMS Sign request body the tests inspect.
type kmsSignRequest struct {
	KeyID            string `json:"KeyId"`
	Message          []byte `json:"Message"`
	MessageType      string `json:"MessageType"`
	SigningAlgorithm string `json:"SigningAlgorithm"`
}

// fakeKMSEndpoint serves GetPublicKey and Sign for one P-256 key.
type fakeKMSEndpoint struct {
	t            *testing.T
	publicKeyDER []byte
	privateKey   *ecdsa.PrivateKey
	// errorType, when set, fails every call with that KMS exception.
	errorType string

	mu              sync.Mutex
	operations      []string
	getPublicKeyIDs []string
	signRequests    []kmsSignRequest
}

func newFakeKMSEndpoint(t *testing.T) *fakeKMSEndpoint {
	t.Helper()

	publicKeyDER, privateKey := generateMockECDSAPublicKeyOnCurve(t, elliptic.P256())

	return &fakeKMSEndpoint{t: t, publicKeyDER: publicKeyDER, privateKey: privateKey}
}

func (e *fakeKMSEndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		e.t.Errorf("failed to read request body: %v", err)
	}
	operation := strings.TrimPrefix(r.Header.Get("X-Amz-Target"), "TrentService.")

	e.mu.Lock()
	defer e.mu.Unlock()
	e.operations = append(e.operations, operation)

	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	if e.errorType != "" {
		w.WriteHeader(http.StatusBadRequest)
		e.writeJSON(w, map[string]string{"__type": e.errorType, "message": "rejected by the test endpoint"})

		return
	}

	switch operation {
	case "GetPublicKey":
		var request struct {
			KeyID string `json:"KeyId"`
		}
		e.decode(body, &request)
		e.getPublicKeyIDs = append(e.getPublicKeyIDs, request.KeyID)
		e.writeJSON(w, map[string]any{
			"KeyId":             request.KeyID,
			"PublicKey":         e.publicKeyDER,
			"KeyUsage":          types.KeyUsageTypeSignVerify,
			"KeySpec":           types.KeySpecEccNistP256,
			"SigningAlgorithms": []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEcdsaSha256},
		})
	case "Sign":
		var request kmsSignRequest
		e.decode(body, &request)
		e.signRequests = append(e.signRequests, request)
		signature, signErr := e.privateKey.Sign(rand.Reader, request.Message, crypto.SHA256)
		if signErr != nil {
			e.t.Errorf("failed to sign: %v", signErr)
		}
		e.writeJSON(w, map[string]any{
			"KeyId":            request.KeyID,
			"Signature":        signature,
			"SigningAlgorithm": request.SigningAlgorithm,
		})
	default:
		e.t.Errorf("unexpected KMS operation %q", operation)
		w.WriteHeader(http.StatusBadRequest)
	}
}

func (e *fakeKMSEndpoint) decode(body []byte, request any) {
	if err := json.Unmarshal(body, request); err != nil {
		e.t.Errorf("failed to decode request %s: %v", body, err)
	}
}

func (e *fakeKMSEndpoint) writeJSON(w io.Writer, response any) {
	if err := json.NewEncoder(w).Encode(response); err != nil {
		e.t.Errorf("failed to write response: %v", err)
	}
}

// calls returns the KMS operations the endpoint has served, in order.
func (e *fakeKMSEndpoint) calls() []string {
	e.mu.Lock()
	defer e.mu.Unlock()

	return slices.Clone(e.operations)
}

// useDefaultAWSConfig points the default AWS configuration at endpoint, with
// static credentials, and keeps it away from the developer's own AWS files,
// profiles and instance metadata.
func useDefaultAWSConfig(t *testing.T, endpoint http.Handler) {
	t.Helper()

	server := httptest.NewServer(endpoint)
	t.Cleanup(server.Close)

	dir := t.TempDir()
	for key, value := range map[string]string{
		"AWS_ACCESS_KEY_ID":                   "AKIDEXAMPLE",
		"AWS_SECRET_ACCESS_KEY":               "test-secret",
		"AWS_SESSION_TOKEN":                   "",
		"AWS_REGION":                          "us-east-1",
		"AWS_PROFILE":                         "",
		"AWS_DEFAULT_PROFILE":                 "",
		"AWS_CONFIG_FILE":                     filepath.Join(dir, "config"),
		"AWS_SHARED_CREDENTIALS_FILE":         filepath.Join(dir, "credentials"),
		"AWS_CA_BUNDLE":                       "",
		"AWS_EC2_METADATA_DISABLED":           "true",
		"AWS_ENDPOINT_URL":                    "",
		"AWS_ENDPOINT_URL_KMS":                server.URL,
		"AWS_IGNORE_CONFIGURED_ENDPOINT_URLS": "",
	} {
		t.Setenv(key, value)
	}
}

//nolint:paralleltest // t.Setenv changes process-wide state
func TestNewKMSCSRBuilderWithContext_DefaultConfigEndToEnd(t *testing.T) {
	endpoint := newFakeKMSEndpoint(t)
	useDefaultAWSConfig(t, endpoint)

	builder, err := NewKMSCSRBuilderWithContext(t.Context(), &SubjectInfo{CommonName: "sdk.example.com"}, testARN)
	if err != nil {
		t.Fatalf("failed to create builder: %v", err)
	}
	if builder.HashAlgo != types.SigningAlgorithmSpecEcdsaSha256 {
		t.Errorf("expected default algorithm %s, got: %s", types.SigningAlgorithmSpecEcdsaSha256, builder.HashAlgo)
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
	if !endpoint.privateKey.PublicKey.Equal(csr.PublicKey) {
		t.Error("public key in CSR does not match the KMS key")
	}

	if calls := endpoint.calls(); !slices.Equal(calls, []string{"GetPublicKey", "Sign"}) {
		t.Fatalf("expected GetPublicKey then Sign, got: %q", calls)
	}
	endpoint.mu.Lock()
	defer endpoint.mu.Unlock()
	if !slices.Equal(endpoint.getPublicKeyIDs, []string{testARN}) {
		t.Errorf("GetPublicKey: expected KeyId %q, got: %q", testARN, endpoint.getPublicKeyIDs)
	}
	sign := endpoint.signRequests[0]
	if sign.KeyID != testARN {
		t.Errorf("Sign: expected KeyId %q, got: %q", testARN, sign.KeyID)
	}
	// KMS hashes a RAW message itself, which would sign a digest of the digest.
	if sign.MessageType != string(types.MessageTypeDigest) {
		t.Errorf("Sign: expected MessageType %s, got: %q", types.MessageTypeDigest, sign.MessageType)
	}
	if expected := types.SigningAlgorithmSpecEcdsaSha256; sign.SigningAlgorithm != string(expected) {
		t.Errorf("Sign: expected SigningAlgorithm %s, got: %q", expected, sign.SigningAlgorithm)
	}
	if len(sign.Message) != crypto.SHA256.Size() {
		t.Errorf("Sign: expected a SHA-256 digest, got %d bytes", len(sign.Message))
	}
}

//nolint:paralleltest // t.Setenv changes process-wide state
func TestNewKMSCSRBuilder_PreservesKMSErrorType(t *testing.T) {
	endpoint := newFakeKMSEndpoint(t)
	endpoint.errorType = "NotFoundException"
	useDefaultAWSConfig(t, endpoint)

	_, err := NewKMSCSRBuilder(&SubjectInfo{CommonName: "sdk.example.com"}, testARN)
	if err == nil || !strings.HasPrefix(err.Error(), "failed to load public key from KMS: ") {
		t.Fatalf("expected public key load error, got: %v", err)
	}
	// Callers need the typed SDK error to tell a missing key from, say, a
	// permissions problem.
	if _, ok := errors.AsType[*types.NotFoundException](err); !ok {
		t.Fatalf("expected a wrapped *types.NotFoundException, got: %v", err)
	}
	if calls := endpoint.calls(); !slices.Equal(calls, []string{"GetPublicKey"}) {
		t.Errorf("expected a single GetPublicKey call, got: %q", calls)
	}
}

// TestNewKMSCSRBuilderWithContext_ReportsConfigLoadError cannot run in
// parallel, because t.Setenv changes process-wide state.
func TestNewKMSCSRBuilderWithContext_ReportsConfigLoadError(t *testing.T) {
	endpoint := newFakeKMSEndpoint(t)
	useDefaultAWSConfig(t, endpoint)
	const profile = "kmscsr-test-missing-profile"
	t.Setenv("AWS_PROFILE", profile)

	_, err := NewKMSCSRBuilderWithContext(t.Context(), &SubjectInfo{CommonName: "sdk.example.com"}, testARN)
	if err == nil || !strings.HasPrefix(err.Error(), "failed to load AWS config: ") {
		t.Fatalf("expected AWS config error, got: %v", err)
	}
	if profileErr, ok := errors.AsType[config.SharedConfigProfileNotExistError](err); !ok ||
		profileErr.Profile != profile {
		t.Fatalf("expected a wrapped missing profile error for %q, got: %v", profile, err)
	}
	if calls := endpoint.calls(); len(calls) != 0 {
		t.Errorf("expected no KMS calls, got: %q", calls)
	}
}
