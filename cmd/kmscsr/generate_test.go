package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/cavenine/kmscsr"
)

const testARN = "arn:aws:kms:us-east-1:123456789012:key/test-key-id"

// fakeKMS is a local KMS stand-in that signs with an in-process RSA key.
type fakeKMS struct {
	publicKeyDER []byte
	privateKey   *rsa.PrivateKey
	signErr      error
}

func newFakeKMS(t *testing.T) *fakeKMS {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}

	return &fakeKMS{publicKeyDER: publicKeyDER, privateKey: privateKey}
}

func (f *fakeKMS) GetPublicKey(
	_ context.Context,
	_ *kms.GetPublicKeyInput,
	_ ...func(*kms.Options),
) (*kms.GetPublicKeyOutput, error) {
	return &kms.GetPublicKeyOutput{
		PublicKey:         f.publicKeyDER,
		KeyUsage:          types.KeyUsageTypeSignVerify,
		KeySpec:           types.KeySpecRsa2048,
		SigningAlgorithms: []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecRsassaPkcs1V15Sha256},
	}, nil
}

func (f *fakeKMS) Sign(
	_ context.Context,
	params *kms.SignInput,
	_ ...func(*kms.Options),
) (*kms.SignOutput, error) {
	if f.signErr != nil {
		return nil, f.signErr
	}

	signature, err := f.privateKey.Sign(rand.Reader, params.Message, crypto.SHA256)
	if err != nil {
		return nil, err
	}

	return &kms.SignOutput{Signature: signature}, nil
}

// clientFactory adapts a KMS client into the command's builder factory.
func clientFactory(client kmscsr.KMSClient) builderFactory {
	return func(ctx context.Context, subject *kmscsr.SubjectInfo, kmsArn string) (*kmscsr.Builder, error) {
		return kmscsr.NewKMSCSRBuilderWithClient(ctx, subject, kmsArn, client)
	}
}

// executeWith runs the root command against factory and captures its streams.
func executeWith(t *testing.T, factory builderFactory, args ...string) (string, string, error) {
	t.Helper()

	command, err := newRootCommandWithOptions(&cliOptions{newBuilder: factory})
	if err != nil {
		t.Fatalf("failed to create command: %v", err)
	}

	var stdout, stderr bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&stderr)
	command.SetArgs(args)

	execErr := command.ExecuteContext(t.Context())

	return stdout.String(), stderr.String(), execErr
}

// execute runs the root command with a fake KMS client and captures its streams.
func execute(t *testing.T, client kmscsr.KMSClient, args ...string) (string, string, error) {
	t.Helper()

	return executeWith(t, clientFactory(client), args...)
}

// unusedFactory fails the test if the command reaches builder construction.
func unusedFactory(t *testing.T) builderFactory {
	t.Helper()

	return func(context.Context, *kmscsr.SubjectInfo, string) (*kmscsr.Builder, error) {
		t.Error("builder should not be constructed for this input")

		return nil, errors.New("unexpected builder construction")
	}
}

// parseCSROutput decodes the PEM the command wrote and verifies its signature.
func parseCSROutput(t *testing.T, output string) *x509.CertificateRequest {
	t.Helper()

	block, rest := pem.Decode([]byte(output))
	if block == nil {
		t.Fatalf("output is not PEM: %q", output)

		return nil
	}
	if block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("unexpected PEM type: %s", block.Type)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		t.Fatalf("unexpected trailing output: %q", rest)
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse CSR: %v", err)
	}
	if signatureErr := csr.CheckSignature(); signatureErr != nil {
		t.Fatalf("CSR signature verification failed: %v", signatureErr)
	}

	return csr
}

func TestGenerateCSR_WritesPEMToStdout(t *testing.T) {
	stdout, _, err := execute(t, newFakeKMS(t),
		"--kms-arn", testARN,
		"--common-name", "example.com",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	csr := parseCSROutput(t, stdout)
	if csr.Subject.CommonName != "example.com" {
		t.Fatalf("expected CN example.com, got: %s", csr.Subject.CommonName)
	}
}

func TestGenerateCSR_MapsAllSubjectFields(t *testing.T) {
	stdout, _, err := execute(t, newFakeKMS(t),
		"--kms-arn", testARN,
		"--common-name", "example.com",
		"--country", "US",
		"--state", "California",
		"--locality", "San Francisco",
		"--organization", "Example Corp",
		"--org-unit", "Engineering",
		"--email", "admin@example.com",
		"--street", "1 Example Street",
		"--postal-code", "94105",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	csr := parseCSROutput(t, stdout)
	subject := csr.Subject
	checks := []struct {
		field  string
		actual []string
		want   string
	}{
		{"country", subject.Country, "US"},
		{"province", subject.Province, "California"},
		{"locality", subject.Locality, "San Francisco"},
		{"organization", subject.Organization, "Example Corp"},
		{"organizational unit", subject.OrganizationalUnit, "Engineering"},
		{"street address", subject.StreetAddress, "1 Example Street"},
		{"postal code", subject.PostalCode, "94105"},
	}
	for _, check := range checks {
		if len(check.actual) != 1 || check.actual[0] != check.want {
			t.Errorf("%s: expected [%s], got %#v", check.field, check.want, check.actual)
		}
	}

	emailOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
	found := false
	for _, name := range subject.Names {
		if name.Type.Equal(emailOID) && name.Value == "admin@example.com" {
			found = true
		}
	}
	if !found {
		t.Errorf("email address not present in subject: %#v", subject.Names)
	}
}

func TestGenerateCSR_WiresSubjectAltNames(t *testing.T) {
	stdout, _, err := execute(t, newFakeKMS(t),
		"--kms-arn", testARN,
		"--common-name", "example.com",
		"--san-dns", "www.example.com,api.example.com",
		"--san-ip", "192.0.2.1",
		"--san-ip", "2001:db8::1",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	csr := parseCSROutput(t, stdout)
	if len(csr.DNSNames) != 2 || csr.DNSNames[0] != "www.example.com" || csr.DNSNames[1] != "api.example.com" {
		t.Errorf("unexpected DNS names: %#v", csr.DNSNames)
	}
	if len(csr.IPAddresses) != 2 ||
		!csr.IPAddresses[0].Equal(net.ParseIP("192.0.2.1")) ||
		!csr.IPAddresses[1].Equal(net.ParseIP("2001:db8::1")) {
		t.Errorf("unexpected IP addresses: %#v", csr.IPAddresses)
	}
}

func TestGenerateCSR_CAFlagSetsCAKeyUsage(t *testing.T) {
	stdout, _, err := execute(t, newFakeKMS(t),
		"--kms-arn", testARN,
		"--common-name", "ca.example.com",
		"--ca",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	csr := parseCSROutput(t, stdout)
	basicConstraintsOID := asn1.ObjectIdentifier{2, 5, 29, 19}
	found := false
	for _, extension := range csr.Extensions {
		if extension.Id.Equal(basicConstraintsOID) {
			found = true
			if !extension.Critical {
				t.Error("expected basic constraints to be critical")
			}
		}
	}
	if !found {
		t.Error("expected basic constraints extension in a CA request")
	}
}

func TestGenerateCSR_WritesOutputFileWithRestrictivePermissions(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "request.csr")

	stdout, stderr, err := execute(t, newFakeKMS(t),
		"--kms-arn", testARN,
		"--common-name", "example.com",
		"--output", outputPath,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stdout != "" {
		t.Errorf("expected no stdout output, got: %q", stdout)
	}
	if !strings.Contains(stderr, outputPath) {
		t.Errorf("expected confirmation naming the output file, got: %q", stderr)
	}

	info, err := os.Stat(outputPath)
	if err != nil {
		t.Fatalf("failed to stat output file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != fs.FileMode(0600) {
		t.Errorf("expected 0600 permissions, got: %v", perm)
	}

	contents, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}
	parseCSROutput(t, string(contents))
}

func TestGenerateCSR_ReportsUnwritableOutputFile(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "missing-dir", "request.csr")

	_, _, err := execute(t, newFakeKMS(t),
		"--kms-arn", testARN,
		"--common-name", "example.com",
		"--output", outputPath,
	)
	if err == nil || !strings.Contains(err.Error(), "failed to write CSR to file") {
		t.Fatalf("expected output file error, got: %v", err)
	}
}

func TestGenerateCSR_RejectsEmptyRequiredFlags(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "empty kms arn",
			args:    []string{"--kms-arn", "", "--common-name", "example.com"},
			wantErr: "--kms-arn cannot be empty",
		},
		{
			name:    "empty common name",
			args:    []string{"--kms-arn", testARN, "--common-name", ""},
			wantErr: "--common-name cannot be empty",
		},
		{
			name:    "whitespace common name",
			args:    []string{"--kms-arn", testARN, "--common-name", "   "},
			wantErr: "--common-name cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// unusedFactory also asserts the rejection happens before any AWS work.
			_, _, err := executeWith(t, unusedFactory(t), tt.args...)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected %q, got: %v", tt.wantErr, err)
			}
		})
	}
}

func TestGenerateCSR_RejectsEmptySANEntry(t *testing.T) {
	_, _, err := execute(t, newFakeKMS(t),
		"--kms-arn", testARN,
		"--common-name", "example.com",
		"--san-dns", "www.example.com,,api.example.com",
	)
	if err == nil || !strings.Contains(err.Error(), "DNS name cannot be empty") {
		t.Fatalf("expected empty SAN error, got: %v", err)
	}
}

func TestGenerateCSR_PropagatesBuilderError(t *testing.T) {
	sentinel := errors.New("credentials not found")
	factory := func(context.Context, *kmscsr.SubjectInfo, string) (*kmscsr.Builder, error) {
		return nil, sentinel
	}

	_, _, err := executeWith(t, factory, "--kms-arn", testARN, "--common-name", "example.com")
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected wrapped builder error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "failed to create KMS CSR builder") {
		t.Fatalf("expected builder context in error, got: %v", err)
	}
}

func TestGenerateCSR_PropagatesSignError(t *testing.T) {
	client := newFakeKMS(t)
	client.signErr = errors.New("AccessDeniedException")

	_, _, err := execute(t, client,
		"--kms-arn", testARN,
		"--common-name", "example.com",
	)
	if err == nil || !strings.Contains(err.Error(), "failed to build CSR") {
		t.Fatalf("expected build error, got: %v", err)
	}
}

func TestGenerateCSR_SuppressesUsageOnOperationalError(t *testing.T) {
	client := newFakeKMS(t)
	client.signErr = errors.New("AccessDeniedException")

	stdout, stderr, err := execute(t, client,
		"--kms-arn", testARN,
		"--common-name", "example.com",
	)
	if err == nil {
		t.Fatal("expected an error")
	}
	if output := stdout + stderr; strings.Contains(output, "Usage:") {
		t.Errorf("usage text should not follow an operational failure, got: %q", output)
	}
}

func TestRootCommand_ShowsUsageOnFlagError(t *testing.T) {
	stdout, stderr, err := executeWith(t, unusedFactory(t), "--common-name", "example.com")
	if err == nil || !strings.Contains(err.Error(), "kms-arn") {
		t.Fatalf("expected missing flag error, got: %v", err)
	}
	if output := stdout + stderr; !strings.Contains(output, "Usage:") {
		t.Errorf("expected usage text for a flag error, got: %q", output)
	}
}

func TestGenerateCSR_TimeoutZeroDisablesDeadline(t *testing.T) {
	stdout, _, err := execute(t, newFakeKMS(t),
		"--kms-arn", testARN,
		"--common-name", "example.com",
		"--timeout", "0",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	parseCSROutput(t, stdout)
}

func TestGenerateCSR_TimeoutAppliesDeadline(t *testing.T) {
	var deadlineSet bool
	inner := clientFactory(newFakeKMS(t))
	factory := func(ctx context.Context, subject *kmscsr.SubjectInfo, kmsArn string) (*kmscsr.Builder, error) {
		_, deadlineSet = ctx.Deadline()

		return inner(ctx, subject, kmsArn)
	}

	_, _, err := executeWith(t, factory,
		"--kms-arn", testARN,
		"--common-name", "example.com",
		"--timeout", "5s",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !deadlineSet {
		t.Error("expected a deadline on the context passed to the builder")
	}
}
