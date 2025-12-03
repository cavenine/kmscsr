package kmscsr

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// KMSClient defines the interface for KMS operations needed by the builder.
type KMSClient interface {
	GetPublicKey(ctx context.Context,
		params *kms.GetPublicKeyInput,
		optFns ...func(*kms.Options),
	) (*kms.GetPublicKeyOutput, error)
	Sign(ctx context.Context,
		params *kms.SignInput,
		optFns ...func(*kms.Options),
	) (*kms.SignOutput, error)
}

// Builder provides functionality to build Certificate Signing Requests
// signed by AWS KMS keys.
type Builder struct {
	// Subject information for the CSR
	Subject *pkix.Name

	// KMS Key ARN for signing
	KMSArn string

	// Hash algorithm (SHA256, SHA384, SHA512)
	HashAlgo types.SigningAlgorithmSpec

	// CA indicates if this is a CA certificate request
	CA bool

	// SubjectAltDomains contains DNS names for the SAN extension
	SubjectAltDomains []string

	// SubjectAltIPs contains IP addresses for the SAN extension
	SubjectAltIPs []net.IP

	// KeyUsage represents the key usage extension
	KeyUsage x509.KeyUsage

	// ExtKeyUsage represents extended key usage
	ExtKeyUsage []x509.ExtKeyUsage

	// Internal fields
	kmsClient KMSClient
	publicKey crypto.PublicKey
	signAlgo  types.SigningAlgorithmSpec
	keySpec   types.KeySpec
}

// SubjectInfo holds all the subject-distinguished name fields.
type SubjectInfo struct {
	CountryName            string
	StateOrProvinceName    string
	LocalityName           string
	OrganizationName       string
	CommonName             string
	OrganizationalUnitName string
	EmailAddress           string
	StreetAddress          string
	PostalCode             string
}

// NewKMSCSRBuilder creates a new CSR builder with AWS KMS integration.
func NewKMSCSRBuilder(subject *SubjectInfo, kmsArn string) (*Builder, error) {
	if subject == nil {
		return nil, errors.New("subject cannot be nil")
	}

	if kmsArn == "" {
		return nil, errors.New("kmsArn cannot be empty")
	}

	// Initialize AWS KMS client
	ctx := context.TODO()
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	kmsClient := kms.NewFromConfig(cfg)

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
		kmsClient: kmsClient,
		HashAlgo:  types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
		CA:        false,
	}

	// Retrieve public key from KMS
	if loadErr := builder.loadPublicKey(ctx); loadErr != nil {
		return nil, fmt.Errorf("failed to load public key from KMS: %w", loadErr)
	}

	return builder, nil
}

// loadPublicKey retrieves the public key from AWS KMS.
func (b *Builder) loadPublicKey(ctx context.Context) error {
	output, err := b.kmsClient.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: &b.KMSArn,
	})
	if err != nil {
		return fmt.Errorf("could not get public key from KMS: %w", err)
	}

	// Verify key usage is SIGN_VERIFY
	if output.KeyUsage != types.KeyUsageTypeSignVerify {
		return fmt.Errorf("KMS key must have SIGN_VERIFY usage, got: %v", output.KeyUsage)
	}

	// Store key spec and determine signing algorithm
	b.keySpec = output.KeySpec

	// Parse the public key
	pubKey, err := x509.ParsePKIXPublicKey(output.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	b.publicKey = pubKey

	// Determine the appropriate signing algorithm based on the key type
	switch pubKey.(type) {
	case *rsa.PublicKey:
		b.signAlgo = types.SigningAlgorithmSpecRsassaPkcs1V15Sha256
	case *ecdsa.PublicKey:
		b.signAlgo = types.SigningAlgorithmSpecEcdsaSha256
	default:
		return fmt.Errorf("unsupported public key type: %T", pubKey)
	}

	// Set default key usage based on CA setting
	if b.CA {
		b.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		b.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}
	} else {
		b.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		b.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}

	return nil
}

// SetCA sets whether this is a CA certificate request.
func (b *Builder) SetCA(isCA bool) {
	b.CA = isCA
	if isCA {
		b.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		b.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}
	} else {
		b.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		b.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}
}

// BuildWithKMS constructs and signs the CSR using AWS KMS.
func (b *Builder) BuildWithKMS(_ context.Context) ([]byte, error) {
	// Create certificate request template
	template := x509.CertificateRequest{
		Subject:            *b.Subject,
		SignatureAlgorithm: getSignatureAlgorithm(b.signAlgo),
	}

	// Add SAN extension if domains or IPs are specified
	if len(b.SubjectAltDomains) > 0 || len(b.SubjectAltIPs) > 0 {
		template.DNSNames = b.SubjectAltDomains
		template.IPAddresses = b.SubjectAltIPs
	}

	// Add extensions
	var extensions []pkix.Extension

	// Basic Constraints
	if b.CA {
		basicConstraints := basicConstraintsExtension(true)
		extensions = append(extensions, basicConstraints)
	}

	// Key Usage
	if b.KeyUsage != 0 {
		keyUsageExt, err := keyUsageExtension(b.KeyUsage)
		if err != nil {
			return nil, fmt.Errorf("failed to create key usage extension: %w", err)
		}
		extensions = append(extensions, keyUsageExt)
	}

	// Extended Key Usage
	if len(b.ExtKeyUsage) > 0 {
		extKeyUsageExt, err := extKeyUsageExtension(b.ExtKeyUsage)
		if err != nil {
			return nil, fmt.Errorf("failed to create extended key usage extension: %w", err)
		}
		extensions = append(extensions, extKeyUsageExt)
	}

	template.ExtraExtensions = extensions

	// Create the CSR (unsigned)
	csrDER, err := x509.CreateCertificateRequest(nil, &template, &kmsSigner{
		kmsClient: b.kmsClient,
		keyArn:    b.KMSArn,
		signAlgo:  b.signAlgo,
		publicKey: b.publicKey,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate request: %w", err)
	}

	return csrDER, nil
}

// PEMEncode encodes the CSR in PEM format.
func PEMEncode(csrDER []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})
}

// kmsSigner implements crypto.Signer interface using AWS KMS.
type kmsSigner struct {
	kmsClient KMSClient
	keyArn    string
	signAlgo  types.SigningAlgorithmSpec
	publicKey crypto.PublicKey
}

func (s *kmsSigner) Public() crypto.PublicKey {
	return s.publicKey
}

func (s *kmsSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	ctx := context.TODO()

	// Sign with KMS
	output, err := s.kmsClient.Sign(ctx, &kms.SignInput{
		KeyId:            &s.keyArn,
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: s.signAlgo,
	})
	if err != nil {
		return nil, fmt.Errorf("KMS signing failed: %w", err)
	}

	return output.Signature, nil
}

// Helper functions for extensions

func basicConstraintsExtension(isCA bool) pkix.Extension {
	val, _ := asn1.Marshal(struct {
		IsCA bool `asn1:"optional"`
	}{IsCA: isCA})

	return pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 19},
		Critical: isCA,
		Value:    val,
	}
}

// keyUsageExtension creates a PKIX extension for the given x509.KeyUsage.
// The function encodes the key usage into an ASN.1 bit string and returns it as a critical extension.
func keyUsageExtension(usage x509.KeyUsage) (pkix.Extension, error) {
	// Convert KeyUsage to bit string
	var usageBits asn1.BitString
	usageBits.Bytes = []byte{byte(usage >> 8), byte(usage)} //nolint:mnd // intentional
	usageBits.BitLength = 9

	val, err := asn1.Marshal(usageBits)
	if err != nil {
		return pkix.Extension{}, err
	}

	return pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 15},
		Critical: true,
		Value:    val,
	}, nil
}

func extKeyUsageExtension(usages []x509.ExtKeyUsage) (pkix.Extension, error) {
	var oids []asn1.ObjectIdentifier
	for _, usage := range usages {
		oid := extKeyUsageOID(usage)
		if oid != nil {
			oids = append(oids, oid)
		}
	}

	val, err := asn1.Marshal(oids)
	if err != nil {
		return pkix.Extension{}, err
	}

	return pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 37},
		Critical: false,
		Value:    val,
	}, nil
}

func extKeyUsageOID(usage x509.ExtKeyUsage) asn1.ObjectIdentifier {
	switch usage { //nolint:exhaustive // only supporting common server/client usages
	case x509.ExtKeyUsageServerAuth:
		return asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	case x509.ExtKeyUsageClientAuth:
		return asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	case x509.ExtKeyUsageCodeSigning:
		return asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
	case x509.ExtKeyUsageEmailProtection:
		return asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}
	case x509.ExtKeyUsageTimeStamping:
		return asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	case x509.ExtKeyUsageOCSPSigning:
		return asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
	default:
		return nil
	}
}

func getSignatureAlgorithm(algo types.SigningAlgorithmSpec) x509.SignatureAlgorithm {
	switch algo { //nolint:exhaustive // only supporting RSA and ECDSA
	case types.SigningAlgorithmSpecRsassaPkcs1V15Sha256:
		return x509.SHA256WithRSA
	case types.SigningAlgorithmSpecRsassaPkcs1V15Sha384:
		return x509.SHA384WithRSA
	case types.SigningAlgorithmSpecRsassaPkcs1V15Sha512:
		return x509.SHA512WithRSA
	case types.SigningAlgorithmSpecEcdsaSha256:
		return x509.ECDSAWithSHA256
	case types.SigningAlgorithmSpecEcdsaSha384:
		return x509.ECDSAWithSHA384
	case types.SigningAlgorithmSpecEcdsaSha512:
		return x509.ECDSAWithSHA512
	default:
		return x509.SHA256WithRSA
	}
}
