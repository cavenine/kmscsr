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
	"math/bits"
	"net"
	"slices"
	"strings"
	"unicode"

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

	// HashAlgo is the complete KMS signing algorithm to use. The name is kept
	// for backward compatibility.
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
	kmsClient                  KMSClient
	publicKey                  crypto.PublicKey
	supportedSigningAlgorithms []types.SigningAlgorithmSpec
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
	return NewKMSCSRBuilderWithContext(context.Background(), subject, kmsArn)
}

// NewKMSCSRBuilderWithContext creates a new CSR builder with AWS KMS integration
// and uses ctx for AWS configuration loading and public-key retrieval.
func NewKMSCSRBuilderWithContext(ctx context.Context, subject *SubjectInfo, kmsArn string) (*Builder, error) {
	if err := validateBuilderInputs(ctx, subject, kmsArn); err != nil {
		return nil, err
	}

	// Initialize AWS KMS client
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	kmsClient := kms.NewFromConfig(cfg)

	return newKMSCSRBuilder(ctx, subject, kmsArn, kmsClient)
}

// NewKMSCSRBuilderWithClient creates a new CSR builder that signs with the
// supplied KMS client instead of one built from the ambient AWS configuration.
// Use it to control the region, endpoint, or credentials of the KMS client.
func NewKMSCSRBuilderWithClient(
	ctx context.Context,
	subject *SubjectInfo,
	kmsArn string,
	kmsClient KMSClient,
) (*Builder, error) {
	return newKMSCSRBuilder(ctx, subject, kmsArn, kmsClient)
}

func newKMSCSRBuilder(
	ctx context.Context,
	subject *SubjectInfo,
	kmsArn string,
	kmsClient KMSClient,
) (*Builder, error) {
	if err := validateBuilderInputs(ctx, subject, kmsArn); err != nil {
		return nil, err
	}
	if kmsClient == nil {
		return nil, errors.New("KMS client cannot be nil")
	}

	name, err := subjectName(subject)
	if err != nil {
		return nil, err
	}

	builder := &Builder{
		Subject:   name,
		KMSArn:    kmsArn,
		kmsClient: kmsClient,
		CA:        false,
	}

	// Retrieve public key from KMS
	if loadErr := builder.loadPublicKey(ctx); loadErr != nil {
		return nil, fmt.Errorf("failed to load public key from KMS: %w", loadErr)
	}

	return builder, nil
}

func validateBuilderInputs(ctx context.Context, subject *SubjectInfo, kmsArn string) error {
	if ctx == nil {
		return errors.New("context cannot be nil")
	}
	if subject == nil {
		return errors.New("subject cannot be nil")
	}
	if kmsArn == "" {
		return errors.New("kmsArn cannot be empty")
	}
	for _, char := range subject.EmailAddress {
		if char > unicode.MaxASCII {
			return errors.New("email address must contain only ASCII characters")
		}
	}

	return validateSubjectFields(subject)
}

// validateSubjectFields rejects control characters anywhere in the subject.
// An embedded NUL or line break is silently truncated or misparsed by common
// certificate tooling, so a distinguished name carrying one cannot be trusted
// to mean the same thing to the requester and to the issuing CA.
func validateSubjectFields(subject *SubjectInfo) error {
	fields := []struct {
		name  string
		value string
	}{
		{"country name", subject.CountryName},
		{"state or province name", subject.StateOrProvinceName},
		{"locality name", subject.LocalityName},
		{"organization name", subject.OrganizationName},
		{"common name", subject.CommonName},
		{"organizational unit name", subject.OrganizationalUnitName},
		{"email address", subject.EmailAddress},
		{"street address", subject.StreetAddress},
		{"postal code", subject.PostalCode},
	}
	for _, field := range fields {
		if strings.ContainsFunc(field.value, unicode.IsControl) {
			return fmt.Errorf("%s must not contain control characters", field.name)
		}
	}

	return nil
}

func subjectName(subject *SubjectInfo) (*pkix.Name, error) {
	if subject == nil {
		return nil, errors.New("subject cannot be nil")
	}

	name := &pkix.Name{CommonName: subject.CommonName}
	name.Country = appendNonEmpty(name.Country, subject.CountryName)
	name.Province = appendNonEmpty(name.Province, subject.StateOrProvinceName)
	name.Locality = appendNonEmpty(name.Locality, subject.LocalityName)
	name.Organization = appendNonEmpty(name.Organization, subject.OrganizationName)
	name.OrganizationalUnit = appendNonEmpty(name.OrganizationalUnit, subject.OrganizationalUnitName)
	name.StreetAddress = appendNonEmpty(name.StreetAddress, subject.StreetAddress)
	name.PostalCode = appendNonEmpty(name.PostalCode, subject.PostalCode)
	if subject.EmailAddress != "" {
		name.ExtraNames = append(name.ExtraNames, pkix.AttributeTypeAndValue{
			Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1},
			Value: asn1.RawValue{
				Tag:   asn1.TagIA5String,
				Bytes: []byte(subject.EmailAddress),
			},
		})
	}

	return name, nil
}

func appendNonEmpty(values []string, value string) []string {
	if value == "" {
		return values
	}

	return append(values, value)
}

// loadPublicKey retrieves the public key from AWS KMS.
func (b *Builder) loadPublicKey(ctx context.Context) error {
	output, err := b.kmsClient.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: &b.KMSArn,
	})
	if err != nil {
		return fmt.Errorf("could not get public key from KMS: %w", err)
	}
	if output == nil {
		return errors.New("KMS GetPublicKey returned an empty response")
	}

	// Verify key usage is SIGN_VERIFY
	if output.KeyUsage != types.KeyUsageTypeSignVerify {
		return fmt.Errorf("KMS key must have SIGN_VERIFY usage, got: %v", output.KeyUsage)
	}

	b.supportedSigningAlgorithms = append([]types.SigningAlgorithmSpec(nil), output.SigningAlgorithms...)

	// Parse the public key
	pubKey, err := x509.ParsePKIXPublicKey(output.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	b.publicKey = pubKey

	// Determine an appropriate default that KMS explicitly advertises.
	b.HashAlgo, err = defaultSigningAlgorithm(pubKey, b.supportedSigningAlgorithms)
	if err != nil {
		return err
	}

	// Apply the key usage defaults matching the current CA setting.
	b.SetCA(b.CA)

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
func (b *Builder) BuildWithKMS(ctx context.Context) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("context cannot be nil")
	}
	if b.Subject == nil {
		return nil, errors.New("subject cannot be nil")
	}
	if err := validateSubjectAltNames(b.SubjectAltDomains, b.SubjectAltIPs); err != nil {
		return nil, err
	}

	signAlgo, signatureAlgorithm, err := b.resolveSigningAlgorithm()
	if err != nil {
		return nil, err
	}

	// Create certificate request template
	template := x509.CertificateRequest{
		Subject:            *b.Subject,
		SignatureAlgorithm: signatureAlgorithm,
	}

	// Add extensions
	var extensions []pkix.Extension

	// Basic Constraints. The extension is always requested, so that a non-CA
	// request states cA=FALSE rather than leaving it to the issuer to infer.
	basicConstraints, constraintsErr := basicConstraintsExtension(b.CA)
	if constraintsErr != nil {
		return nil, fmt.Errorf("failed to create basic constraints extension: %w", constraintsErr)
	}
	extensions = append(extensions, basicConstraints)

	// Key Usage
	if b.KeyUsage != 0 {
		keyUsageExt, keyUsageErr := keyUsageExtension(b.KeyUsage)
		if keyUsageErr != nil {
			return nil, fmt.Errorf("failed to create key usage extension: %w", keyUsageErr)
		}
		extensions = append(extensions, keyUsageExt)
	}

	// Extended Key Usage
	if len(b.ExtKeyUsage) > 0 {
		extKeyUsageExt, extUsageErr := extKeyUsageExtension(b.ExtKeyUsage)
		if extUsageErr != nil {
			return nil, fmt.Errorf("failed to create extended key usage extension: %w", extUsageErr)
		}
		extensions = append(extensions, extKeyUsageExt)
	}

	// Subject Alternative Name. Built here rather than through the template's
	// DNSNames and IPAddresses fields so that criticality follows RFC 5280.
	if len(b.SubjectAltDomains) > 0 || len(b.SubjectAltIPs) > 0 {
		sanExt, sanErr := subjectAltNameExtension(
			b.SubjectAltDomains,
			b.SubjectAltIPs,
			subjectIsEmpty(b.Subject),
		)
		if sanErr != nil {
			return nil, fmt.Errorf("failed to create subject alternative name extension: %w", sanErr)
		}
		extensions = append(extensions, sanExt)
	}

	template.ExtraExtensions = extensions

	// Create the CSR (unsigned)
	csrDER, err := x509.CreateCertificateRequest(nil, &template, &kmsSigner{
		ctx:       ctx,
		kmsClient: b.kmsClient,
		keyArn:    b.KMSArn,
		signAlgo:  signAlgo,
		publicKey: b.publicKey,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate request: %w", err)
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated certificate request: %w", err)
	}
	if signatureErr := csr.CheckSignature(); signatureErr != nil {
		return nil, fmt.Errorf("generated certificate request signature verification failed: %w", signatureErr)
	}

	return csrDER, nil
}

// GeneralName choice tags from RFC 5280 section 4.2.1.6.
const (
	nameTypeDNSName   = 2
	nameTypeIPAddress = 7
)

// subjectAltNameExtension builds the subject alternative name extension.
// RFC 5280 section 4.2.1.6 requires the extension to be critical when the
// subject is empty, because it then carries the request's only identity.
func subjectAltNameExtension(domains []string, ips []net.IP, critical bool) (pkix.Extension, error) {
	rawValues := make([]asn1.RawValue, 0, len(domains)+len(ips))
	for _, domain := range domains {
		rawValues = append(rawValues, asn1.RawValue{
			Class: asn1.ClassContextSpecific,
			Tag:   nameTypeDNSName,
			Bytes: []byte(domain),
		})
	}
	for _, ip := range ips {
		// Prefer the 4-byte form so IPv4 addresses do not encode as
		// IPv4-mapped IPv6, which parsers compare unequal.
		encoded := ip.To4()
		if encoded == nil {
			encoded = ip.To16()
		}
		rawValues = append(rawValues, asn1.RawValue{
			Class: asn1.ClassContextSpecific,
			Tag:   nameTypeIPAddress,
			Bytes: encoded,
		})
	}

	val, err := asn1.Marshal(rawValues)
	if err != nil {
		return pkix.Extension{}, err
	}

	return pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 17},
		Critical: critical,
		Value:    val,
	}, nil
}

// subjectIsEmpty reports whether the subject encodes to an empty distinguished
// name, which is the condition RFC 5280 attaches the critical SAN rule to.
func subjectIsEmpty(name *pkix.Name) bool {
	return name == nil || len(name.ToRDNSequence()) == 0
}

// validateSubjectAltNames rejects SAN entries that encode into a malformed
// extension. It runs before the KMS signing request so a bad entry fails with a
// message naming it, rather than surfacing afterwards as an opaque parse failure
// of the generated request.
func validateSubjectAltNames(domains []string, ips []net.IP) error {
	for _, domain := range domains {
		if strings.TrimSpace(domain) == "" {
			return errors.New("subject alternative DNS name cannot be empty")
		}
		if domain != strings.TrimSpace(domain) {
			return fmt.Errorf("subject alternative DNS name %q has leading or trailing whitespace", domain)
		}
		// dNSName is an IA5String, so it cannot carry non-ASCII runes.
		// Internationalized names must be supplied in their A-label form.
		for _, char := range domain {
			if char > unicode.MaxASCII {
				return fmt.Errorf("subject alternative DNS name %q must contain only ASCII characters", domain)
			}
		}
	}
	for _, ip := range ips {
		// To16 reports nil for any address that is neither 4 nor 16 bytes,
		// which is exactly the set x509 cannot encode.
		if ip.To16() == nil {
			return fmt.Errorf("invalid subject alternative IP address of length %d", len(ip))
		}
	}

	return nil
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
	ctx       context.Context
	kmsClient KMSClient
	keyArn    string
	signAlgo  types.SigningAlgorithmSpec
	publicKey crypto.PublicKey
}

func (s *kmsSigner) Public() crypto.PublicKey {
	return s.publicKey
}

func (s *kmsSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	expectedHash, err := hashForSigningAlgorithm(s.signAlgo)
	if err != nil {
		return nil, err
	}
	if opts == nil || opts.HashFunc() != expectedHash {
		return nil, fmt.Errorf("signer hash does not match KMS signing algorithm %s", s.signAlgo)
	}
	if len(digest) != expectedHash.Size() {
		return nil, fmt.Errorf("digest length %d does not match %s", len(digest), expectedHash)
	}

	// Sign with KMS
	output, err := s.kmsClient.Sign(s.ctx, &kms.SignInput{
		KeyId:            &s.keyArn,
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: s.signAlgo,
	})
	if err != nil {
		return nil, fmt.Errorf("KMS signing failed: %w", err)
	}
	if output == nil || len(output.Signature) == 0 {
		return nil, errors.New("KMS Sign returned an empty signature")
	}

	return output.Signature, nil
}

// Helper functions for extensions

func basicConstraintsExtension(isCA bool) (pkix.Extension, error) {
	val, err := asn1.Marshal(struct {
		IsCA bool `asn1:"optional"`
	}{IsCA: isCA})
	if err != nil {
		return pkix.Extension{}, err
	}

	return pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 19},
		Critical: isCA,
		Value:    val,
	}, nil
}

// keyUsageExtension creates a PKIX extension for the given x509.KeyUsage.
// The function encodes the key usage into an ASN.1 bit string and returns it as a critical extension.
func keyUsageExtension(usage x509.KeyUsage) (pkix.Extension, error) {
	const supportedKeyUsage = x509.KeyUsage(0x1ff)
	if usage&^supportedKeyUsage != 0 {
		return pkix.Extension{}, fmt.Errorf("unsupported key usage bits: %#x", usage&^supportedKeyUsage)
	}
	// RFC 5280 requires at least one bit to be set, and an all-zero usage would
	// encode as a BIT STRING whose declared length contradicts its content.
	if usage == 0 {
		return pkix.Extension{}, errors.New("key usage must set at least one bit")
	}

	usageValue := uint16(usage) //nolint:gosec // the supported-bit mask above proves this conversion is lossless
	const bitsPerByte = 8
	lowByte := byte(usageValue) //nolint:gosec // the supported-bit mask proves this extraction is intentional
	usageBytes := []byte{
		bits.Reverse8(lowByte),
		bits.Reverse8(byte(usageValue >> bitsPerByte)),
	}
	if usageBytes[1] == 0 {
		usageBytes = usageBytes[:1]
	}
	bitLength := len(usageBytes)*bitsPerByte - bits.TrailingZeros8(usageBytes[len(usageBytes)-1])
	usageBits := asn1.BitString{Bytes: usageBytes, BitLength: bitLength}

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
	oids := make([]asn1.ObjectIdentifier, 0, len(usages))
	for _, usage := range usages {
		oid, ok := extKeyUsageOID(usage)
		if !ok {
			return pkix.Extension{}, fmt.Errorf("unsupported extended key usage: %d", usage)
		}
		oids = append(oids, oid)
	}
	if len(oids) == 0 {
		return pkix.Extension{}, errors.New("extended key usage cannot be empty")
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

func extKeyUsageOID(usage x509.ExtKeyUsage) (asn1.ObjectIdentifier, bool) {
	switch usage { //nolint:exhaustive // only supporting common server/client usages
	case x509.ExtKeyUsageAny:
		return asn1.ObjectIdentifier{2, 5, 29, 37, 0}, true
	case x509.ExtKeyUsageServerAuth:
		return asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}, true
	case x509.ExtKeyUsageClientAuth:
		return asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}, true
	case x509.ExtKeyUsageCodeSigning:
		return asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}, true
	case x509.ExtKeyUsageEmailProtection:
		return asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}, true
	case x509.ExtKeyUsageTimeStamping:
		return asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}, true
	case x509.ExtKeyUsageOCSPSigning:
		return asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}, true
	default:
		return nil, false
	}
}

func getSignatureAlgorithm(algo types.SigningAlgorithmSpec) (x509.SignatureAlgorithm, error) {
	switch algo { //nolint:exhaustive // only supporting RSA and ECDSA
	case types.SigningAlgorithmSpecRsassaPkcs1V15Sha256:
		return x509.SHA256WithRSA, nil
	case types.SigningAlgorithmSpecRsassaPkcs1V15Sha384:
		return x509.SHA384WithRSA, nil
	case types.SigningAlgorithmSpecRsassaPkcs1V15Sha512:
		return x509.SHA512WithRSA, nil
	case types.SigningAlgorithmSpecEcdsaSha256:
		return x509.ECDSAWithSHA256, nil
	case types.SigningAlgorithmSpecEcdsaSha384:
		return x509.ECDSAWithSHA384, nil
	case types.SigningAlgorithmSpecEcdsaSha512:
		return x509.ECDSAWithSHA512, nil
	default:
		return x509.UnknownSignatureAlgorithm, fmt.Errorf("unsupported signing algorithm: %s", algo)
	}
}

func hashForSigningAlgorithm(algo types.SigningAlgorithmSpec) (crypto.Hash, error) {
	switch algo { //nolint:exhaustive // only supporting RSA and ECDSA
	case types.SigningAlgorithmSpecRsassaPkcs1V15Sha256, types.SigningAlgorithmSpecEcdsaSha256:
		return crypto.SHA256, nil
	case types.SigningAlgorithmSpecRsassaPkcs1V15Sha384, types.SigningAlgorithmSpecEcdsaSha384:
		return crypto.SHA384, nil
	case types.SigningAlgorithmSpecRsassaPkcs1V15Sha512, types.SigningAlgorithmSpecEcdsaSha512:
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported signing algorithm: %s", algo)
	}
}

func defaultSigningAlgorithm(
	publicKey crypto.PublicKey,
	supported []types.SigningAlgorithmSpec,
) (types.SigningAlgorithmSpec, error) {
	var candidates []types.SigningAlgorithmSpec
	const (
		p256BitSize = 256
		p384BitSize = 384
		p521BitSize = 521
	)
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		candidates = []types.SigningAlgorithmSpec{
			types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
			types.SigningAlgorithmSpecRsassaPkcs1V15Sha384,
			types.SigningAlgorithmSpecRsassaPkcs1V15Sha512,
		}
	case *ecdsa.PublicKey:
		switch key.Curve.Params().BitSize {
		case p256BitSize:
			candidates = []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEcdsaSha256}
		case p384BitSize:
			candidates = []types.SigningAlgorithmSpec{
				types.SigningAlgorithmSpecEcdsaSha384,
				types.SigningAlgorithmSpecEcdsaSha256,
				types.SigningAlgorithmSpecEcdsaSha512,
			}
		case p521BitSize:
			candidates = []types.SigningAlgorithmSpec{
				types.SigningAlgorithmSpecEcdsaSha512,
				types.SigningAlgorithmSpecEcdsaSha384,
				types.SigningAlgorithmSpecEcdsaSha256,
			}
		default:
			return "", fmt.Errorf("unsupported ECDSA curve size: %d", key.Curve.Params().BitSize)
		}
	default:
		return "", fmt.Errorf("unsupported public key type: %T", publicKey)
	}

	for _, candidate := range candidates {
		if containsSigningAlgorithm(supported, candidate) {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("KMS key does not advertise a supported signing algorithm for %T", publicKey)
}

func (b *Builder) resolveSigningAlgorithm() (
	types.SigningAlgorithmSpec,
	x509.SignatureAlgorithm,
	error,
) {
	algo := b.HashAlgo
	if algo == "" {
		return "", x509.UnknownSignatureAlgorithm, errors.New("signing algorithm cannot be empty")
	}
	if !containsSigningAlgorithm(b.supportedSigningAlgorithms, algo) {
		return "", x509.UnknownSignatureAlgorithm, fmt.Errorf("KMS key does not support signing algorithm %s", algo)
	}

	signatureAlgorithm, err := getSignatureAlgorithm(algo)
	if err != nil {
		return "", x509.UnknownSignatureAlgorithm, err
	}
	switch b.publicKey.(type) {
	case *rsa.PublicKey:
		if algo != types.SigningAlgorithmSpecRsassaPkcs1V15Sha256 &&
			algo != types.SigningAlgorithmSpecRsassaPkcs1V15Sha384 &&
			algo != types.SigningAlgorithmSpecRsassaPkcs1V15Sha512 {
			return "", x509.UnknownSignatureAlgorithm, fmt.Errorf("signing algorithm %s is incompatible with RSA", algo)
		}
	case *ecdsa.PublicKey:
		if algo != types.SigningAlgorithmSpecEcdsaSha256 &&
			algo != types.SigningAlgorithmSpecEcdsaSha384 &&
			algo != types.SigningAlgorithmSpecEcdsaSha512 {
			return "", x509.UnknownSignatureAlgorithm,
				fmt.Errorf("signing algorithm %s is incompatible with ECDSA", algo)
		}
	default:
		return "", x509.UnknownSignatureAlgorithm, fmt.Errorf("unsupported public key type: %T", b.publicKey)
	}

	return algo, signatureAlgorithm, nil
}

func containsSigningAlgorithm(algorithms []types.SigningAlgorithmSpec, target types.SigningAlgorithmSpec) bool {
	return slices.Contains(algorithms, target)
}
