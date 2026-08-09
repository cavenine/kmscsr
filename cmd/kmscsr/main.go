package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/cavenine/kmscsr"
	"github.com/spf13/cobra"
)

const defaultTimeout = 30 * time.Second

// Build information. GoReleaser overwrites these at link time via -X; the
// defaults are what a plain "go build" or "go install" produces.
//
//nolint:gochecknoglobals // linker-injected build metadata must be package level
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// versionString renders the build metadata for the --version flag.
func versionString() string {
	return fmt.Sprintf("kmscsr %s (commit %s, built %s, %s)", version, commit, date, runtime.Version())
}

// builderFactory constructs the CSR builder for a run. Tests substitute one
// backed by a fake KMS client so the command can be exercised without AWS.
type builderFactory func(ctx context.Context, subject *kmscsr.SubjectInfo, kmsArn string) (*kmscsr.Builder, error)

type cliOptions struct {
	kmsArn        string
	commonName    string
	country       string
	state         string
	locality      string
	organization  string
	orgUnit       string
	emailAddress  string
	streetAddress string
	postalCode    string

	// SAN fields
	sanDomains []string
	sanIPs     []string

	// Certificate options
	isCA       bool
	outputFile string
	timeout    time.Duration

	newBuilder builderFactory
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	rootCmd, err := newRootCommand()
	if err != nil {
		return fmt.Errorf("failed to configure command: %w", err)
	}

	return rootCmd.ExecuteContext(ctx)
}

func newRootCommand() (*cobra.Command, error) {
	return newRootCommandWithOptions(&cliOptions{newBuilder: kmscsr.NewKMSCSRBuilderWithContext})
}

func newRootCommandWithOptions(options *cliOptions) (*cobra.Command, error) {
	rootCmd := &cobra.Command{
		Use:   "kmscsr",
		Short: "Generate X.509 certificate signing requests using AWS KMS keys",
		Long: `kmscsr is a CLI tool for creating and signing X.509 certificate signing
requests (CSRs) with AWS KMS keys. It supports RSA and ECDSA key types,
subject alternative names, and configurable key usage extensions.`,
		RunE: options.generateCSR,
		// main reports errors so that a failed run prints one line rather than
		// cobra's message followed by the full usage text.
		SilenceErrors: true,
		Version:       versionString(),
	}
	rootCmd.SetVersionTemplate("{{.Version}}\n")

	// Required flags
	rootCmd.Flags().StringVar(&options.kmsArn, "kms-arn", "", "AWS KMS key ARN (required)")
	rootCmd.Flags().StringVar(&options.commonName, "common-name", "", "Common Name (CN) for the certificate (required)")

	// Subject optional flags
	rootCmd.Flags().StringVar(&options.country, "country", "", "Country Name (C)")
	rootCmd.Flags().StringVar(&options.state, "state", "", "State or Province Name (ST)")
	rootCmd.Flags().StringVar(&options.locality, "locality", "", "Locality Name (L)")
	rootCmd.Flags().StringVar(&options.organization, "organization", "", "Organization Name (O)")
	rootCmd.Flags().StringVar(&options.orgUnit, "org-unit", "", "Organizational Unit Name (OU)")
	rootCmd.Flags().StringVar(&options.emailAddress, "email", "", "Email Address")
	rootCmd.Flags().StringVar(&options.streetAddress, "street", "", "Street Address")
	rootCmd.Flags().StringVar(&options.postalCode, "postal-code", "", "Postal Code")

	// SAN flags
	rootCmd.Flags().StringSliceVar(
		&options.sanDomains,
		"san-dns",
		nil,
		"Subject Alternative Name DNS entries (can be specified multiple times)",
	)
	rootCmd.Flags().StringSliceVar(
		&options.sanIPs,
		"san-ip",
		nil,
		"Subject Alternative Name IP addresses (can be specified multiple times)",
	)

	// Certificate options
	rootCmd.Flags().BoolVar(&options.isCA, "ca", false, "Generate a CA certificate request")
	rootCmd.Flags().StringVarP(&options.outputFile, "output", "o", "", "Output file path (default: stdout)")
	rootCmd.Flags().DurationVar(
		&options.timeout,
		"timeout",
		defaultTimeout,
		"Maximum time for AWS KMS operations (0 disables the timeout)",
	)

	// Mark required flags
	if err := rootCmd.MarkFlagRequired("kms-arn"); err != nil {
		return nil, fmt.Errorf("failed to mark kms-arn as required: %w", err)
	}
	if err := rootCmd.MarkFlagRequired("common-name"); err != nil {
		return nil, fmt.Errorf("failed to mark common-name as required: %w", err)
	}

	return rootCmd, nil
}

func (o *cliOptions) generateCSR(cmd *cobra.Command, _ []string) error {
	// Past flag parsing, a failure is an operational one; repeating the usage
	// text buries the actual error.
	cmd.SilenceUsage = true

	// MarkFlagRequired only checks that a flag was supplied, so an explicitly
	// empty value still reaches here.
	if strings.TrimSpace(o.kmsArn) == "" {
		return errors.New("--kms-arn cannot be empty")
	}
	if strings.TrimSpace(o.commonName) == "" {
		return errors.New("--common-name cannot be empty")
	}

	ipAddresses, err := parseIPAddresses(o.sanIPs)
	if err != nil {
		return err
	}

	// Create subject information
	subject := &kmscsr.SubjectInfo{
		CommonName:             o.commonName,
		CountryName:            o.country,
		StateOrProvinceName:    o.state,
		LocalityName:           o.locality,
		OrganizationName:       o.organization,
		OrganizationalUnitName: o.orgUnit,
		EmailAddress:           o.emailAddress,
		StreetAddress:          o.streetAddress,
		PostalCode:             o.postalCode,
	}

	ctx := cmd.Context()
	if o.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, o.timeout)
		defer cancel()
	}

	// Create KMS CSR Builder
	builder, err := o.newBuilder(ctx, subject, o.kmsArn)
	if err != nil {
		return fmt.Errorf("failed to create KMS CSR builder: %w", err)
	}

	// Set CA option if specified
	if o.isCA {
		builder.SetCA(true)
	}

	// Add SAN domains
	if len(o.sanDomains) > 0 {
		builder.SubjectAltDomains = o.sanDomains
	}

	if len(ipAddresses) > 0 {
		builder.SubjectAltIPs = ipAddresses
	}

	// Build the CSR with KMS signing
	csrDER, err := builder.BuildWithKMS(ctx)
	if err != nil {
		return fmt.Errorf("failed to build CSR: %w", err)
	}

	// Encode to PEM format
	csrPEM := kmscsr.PEMEncode(csrDER)

	// Write output
	if o.outputFile != "" {
		if writeErr := os.WriteFile(o.outputFile, csrPEM, 0600); writeErr != nil {
			return fmt.Errorf("failed to write CSR to file: %w", writeErr)
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "CSR successfully created and saved to %s\n", o.outputFile)
	} else {
		if _, writeErr := cmd.OutOrStdout().Write(csrPEM); writeErr != nil {
			return fmt.Errorf("failed to write CSR to stdout: %w", writeErr)
		}
	}

	return nil
}

func parseIPAddresses(values []string) ([]net.IP, error) {
	ipAddresses := make([]net.IP, 0, len(values))
	for _, value := range values {
		ip := net.ParseIP(strings.TrimSpace(value))
		if ip == nil {
			return nil, fmt.Errorf("invalid IP address: %s", value)
		}
		ipAddresses = append(ipAddresses, ip)
	}

	return ipAddresses, nil
}
