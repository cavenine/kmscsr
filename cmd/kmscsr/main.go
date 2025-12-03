package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/cavenine/kmscsr"
	"github.com/spf13/cobra"
)

var (
	// Subject fields
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
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "kmscsr",
		Short: "Generate X.509 certificate signing requests using AWS KMS keys",
		Long: `kmscsr is a CLI tool for creating and signing X.509 certificate signing 
requests (CSRs) with AWS KMS keys. It supports RSA and ECDSA key types,
subject alternative names, and configurable key usage extensions.`,
		RunE: generateCSR,
	}

	// Required flags
	rootCmd.Flags().StringVar(&kmsArn, "kms-arn", "", "AWS KMS key ARN (required)")
	rootCmd.Flags().StringVar(&commonName, "common-name", "", "Common Name (CN) for the certificate (required)")

	// Subject optional flags
	rootCmd.Flags().StringVar(&country, "country", "", "Country Name (C)")
	rootCmd.Flags().StringVar(&state, "state", "", "State or Province Name (ST)")
	rootCmd.Flags().StringVar(&locality, "locality", "", "Locality Name (L)")
	rootCmd.Flags().StringVar(&organization, "organization", "", "Organization Name (O)")
	rootCmd.Flags().StringVar(&orgUnit, "org-unit", "", "Organizational Unit Name (OU)")
	rootCmd.Flags().StringVar(&emailAddress, "email", "", "Email Address")
	rootCmd.Flags().StringVar(&streetAddress, "street", "", "Street Address")
	rootCmd.Flags().StringVar(&postalCode, "postal-code", "", "Postal Code")

	// SAN flags
	rootCmd.Flags().StringSliceVar(&sanDomains, "san-dns", []string{}, "Subject Alternative Name DNS entries (can be specified multiple times)")
	rootCmd.Flags().StringSliceVar(&sanIPs, "san-ip", []string{}, "Subject Alternative Name IP addresses (can be specified multiple times)")

	// Certificate options
	rootCmd.Flags().BoolVar(&isCA, "ca", false, "Generate a CA certificate request")
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file path (default: stdout)")

	// Mark required flags
	if err := rootCmd.MarkFlagRequired("kms-arn"); err != nil {
		fmt.Fprintf(os.Stderr, "Error marking flag as required: %v\n", err)
		os.Exit(1)
	}
	if err := rootCmd.MarkFlagRequired("common-name"); err != nil {
		fmt.Fprintf(os.Stderr, "Error marking flag as required: %v\n", err)
		os.Exit(1)
	}

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func generateCSR(cmd *cobra.Command, args []string) error {
	// Create subject information
	subject := &kmscsr.SubjectInfo{
		CommonName:             commonName,
		CountryName:            country,
		StateOrProvinceName:    state,
		LocalityName:           locality,
		OrganizationName:       organization,
		OrganizationalUnitName: orgUnit,
		EmailAddress:           emailAddress,
		StreetAddress:          streetAddress,
		PostalCode:             postalCode,
	}

	// Create KMS CSR Builder
	builder, err := kmscsr.NewKMSCSRBuilder(subject, kmsArn)
	if err != nil {
		return fmt.Errorf("failed to create KMS CSR builder: %w", err)
	}

	// Set CA option if specified
	if isCA {
		builder.SetCA(true)
	}

	// Add SAN domains
	if len(sanDomains) > 0 {
		builder.SubjectAltDomains = sanDomains
	}

	// Parse and add SAN IP addresses
	if len(sanIPs) > 0 {
		var ipAddresses []net.IP
		for _, ipStr := range sanIPs {
			ip := net.ParseIP(strings.TrimSpace(ipStr))
			if ip == nil {
				return fmt.Errorf("invalid IP address: %s", ipStr)
			}
			ipAddresses = append(ipAddresses, ip)
		}
		builder.SubjectAltIPs = ipAddresses
	}

	// Build the CSR with KMS signing
	ctx := context.Background()
	csrDER, err := builder.BuildWithKMS(ctx)
	if err != nil {
		return fmt.Errorf("failed to build CSR: %w", err)
	}

	// Encode to PEM format
	csrPEM := kmscsr.PEMEncode(csrDER)

	// Write output
	if outputFile != "" {
		if err := os.WriteFile(outputFile, csrPEM, 0600); err != nil {
			return fmt.Errorf("failed to write CSR to file: %w", err)
		}
		fmt.Fprintf(os.Stderr, "CSR successfully created and saved to %s\n", outputFile)
	} else {
		fmt.Print(string(csrPEM))
	}

	return nil
}
