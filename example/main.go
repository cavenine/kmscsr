package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/cavenine/kmscsr"
)

const kmsOperationTimeout = 30 * time.Second

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	// Define the KMS key ARN
	kmsArn := "arn:aws:kms:us-east-1:xxxxxxxxxxxx:key/1234abcd-12ab-34cd-56ef-1234567890ab"

	// Create subject information
	subject := &kmscsr.SubjectInfo{
		CountryName:         "US",
		StateOrProvinceName: "Florida",
		LocalityName:        "Tampa Bay",
		OrganizationName:    "CaveNine",
		CommonName:          "cavenine.com",
	}

	ctx, cancel := context.WithTimeout(context.Background(), kmsOperationTimeout)
	defer cancel()

	// Create a new KMS CSR Builder
	builder, err := kmscsr.NewKMSCSRBuilderWithContext(ctx, subject, kmsArn)
	if err != nil {
		return fmt.Errorf("failed to create KMS CSR Builder: %w", err)
	}

	// Add subject alternative names (domains)
	builder.SubjectAltDomains = []string{"api.cavenine.com", "www.cavenine.com"}

	// Build the CSR with KMS signing
	csrDER, err := builder.BuildWithKMS(ctx)
	if err != nil {
		return fmt.Errorf("failed to build CSR: %w", err)
	}

	// Encode to PEM format
	csrPEM := kmscsr.PEMEncode(csrDER)

	// Write to file
	err = os.WriteFile("example-kms.csr", csrPEM, 0600)
	if err != nil {
		return fmt.Errorf("failed to write CSR to file: %w", err)
	}

	log.Println("CSR successfully created and saved to example-kms.csr")

	return nil
}
