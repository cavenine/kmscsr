package main

import (
	"context"
	"log"
	"os"

	"github.com/cavenine/kmscsr"
)

func main() {
	// Define the KMS key ARN
	kmsArn := "arn:aws:kms:eu-west-1:xxxxxxxxxxxx:key/1234abcd-12ab-34cd-56ef-1234567890ab"

	// Create subject information
	subject := &kmscsr.SubjectInfo{
		CountryName:         "US",
		StateOrProvinceName: "Florida",
		LocalityName:        "Tampa Bay",
		OrganizationName:    "CaveNine",
		CommonName:          "cavenine.com",
	}

	// Create a new KMS CSR Builder
	builder, err := kmscsr.NewKMSCSRBuilder(subject, kmsArn)
	if err != nil {
		log.Fatalf("Failed to create KMS CSR Builder: %v", err)
	}

	// Add subject alternative names (domains)
	builder.SubjectAltDomains = []string{"api.cavenine.com", "www.cavenine.com"}

	// Build the CSR with KMS signing
	ctx := context.Background()
	csrDER, err := builder.BuildWithKMS(ctx)
	if err != nil {
		log.Fatalf("Failed to build CSR: %v", err)
	}

	// Encode to PEM format
	csrPEM := kmscsr.PEMEncode(csrDER)

	// Write to file
	err = os.WriteFile("example-kms.csr", csrPEM, 0600)
	if err != nil {
		log.Fatalf("Failed to write CSR to file: %v", err)
	}

	log.Println("CSR successfully created and saved to example-kms.csr")
}
