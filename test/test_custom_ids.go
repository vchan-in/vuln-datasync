package main

import (
	"log"

	"github.com/vchan-in/vuln-datasync/internal/merger"
	"github.com/vchan-in/vuln-datasync/internal/types"
	"github.com/vchan-in/vuln-datasync/internal/utils"
)

func main() {
	log.Println("Testing custom vulnerability ID generation...")

	// Test the ID generator directly
	log.Println("\n1. Testing ID generator:")
	for i := 0; i < 5; i++ {
		id, err := utils.GenerateCustomVulnID()
		if err != nil {
			log.Fatalf("Failed to generate ID: %v", err)
		}
		log.Printf("Generated ID %d: %s (valid: %t)", i+1, id, utils.ValidateCustomVulnID(id))
	}

	// Test the normalizer with OSV data
	log.Println("\n2. Testing normalizer with sample OSV vulnerability:")
	normalizer := merger.NewNormalizer()

	sampleOSV := &types.OSVVulnerability{
		ID:        "CVE-2024-12345",
		Summary:   "Sample vulnerability for testing",
		Details:   "This is a test vulnerability",
		Aliases:   []string{"GHSA-abcd-1234", "PYSEC-2024-123"},
		Published: "2024-01-01T00:00:00Z",
		Modified:  "2024-01-02T00:00:00Z",
	}

	normalized, err := normalizer.NormalizeOSV(sampleOSV)
	if err != nil {
		log.Fatalf("Failed to normalize OSV: %v", err)
	}

	log.Printf("Original OSV ID: %s", sampleOSV.ID)
	log.Printf("Generated Custom ID: %s", normalized.ID)
	log.Printf("Aliases (includes original): %v", normalized.Aliases)
	log.Printf("Source: %v", normalized.Source)
	log.Printf("Custom ID is valid: %t", utils.ValidateCustomVulnID(normalized.ID))

	log.Println("\nCustom ID generation test completed successfully!")
}
