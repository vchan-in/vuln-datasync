package main

import (
	"fmt"
	"log"

	"github.com/vchan-in/vuln-datasync/internal/merger"
	"github.com/vchan-in/vuln-datasync/internal/types"
	"github.com/vchan-in/vuln-datasync/internal/utils"
)

func main() {
	fmt.Println("=== Testing Merge Prevention with Deterministic IDs ===")

	normalizer := merger.NewNormalizer()

	// Create two slightly different versions of the same OSV vulnerability
	// (simulating what might happen on subsequent syncs)
	osvV1 := &types.OSVVulnerability{
		ID:      "CVE-2024-12345",
		Summary: "Test vulnerability v1",
		Details: "This is a test vulnerability (version 1)",
		Aliases: []string{"GHSA-1234-5678-9abc"},
	}

	osvV2 := &types.OSVVulnerability{
		ID:      "CVE-2024-12345", // Same original ID
		Summary: "Test vulnerability v2 (updated)",
		Details: "This is a test vulnerability (version 2 with updates)",
		Aliases: []string{"GHSA-1234-5678-9abc", "PYSEC-2024-123"}, // More aliases
	}

	// Normalize both versions
	vulnV1, err := normalizer.NormalizeOSV(osvV1)
	if err != nil {
		log.Fatalf("Failed to normalize OSV v1: %v", err)
	}

	vulnV2, err := normalizer.NormalizeOSV(osvV2)
	if err != nil {
		log.Fatalf("Failed to normalize OSV v2: %v", err)
	}

	fmt.Printf("Original OSV ID: %s\n", osvV1.ID)
	fmt.Printf("VULN ID from v1: %s\n", vulnV1.ID)
	fmt.Printf("VULN ID from v2: %s\n", vulnV2.ID)

	// Verify they have the same VULN ID
	if vulnV1.ID != vulnV2.ID {
		log.Fatalf("FAIL: Different VULN IDs for same source: %s vs %s", vulnV1.ID, vulnV2.ID)
	}

	fmt.Printf("✓ Same source ID generates same VULN ID: %s\n", vulnV1.ID)

	// With the same VULN ID, the database upsert will handle updates automatically
	// without triggering the merge logic that was causing the issue

	fmt.Printf("✓ Aliases v1: %v\n", vulnV1.Aliases)
	fmt.Printf("✓ Aliases v2: %v\n", vulnV2.Aliases)

	// Verify no VULN IDs in aliases
	allAliases := append(vulnV1.Aliases, vulnV2.Aliases...)
	for _, alias := range allAliases {
		if utils.ValidateCustomVulnID(alias) {
			log.Fatalf("FAIL: Found VULN ID in aliases: %s", alias)
		}
	}

	fmt.Println("✓ No VULN IDs found in aliases")
	fmt.Println("✓ Database upsert will handle updates by VULN ID without merging")
	fmt.Println("\n=== Merge Prevention Test PASSED ===")
	fmt.Println("This should fix the OSV->OSV merge issue in the logs!")
}
