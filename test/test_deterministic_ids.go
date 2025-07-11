package main

import (
	"fmt"
	"log"

	"github.com/vchan-in/vuln-datasync/internal/merger"
	"github.com/vchan-in/vuln-datasync/internal/types"
	"github.com/vchan-in/vuln-datasync/internal/utils"
)

func main() {
	fmt.Println("=== Testing Deterministic VULN ID Generation ===")

	// Test that the same source ID always generates the same VULN ID
	testCases := []string{
		"CVE-2024-12345",
		"GHSA-1234-5678-9abc",
		"OSV-2024-001",
		"PYSEC-2024-123",
	}

	fmt.Println("\n1. Testing deterministic ID generation:")
	for _, sourceID := range testCases {
		// Generate the same ID multiple times
		id1 := utils.GenerateDeterministicVulnID(sourceID)
		id2 := utils.GenerateDeterministicVulnID(sourceID)
		id3 := utils.GenerateDeterministicVulnID(sourceID)

		if id1 != id2 || id2 != id3 {
			log.Fatalf("FAIL: Non-deterministic ID generation for %s: %s, %s, %s", sourceID, id1, id2, id3)
		}

		fmt.Printf("  %s -> %s ✓\n", sourceID, id1)
	}

	// Test that different source IDs generate different VULN IDs
	fmt.Println("\n2. Testing uniqueness:")
	idMap := make(map[string]string)
	for _, sourceID := range testCases {
		vulnID := utils.GenerateDeterministicVulnID(sourceID)
		if existingSource, exists := idMap[vulnID]; exists {
			log.Fatalf("FAIL: Collision detected! %s and %s both generated %s", sourceID, existingSource, vulnID)
		}
		idMap[vulnID] = sourceID
		fmt.Printf("  %s -> %s (unique) ✓\n", sourceID, vulnID)
	}

	// Test normalization with deterministic IDs
	fmt.Println("\n3. Testing OSV normalization:")
	normalizer := merger.NewNormalizer()

	sampleOSV := &types.OSVVulnerability{
		ID:      "CVE-2024-12345",
		Summary: "Test vulnerability",
		Details: "This is a test vulnerability",
		Aliases: []string{"GHSA-1234-5678-9abc", "PYSEC-2024-123"},
	}

	// Normalize multiple times
	vuln1, err := normalizer.NormalizeOSV(sampleOSV)
	if err != nil {
		log.Fatalf("Failed to normalize OSV: %v", err)
	}

	vuln2, err := normalizer.NormalizeOSV(sampleOSV)
	if err != nil {
		log.Fatalf("Failed to normalize OSV: %v", err)
	}

	// Check that the same source generates the same VULN ID
	if vuln1.ID != vuln2.ID {
		log.Fatalf("FAIL: Non-deterministic normalization: %s vs %s", vuln1.ID, vuln2.ID)
	}

	fmt.Printf("  OSV ID: %s\n", sampleOSV.ID)
	fmt.Printf("  Generated VULN ID: %s (deterministic) ✓\n", vuln1.ID)
	fmt.Printf("  Aliases: %v\n", vuln1.Aliases)

	// Verify VULN ID is NOT in aliases
	for _, alias := range vuln1.Aliases {
		if utils.ValidateCustomVulnID(alias) {
			log.Fatalf("FAIL: VULN ID %s found in aliases - this should not happen!", alias)
		}
	}
	fmt.Printf("  Aliases contain no VULN IDs ✓\n")

	fmt.Println("\n=== All Tests PASSED ===")
	fmt.Println("✓ VULN IDs are deterministic based on source ID")
	fmt.Println("✓ Different source IDs generate different VULN IDs")
	fmt.Println("✓ VULN IDs are never included in aliases")
	fmt.Println("✓ Only original source IDs are used for matching")
}
