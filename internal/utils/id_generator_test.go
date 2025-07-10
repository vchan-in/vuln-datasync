package utils

import (
	"testing"
)

func TestGenerateCustomVulnID(t *testing.T) {
	// Test that we can generate IDs
	id, err := GenerateCustomVulnID()
	if err != nil {
		t.Fatalf("Failed to generate ID: %v", err)
	}

	// Test that the ID follows the correct format
	if !ValidateCustomVulnID(id) {
		t.Errorf("Generated ID %s does not follow the expected format", id)
	}

	// Test that the ID has the correct length
	if len(id) != 14 {
		t.Errorf("Expected ID length 14, got %d", len(id))
	}

	// Test that the ID starts with VULN-
	if id[:5] != "VULN-" {
		t.Errorf("Expected ID to start with 'VULN-', got %s", id[:5])
	}

	// Generate multiple IDs to ensure they're different
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		newID, err := GenerateCustomVulnID()
		if err != nil {
			t.Fatalf("Failed to generate ID #%d: %v", i, err)
		}
		if ids[newID] {
			t.Errorf("Generated duplicate ID: %s", newID)
		}
		ids[newID] = true
	}
}

func TestValidateCustomVulnID(t *testing.T) {
	validIDs := []string{
		"VULN-1234-ABCD",
		"VULN-9999-0000",
		"VULN-1000-FFFF",
		"VULN-5678-A1B2",
	}

	for _, id := range validIDs {
		if !ValidateCustomVulnID(id) {
			t.Errorf("Expected %s to be valid", id)
		}
	}

	invalidIDs := []string{
		"VULN-123-ABCD",   // Too few digits
		"VULN-12345-ABCD", // Too many digits
		"VULN-1234-ABCDE", // Too many hex chars
		"VULN-1234-ABC",   // Too few hex chars
		"VULN-1234-GHIJ",  // Invalid hex chars
		"VULN-123A-ABCD",  // Non-digit in digit part
		"vuln-1234-ABCD",  // Wrong case
		"VULN_1234_ABCD",  // Wrong separators
		"VULN-1234",       // Missing hex part
		"1234-ABCD",       // Missing prefix
		"",                // Empty string
		"VULN-1234-abcd",  // Lowercase hex (should be uppercase)
	}

	for _, id := range invalidIDs {
		if ValidateCustomVulnID(id) {
			t.Errorf("Expected %s to be invalid", id)
		}
	}
}
