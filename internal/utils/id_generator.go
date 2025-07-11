package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

// GenerateCustomVulnID generates a custom vulnerability ID in the format:
// VULN-<RANDOM 4 DIGIT>-<RANDOM 4 HEX>
// Example: VULN-1234-A1B2
func GenerateCustomVulnID() (string, error) {
	// Generate random 4-digit number (1000-9999)
	digitsPart, err := rand.Int(rand.Reader, big.NewInt(9000))
	if err != nil {
		return "", fmt.Errorf("failed to generate random digits: %w", err)
	}
	digits := digitsPart.Int64() + 1000 // Ensure 4 digits (1000-9999)

	// Generate random 4-character hex string
	hexBytes := make([]byte, 2) // 2 bytes = 4 hex characters
	_, err = rand.Read(hexBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random hex: %w", err)
	}
	hex := fmt.Sprintf("%02X%02X", hexBytes[0], hexBytes[1])

	return fmt.Sprintf("VULN-%04d-%s", digits, hex), nil
}

// ValidateCustomVulnID validates that an ID follows the custom format
func ValidateCustomVulnID(id string) bool {
	if len(id) != 14 { // VULN-1234-A1B2 = 14 characters
		return false
	}

	if id[:5] != "VULN-" {
		return false
	}

	if id[9] != '-' {
		return false
	}

	// Validate digits part (positions 5-8)
	for i := 5; i < 9; i++ {
		if id[i] < '0' || id[i] > '9' {
			return false
		}
	}

	// Validate hex part (positions 10-13)
	for i := 10; i < 14; i++ {
		c := id[i]
		if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}

	return true
}

// GenerateDeterministicVulnID generates a deterministic custom vulnerability ID based on source ID
// Format: VULN-<DETERMINISTIC 4 DIGIT>-<DETERMINISTIC 4 HEX>
// Example: VULN-1234-A1B2 (always the same for the same input)
func GenerateDeterministicVulnID(sourceID string) string {
	// Use SHA256 hash of the source ID to generate deterministic values
	hash := sha256.Sum256([]byte(sourceID))

	// Extract 4-digit number from first 2 bytes of hash (1000-9999)
	digits := (int(hash[0])<<8|int(hash[1]))%9000 + 1000

	// Extract 4-character hex from next 2 bytes of hash
	hex := fmt.Sprintf("%02X%02X", hash[2], hash[3])

	return fmt.Sprintf("VULN-%04d-%s", digits, hex)
}
