package main

import (
	"context"
	"log"
	"time"

	"github.com/vchan-in/vuln-datasync/internal/config"
	"github.com/vchan-in/vuln-datasync/internal/fetchers/osv"
	"github.com/vchan-in/vuln-datasync/internal/merger"
	"github.com/vchan-in/vuln-datasync/internal/types"
	"github.com/vchan-in/vuln-datasync/internal/utils"
)

func main() {
	log.Println("Testing OSV fetcher with custom IDs...")

	cfg := config.DataSourcesConfig{}
	fetcher, err := osv.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create OSV fetcher: %v", err)
	}
	defer fetcher.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	normalizer := merger.NewNormalizer()
	processedCount := 0
	customIDCount := 0

	// Define batch processor that normalizes and shows custom IDs
	batchProcessor := func(ctx context.Context, batch []*types.OSVVulnerability) error {
		log.Printf("Processing batch of %d vulnerabilities...", len(batch))

		for _, osvVuln := range batch {
			// Normalize the vulnerability to generate custom ID
			normalized, err := normalizer.NormalizeOSV(osvVuln)
			if err != nil {
				log.Printf("Failed to normalize vulnerability %s: %v", osvVuln.ID, err)
				continue
			}

			// Validate the custom ID
			if !utils.ValidateCustomVulnID(normalized.ID) {
				log.Printf("Invalid custom ID generated: %s", normalized.ID)
				continue
			}

			customIDCount++

			// Show first few examples
			if processedCount < 5 {
				log.Printf("  Example %d:", processedCount+1)
				log.Printf("    Original ID: %s", osvVuln.ID)
				log.Printf("    Custom ID:   %s", normalized.ID)
				log.Printf("    Aliases:     %v", normalized.Aliases)
			}

			processedCount++

			// Only process a small number for testing
			if processedCount >= 10 {
				return nil
			}
		}

		return nil
	}

	// Process only a small batch for testing
	batchSize := 50
	err = fetcher.FetchAllWithBatchProcessing(ctx, []string{}, batchSize, batchProcessor)
	if err != nil {
		log.Fatalf("Failed to fetch OSV vulnerabilities: %v", err)
	}

	log.Printf("\nTest completed!")
	log.Printf("Processed %d vulnerabilities", processedCount)
	log.Printf("Generated %d valid custom IDs", customIDCount)
}
