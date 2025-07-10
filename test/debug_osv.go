package main

import (
	"context"
	"log"
	"time"

	"github.com/vchan-in/vuln-datasync/internal/config"
	"github.com/vchan-in/vuln-datasync/internal/fetchers/osv"
	"github.com/vchan-in/vuln-datasync/internal/types"
)

func main() {
	cfg := config.DataSourcesConfig{}

	fetcher, err := osv.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create OSV fetcher: %v", err)
	}
	defer fetcher.Close()

	ctx := context.Background()

	// Add a longer timeout for testing
	ctxWithTimeout, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()

	// Test streaming batch processing instead of loading all into memory
	log.Println("Testing OSV batch processing with streaming...")

	totalProcessed := 0
	batchCount := 0

	// Define batch processor
	batchProcessor := func(ctx context.Context, batch []*types.OSVVulnerability) error {
		batchCount++
		totalProcessed += len(batch)

		log.Printf("Processed batch %d: %d vulnerabilities (total: %d)",
			batchCount, len(batch), totalProcessed)

		if len(batch) > 0 {
			log.Printf("Sample vulnerability from batch: Original ID=%s, Summary=%s",
				batch[0].ID, batch[0].Summary)
		}

		return nil
	}

	// Use batch size of 1000 for testing
	batchSize := 1000
	err = fetcher.FetchAllWithBatchProcessing(ctxWithTimeout, []string{}, batchSize, batchProcessor)
	if err != nil {
		log.Fatalf("Failed to fetch OSV vulnerabilities: %v", err)
	}

	log.Printf("Successfully processed %d vulnerabilities in %d batches", totalProcessed, batchCount)
}
