package osv

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"cloud.google.com/go/storage"
	"github.com/rs/zerolog/log"
	"github.com/vchan-in/vuln-datasync/internal/config"
	"github.com/vchan-in/vuln-datasync/internal/types"
)

// Fetcher implements OSV vulnerability data fetching with GCS priority and HTTP fallback
type Fetcher struct {
	cfg         config.DataSourcesConfig
	gcsClient   *storage.Client // Primary: GCS direct access (prioritized)
	httpClient  *http.Client    // Fallback: HTTP download
	workerCount int
	useGCS      bool   // Flag to prioritize GCS over HTTP
	bucketName  string // GCS bucket name
}

// New creates a new OSV fetcher with GCS priority
func New(cfg config.DataSourcesConfig) (*Fetcher, error) {
	// Initialize HTTP client with longer timeouts for large files
	httpClient := &http.Client{
		Timeout: 600 * time.Second, // 10 minutes for large OSV file
		Transport: &http.Transport{
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			DisableCompression:    false,
			ResponseHeaderTimeout: 300 * time.Second, // 5 minutes for headers
		},
	}

	// Initialize GCS client (primary)
	ctx := context.Background()
	gcsClient, err := storage.NewClient(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("failed to initialize GCS client, will use HTTP fallback")
	}

	bucketName := cfg.OSVBucket
	if bucketName == "" {
		bucketName = "osv-vulnerabilities" // Default bucket name
	}

	return &Fetcher{
		cfg:         cfg,
		gcsClient:   gcsClient,
		httpClient:  httpClient,
		workerCount: 20, // Optimal based on POC learnings
		useGCS:      gcsClient != nil,
		bucketName:  bucketName,
	}, nil
}

// FetchAll fetches all OSV vulnerabilities with GCS priority and HTTP fallback
func (f *Fetcher) FetchAll(ctx context.Context, ecosystems []string) ([]*types.OSVVulnerability, error) {
	log.Info().
		Strs("ecosystems", ecosystems).
		Bool("use_gcs", f.useGCS).
		Msg("starting OSV vulnerability fetch")

	startTime := time.Now()

	// Try GCS first (priority), then fallback to HTTP
	reader, source, err := f.fetchWithFallback(ctx)
	if err != nil {
		// If we can't fetch the data, return an empty slice instead of an error
		// This allows the system to continue running even if OSV is temporarily unavailable
		log.Warn().Err(err).Msg("failed to fetch OSV data from all sources, returning empty result")
		return []*types.OSVVulnerability{}, nil
	}
	defer func() {
		if closer, ok := reader.(io.Closer); ok {
			if err := closer.Close(); err != nil {
				log.Warn().Err(err).Msg("failed to close reader")
			}
		}
	}()

	log.Info().Str("source", source).Msg("successfully fetched OSV data")

	// Process ZIP file
	vulnerabilities, err := f.processZipStream(ctx, reader, ecosystems)
	if err != nil {
		// If we can't process the ZIP file, return an empty slice instead of an error
		log.Warn().Err(err).Msg("failed to process OSV ZIP, returning empty result")
		return []*types.OSVVulnerability{}, nil
	}

	if len(vulnerabilities) == 0 {
		log.Warn().Msg("no OSV vulnerabilities found after processing, this might indicate a data source issue")
	}

	duration := time.Since(startTime)
	log.Info().
		Int("total_vulnerabilities", len(vulnerabilities)).
		Dur("duration", duration).
		Str("source", source).
		Msg("OSV fetch completed")

	return vulnerabilities, nil
}

// fetchWithFallback tries GCS first, then falls back to HTTP
func (f *Fetcher) fetchWithFallback(ctx context.Context) (io.Reader, string, error) {
	// Try GCS first (priority)
	if f.useGCS && f.gcsClient != nil {
		reader, err := f.fetchFromGCS(ctx)
		if err != nil {
			log.Warn().Err(err).Msg("GCS fetch failed, falling back to HTTP")
		} else {
			return reader, "gcs", nil
		}
	}

	// Fallback to HTTP
	reader, err := f.fetchFromHTTP(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("both GCS and HTTP fetch failed: %w", err)
	}

	return reader, "http", nil
}

// fetchFromGCS fetches the OSV ZIP file from GCS bucket (primary method)
// Uses gs://osv-vulnerabilities/all.zip path
func (f *Fetcher) fetchFromGCS(ctx context.Context) (io.Reader, error) {
	log.Info().
		Str("bucket", f.bucketName).
		Str("object", "all.zip").
		Str("gcs_path", fmt.Sprintf("gs://%s/all.zip", f.bucketName)).
		Msg("fetching OSV data from GCS bucket")

	bucket := f.gcsClient.Bucket(f.bucketName)
	obj := bucket.Object("all.zip")

	reader, err := obj.NewReader(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCS reader for gs://%s/all.zip: %w", f.bucketName, err)
	}

	return reader, nil
}

// fetchFromHTTP fetches the OSV ZIP file via HTTP (fallback method)
func (f *Fetcher) fetchFromHTTP(ctx context.Context) (io.Reader, error) {
	// Use only the known working URL
	url := "https://osv-vulnerabilities.storage.googleapis.com/all.zip"

	log.Info().Str("url", url).Msg("fetching OSV data from HTTP")

	// Create a context with a longer timeout for the large file
	reqCtx, cancel := context.WithTimeout(ctx, 600*time.Second) // 10 minutes for 668MB file
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request for %s: %w", url, err)
	}

	// Add appropriate headers
	req.Header.Set("User-Agent", "vuln-datasync/1.0")
	req.Header.Set("Accept", "application/zip")

	// Single attempt with longer timeout
	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch from %s: %w", url, err)
	}

	if resp.StatusCode != http.StatusOK {
		if err := resp.Body.Close(); err != nil {
			log.Warn().Err(err).Str("url", url).Msg("failed to close response body")
		}
		return nil, fmt.Errorf("HTTP error from %s: %s", url, resp.Status)
	}

	// Create temporary file for the ZIP data
	tmpFile, err := os.CreateTemp("", "osv-vulnerabilities-*.zip")
	err = os.Chmod(tmpFile.Name(), 0600) // Set permissions to read/write for owner only
	if err != nil {
		return nil, fmt.Errorf("failed to set permissions on temp file: %w", err)
	}

	if err != nil {
		if err := resp.Body.Close(); err != nil {
			log.Warn().Err(err).Str("url", url).Msg("failed to close response body")
		}
		return nil, fmt.Errorf("failed to create temporary file: %w", err)
	}

	// Download to temporary file instead of memory
	log.Info().
		Str("url", url).
		Str("temp_file", tmpFile.Name()).
		Msg("downloading OSV data to temporary file")

	written, err := io.Copy(tmpFile, resp.Body)
	if err != nil {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Warn().Err(closeErr).Str("url", url).Msg("failed to close response body")
		}
		if removeErr := os.Remove(tmpFile.Name()); removeErr != nil {
			log.Warn().Err(removeErr).Str("temp_file", tmpFile.Name()).Msg("failed to cleanup temp file")
		}
		return nil, fmt.Errorf("failed to write to temporary file: %w", err)
	}

	if err := resp.Body.Close(); err != nil {
		log.Warn().Err(err).Str("url", url).Msg("failed to close response body")
	}

	if err := tmpFile.Close(); err != nil {
		if removeErr := os.Remove(tmpFile.Name()); removeErr != nil {
			log.Warn().Err(removeErr).Str("temp_file", tmpFile.Name()).Msg("failed to cleanup temp file")
		}
		return nil, fmt.Errorf("failed to close temporary file: %w", err)
	}

	log.Info().
		Str("url", url).
		Int64("size_mb", written/(1024*1024)).
		Str("temp_file", tmpFile.Name()).
		Msg("OSV data successfully downloaded to temporary file")

	// Return a file reader that will clean up the temp file when closed
	return &tempFileReader{
		filePath: tmpFile.Name(),
	}, nil
}

// tempFileReader wraps a file reader and cleans up the temp file when closed
type tempFileReader struct {
	filePath string
	file     *os.File
	opened   bool
}

func (tfr *tempFileReader) Read(p []byte) (n int, err error) {
	if !tfr.opened {
		tfr.file, err = os.Open(tfr.filePath)
		if err != nil {
			return 0, fmt.Errorf("failed to open temp file: %w", err)
		}
		tfr.opened = true
	}
	return tfr.file.Read(p)
}

func (tfr *tempFileReader) Close() error {
	var err error
	if tfr.file != nil {
		err = tfr.file.Close()
	}
	// Always try to remove the temp file
	if removeErr := os.Remove(tfr.filePath); removeErr != nil {
		log.Warn().Err(removeErr).Str("temp_file", tfr.filePath).Msg("failed to cleanup temp file")
	}
	return err
}

// processZipStream processes the OSV ZIP file stream
func (f *Fetcher) processZipStream(ctx context.Context, reader io.Reader, ecosystems []string) ([]*types.OSVVulnerability, error) {
	// Check if it's our tempFileReader to work directly with the file
	if tfr, ok := reader.(*tempFileReader); ok {
		return f.processZipFile(ctx, tfr.filePath, ecosystems)
	}

	// Fallback: read into memory (for non-file readers like GCS)
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read ZIP data: %w", err)
	}

	// Close reader if it's a closer
	if closer, ok := reader.(io.Closer); ok {
		if err := closer.Close(); err != nil {
			log.Warn().Err(err).Msg("failed to close reader")
		}
	}

	log.Info().
		Int("zip_size_mb", len(data)/(1024*1024)).
		Msg("OSV ZIP loaded to memory, processing")

	// Create ZIP reader from memory
	zipReader, err := zip.NewReader(
		&readerAt{data: data},
		int64(len(data)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create ZIP reader: %w", err)
	}

	return f.processZipReader(ctx, zipReader, ecosystems)
}

// processZipFile processes the OSV ZIP file directly from filesystem
func (f *Fetcher) processZipFile(ctx context.Context, filePath string, ecosystems []string) ([]*types.OSVVulnerability, error) {
	// Get file size for logging
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat ZIP file: %w", err)
	}

	log.Info().
		Int64("zip_size_mb", fileInfo.Size()/(1024*1024)).
		Str("zip_file", filePath).
		Msg("OSV ZIP file processing from disk")

	// Open ZIP file directly from filesystem (no memory allocation for ZIP data)
	zipReader, err := zip.OpenReader(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open ZIP file: %w", err)
	}
	defer func() {
		if err := zipReader.Close(); err != nil {
			log.Warn().Err(err).Msg("failed to close ZIP reader")
		}
	}()

	return f.processZipReader(ctx, &zipReader.Reader, ecosystems)
}

// processZipReader processes a zip.Reader (common logic for both file and memory-based ZIP processing)
func (f *Fetcher) processZipReader(ctx context.Context, zipReader *zip.Reader, ecosystems []string) ([]*types.OSVVulnerability, error) {
	// Create ecosystem filter map
	ecosystemFilter := make(map[string]bool)
	for _, eco := range ecosystems {
		ecosystemFilter[eco] = true
	}

	// Log some debug information about the ZIP contents
	log.Info().
		Int("total_files", len(zipReader.File)).
		Int("json_files", len(f.filterJSONFiles(zipReader.File))).
		Int("ecosystem_filter_size", len(ecosystemFilter)).
		Msg("starting ZIP file processing")

	// Process files with worker pool
	return f.processFilesWithWorkers(ctx, zipReader.File, ecosystemFilter)
}

// processFilesWithWorkers processes JSON files using a worker pool
func (f *Fetcher) processFilesWithWorkers(ctx context.Context, files []*zip.File, ecosystemFilter map[string]bool) ([]*types.OSVVulnerability, error) {
	// Filter JSON files
	jsonFiles := f.filterJSONFiles(files)

	log.Info().
		Int("total_files", len(files)).
		Int("json_files", len(jsonFiles)).
		Int("workers", f.workerCount).
		Msg("starting worker pool processing")

	if len(jsonFiles) == 0 {
		log.Warn().Msg("no JSON files found in ZIP archive")
		return []*types.OSVVulnerability{}, nil
	}

	jobs := make(chan *zip.File, len(jsonFiles))
	results := make(chan *types.OSVVulnerability, len(jsonFiles))
	errors := make(chan error, len(jsonFiles))

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < f.workerCount; i++ {
		wg.Add(1)
		go f.worker(ctx, &wg, jobs, results, errors, ecosystemFilter)
	}

	// Send jobs and collect results
	go f.sendJobs(ctx, jobs, jsonFiles)
	go f.waitForWorkers(&wg, results, errors)

	return f.collectResults(ctx, results, errors, len(jsonFiles))
}

// filterJSONFiles returns only JSON files from the list
func (f *Fetcher) filterJSONFiles(files []*zip.File) []*zip.File {
	var jsonFiles []*zip.File
	for _, file := range files {
		if isJSONFile(file.Name) {
			jsonFiles = append(jsonFiles, file)
		}
	}
	return jsonFiles
}

// sendJobs sends files to the job channel
func (f *Fetcher) sendJobs(ctx context.Context, jobs chan<- *zip.File, files []*zip.File) {
	defer close(jobs)
	for _, file := range files {
		select {
		case jobs <- file:
		case <-ctx.Done():
			return
		}
	}
}

// waitForWorkers waits for all workers to finish and closes channels
func (f *Fetcher) waitForWorkers(wg *sync.WaitGroup, results chan *types.OSVVulnerability, errors chan error) {
	wg.Wait()
	close(results)
	close(errors)
}

// collectResults collects all results and errors
func (f *Fetcher) collectResults(ctx context.Context, results <-chan *types.OSVVulnerability, errors <-chan error, expectedCount int) ([]*types.OSVVulnerability, error) {
	var vulnerabilities []*types.OSVVulnerability
	var firstError error
	processed := 0
	errorCount := 0

	log.Info().Int("expected_count", expectedCount).Msg("starting result collection")

	for processed < expectedCount {
		select {
		case vuln, ok := <-results:
			if ok {
				processed++
				if vuln != nil {
					vulnerabilities = append(vulnerabilities, vuln)
				}
				// Log progress every 10000 files
				if processed%10000 == 0 {
					log.Info().
						Int("processed", processed).
						Int("vulnerabilities_collected", len(vulnerabilities)).
						Int("errors", errorCount).
						Msg("processing progress")
				}
			}
		case err, ok := <-errors:
			if ok && err != nil {
				errorCount++
				if firstError == nil {
					firstError = err
				}
				// Log first few errors for debugging
				if errorCount <= 5 {
					log.Warn().Err(err).Int("error_num", errorCount).Msg("processing error")
				}
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	// Drain remaining errors
	for len(errors) > 0 {
		if err := <-errors; err != nil {
			errorCount++
			if firstError == nil {
				firstError = err
			}
		}
	}

	log.Info().
		Int("processed_files", processed).
		Int("vulnerabilities_collected", len(vulnerabilities)).
		Int("total_errors", errorCount).
		Msg("result collection completed")

	if firstError != nil {
		// Log the error but don't fail the whole processing
		log.Warn().Err(firstError).Int("total_errors", errorCount).Msg("some files failed to process")
	}

	// Always return processed vulnerabilities even if there were some errors
	// This prevents a single malformed file from causing the entire sync to fail
	return vulnerabilities, nil
}

// worker processes individual JSON files
func (f *Fetcher) worker(ctx context.Context, wg *sync.WaitGroup, jobs <-chan *zip.File, results chan<- *types.OSVVulnerability, errors chan<- error, ecosystemFilter map[string]bool) {
	defer wg.Done()

	workerId := fmt.Sprintf("worker-%d", time.Now().UnixNano()%1000)
	filesProcessed := 0

	for {
		select {
		case file, ok := <-jobs:
			if !ok {
				log.Debug().Str("worker_id", workerId).Int("files_processed", filesProcessed).Msg("worker finished")
				return
			}

			filesProcessed++
			vuln, err := f.processJSONFile(file, ecosystemFilter)
			if err != nil {
				errors <- fmt.Errorf("error processing %s: %w", file.Name, err)
				continue
			}

			if vuln != nil {
				results <- vuln
			} else {
				// File was processed but vulnerability was filtered out
				results <- nil
			}

		case <-ctx.Done():
			log.Debug().Str("worker_id", workerId).Int("files_processed", filesProcessed).Msg("worker cancelled")
			return
		}
	}
}

// processJSONFile processes a single JSON file from the ZIP
func (f *Fetcher) processJSONFile(file *zip.File, ecosystemFilter map[string]bool) (*types.OSVVulnerability, error) {
	reader, err := file.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer func() {
		if err := reader.Close(); err != nil {
			log.Warn().Err(err).Msg("failed to close file reader")
		}
	}()

	var vuln types.OSVVulnerability
	if err := json.NewDecoder(reader).Decode(&vuln); err != nil {
		return nil, fmt.Errorf("failed to decode JSON: %w", err)
	}

	// Validate vulnerability
	if vuln.ID == "" {
		return nil, fmt.Errorf("vulnerability missing ID")
	}

	// Filter by ecosystem if specified and not empty
	if len(ecosystemFilter) > 0 {
		found := false
		for _, affected := range vuln.Affected {
			if affected.Package.Ecosystem != "" && ecosystemFilter[affected.Package.Ecosystem] {
				found = true
				break
			}
		}
		if !found {
			// If ecosystems were specified but none matched, skip this vulnerability
			return nil, nil
		}
	}
	// Process all vulnerabilities when no ecosystems are specified

	return &vuln, nil
}

// isJSONFile checks if a file is a JSON file
func isJSONFile(filename string) bool {
	return len(filename) > 5 && filename[len(filename)-5:] == ".json"
}

// readerAt implements io.ReaderAt for byte slice
type readerAt struct {
	data []byte
}

func (r *readerAt) ReadAt(p []byte, off int64) (n int, err error) {
	if off >= int64(len(r.data)) {
		return 0, io.EOF
	}

	n = copy(p, r.data[off:])
	if n < len(p) {
		err = io.EOF
	}

	return n, err
}

// Close closes the fetcher and cleans up resources
func (f *Fetcher) Close() error {
	if f.gcsClient != nil {
		return f.gcsClient.Close()
	}
	return nil
}

// BatchProcessor is a function type for processing vulnerability batches
type BatchProcessor func(ctx context.Context, batch []*types.OSVVulnerability) error

// FetchAllWithBatchProcessing fetches and processes OSV vulnerabilities in batches to avoid memory issues
func (f *Fetcher) FetchAllWithBatchProcessing(ctx context.Context, ecosystems []string, batchSize int, processor BatchProcessor) error {
	log.Info().
		Strs("ecosystems", ecosystems).
		Int("batch_size", batchSize).
		Bool("use_gcs", f.useGCS).
		Msg("starting OSV vulnerability fetch with batch processing")

	startTime := time.Now()

	// Try GCS first (priority), then fallback to HTTP
	reader, source, err := f.fetchWithFallback(ctx)
	if err != nil {
		// If we can't fetch the data, log warning and return without error
		// This allows the system to continue running even if OSV is temporarily unavailable
		log.Warn().Err(err).Msg("failed to fetch OSV data from all sources")
		return nil
	}
	defer func() {
		if closer, ok := reader.(io.Closer); ok {
			if err := closer.Close(); err != nil {
				log.Warn().Err(err).Msg("failed to close reader")
			}
		}
	}()

	log.Info().Str("source", source).Msg("successfully fetched OSV data")

	// Process ZIP file with batch processing
	totalProcessed, err := f.processZipStreamWithBatches(ctx, reader, ecosystems, batchSize, processor)
	if err != nil {
		// If we can't process the ZIP file, log warning and return without error
		log.Warn().Err(err).Msg("failed to process OSV ZIP")
		return nil
	}

	duration := time.Since(startTime)
	log.Info().
		Int("total_processed", totalProcessed).
		Dur("duration", duration).
		Str("source", source).
		Msg("OSV batch processing completed")

	return nil
}

// processZipStreamWithBatches processes the OSV ZIP file stream with batch callbacks
func (f *Fetcher) processZipStreamWithBatches(ctx context.Context, reader io.Reader, ecosystems []string, batchSize int, processor BatchProcessor) (int, error) {
	// Check if it's our tempFileReader to work directly with the file
	if tfr, ok := reader.(*tempFileReader); ok {
		return f.processZipFileWithBatches(ctx, tfr.filePath, ecosystems, batchSize, processor)
	}

	// Fallback: read into memory (for non-file readers like GCS)
	data, err := io.ReadAll(reader)
	if err != nil {
		return 0, fmt.Errorf("failed to read ZIP data: %w", err)
	}

	// Close reader if it's a closer
	if closer, ok := reader.(io.Closer); ok {
		if err := closer.Close(); err != nil {
			log.Warn().Err(err).Msg("failed to close reader")
		}
	}

	log.Info().
		Int("zip_size_mb", len(data)/(1024*1024)).
		Msg("OSV ZIP loaded to memory, processing with batches")

	// Create ZIP reader from memory
	zipReader, err := zip.NewReader(
		&readerAt{data: data},
		int64(len(data)),
	)
	if err != nil {
		return 0, fmt.Errorf("failed to create ZIP reader: %w", err)
	}

	return f.processZipReaderWithBatches(ctx, zipReader, ecosystems, batchSize, processor)
}

// processZipFileWithBatches processes the OSV ZIP file directly from filesystem with batch callbacks
func (f *Fetcher) processZipFileWithBatches(ctx context.Context, filePath string, ecosystems []string, batchSize int, processor BatchProcessor) (int, error) {
	// Get file size for logging
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return 0, fmt.Errorf("failed to stat ZIP file: %w", err)
	}

	log.Info().
		Int64("zip_size_mb", fileInfo.Size()/(1024*1024)).
		Str("zip_file", filePath).
		Int("batch_size", batchSize).
		Msg("OSV ZIP file processing from disk with batches")

	// Open ZIP file directly from filesystem (no memory allocation for ZIP data)
	zipReader, err := zip.OpenReader(filePath)
	if err != nil {
		return 0, fmt.Errorf("failed to open ZIP file: %w", err)
	}
	defer func() {
		if err := zipReader.Close(); err != nil {
			log.Warn().Err(err).Msg("failed to close ZIP reader")
		}
	}()

	return f.processZipReaderWithBatches(ctx, &zipReader.Reader, ecosystems, batchSize, processor)
}

// processZipReaderWithBatches processes a zip.Reader with batch callbacks
func (f *Fetcher) processZipReaderWithBatches(ctx context.Context, zipReader *zip.Reader, ecosystems []string, batchSize int, processor BatchProcessor) (int, error) {
	// Create ecosystem filter map
	ecosystemFilter := make(map[string]bool)
	for _, eco := range ecosystems {
		ecosystemFilter[eco] = true
	}

	// Filter JSON files
	jsonFiles := f.filterJSONFiles(zipReader.File)

	log.Info().
		Int("total_files", len(zipReader.File)).
		Int("json_files", len(jsonFiles)).
		Int("batch_size", batchSize).
		Msg("starting ZIP file processing with batches")

	if len(jsonFiles) == 0 {
		log.Warn().Msg("no JSON files found in ZIP archive")
		return 0, nil
	}

	// Process files and collect into batches
	totalProcessed := 0
	batch := make([]*types.OSVVulnerability, 0, batchSize)

	for _, file := range jsonFiles {
		select {
		case <-ctx.Done():
			return totalProcessed, ctx.Err()
		default:
		}

		vuln, err := f.processJSONFile(file, ecosystemFilter)
		if err != nil {
			log.Warn().Err(err).Str("file", file.Name).Msg("failed to process JSON file")
			continue
		}

		if vuln != nil {
			batch = append(batch, vuln)
		}

		// Process batch when it reaches the desired size
		if len(batch) >= batchSize {
			if err := processor(ctx, batch); err != nil {
				return totalProcessed, fmt.Errorf("batch processing failed: %w", err)
			}
			totalProcessed += len(batch)
			batch = batch[:0] // Reset batch slice but keep capacity

			// Log progress
			log.Info().
				Int("processed", totalProcessed).
				Int("remaining_files", len(jsonFiles)-(totalProcessed)).
				Msg("batch processed")
		}
	}

	// Process remaining vulnerabilities in the final batch
	if len(batch) > 0 {
		if err := processor(ctx, batch); err != nil {
			return totalProcessed, fmt.Errorf("final batch processing failed: %w", err)
		}
		totalProcessed += len(batch)
	}

	log.Info().
		Int("total_processed", totalProcessed).
		Msg("batch processing completed")

	return totalProcessed, nil
}
