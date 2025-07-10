package osv

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"cloud.google.com/go/storage"
	"github.com/rs/zerolog/log"
	"github.com/yourusername/vuln-datasync/internal/config"
	"github.com/yourusername/vuln-datasync/internal/types"
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
	// Initialize HTTP client with timeouts
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:       100,
			IdleConnTimeout:    90 * time.Second,
			DisableCompression: false,
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
		return nil, fmt.Errorf("failed to fetch OSV data from all sources: %w", err)
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
		return nil, fmt.Errorf("failed to process OSV ZIP: %w", err)
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
	url := "https://osv-vulnerabilities.storage.googleapis.com/all.zip"

	log.Info().
		Str("url", url).
		Msg("fetching OSV data from HTTP")

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OSV ZIP: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		if err := resp.Body.Close(); err != nil {
			log.Warn().Err(err).Msg("failed to close response body")
		}
		return nil, fmt.Errorf("HTTP error: %s", resp.Status)
	}

	return resp.Body, nil
}

// processZipStream processes the OSV ZIP file stream
func (f *Fetcher) processZipStream(ctx context.Context, reader io.Reader, ecosystems []string) ([]*types.OSVVulnerability, error) {
	// Read entire ZIP into memory (necessary for zip.Reader)
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
		Msg("OSV ZIP downloaded, processing")

	// Create ZIP reader
	zipReader, err := zip.NewReader(
		&readerAt{data: data},
		int64(len(data)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create ZIP reader: %w", err)
	}

	// Create ecosystem filter map
	ecosystemFilter := make(map[string]bool)
	for _, eco := range ecosystems {
		ecosystemFilter[eco] = true
	}

	// Process files with worker pool
	return f.processFilesWithWorkers(ctx, zipReader.File, ecosystemFilter)
}

// processFilesWithWorkers processes JSON files using a worker pool
func (f *Fetcher) processFilesWithWorkers(ctx context.Context, files []*zip.File, ecosystemFilter map[string]bool) ([]*types.OSVVulnerability, error) {
	// Filter JSON files
	jsonFiles := f.filterJSONFiles(files)

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

	for processed < expectedCount {
		select {
		case vuln, ok := <-results:
			if ok {
				processed++
				if vuln != nil {
					vulnerabilities = append(vulnerabilities, vuln)
				}
			}
		case err, ok := <-errors:
			if ok && err != nil && firstError == nil {
				firstError = err
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	// Drain remaining errors
	for len(errors) > 0 {
		if err := <-errors; err != nil && firstError == nil {
			firstError = err
		}
	}

	if firstError != nil {
		log.Warn().Err(firstError).Msg("some files failed to process")
	}

	return vulnerabilities, nil
}

// worker processes individual JSON files
func (f *Fetcher) worker(ctx context.Context, wg *sync.WaitGroup, jobs <-chan *zip.File, results chan<- *types.OSVVulnerability, errors chan<- error, ecosystemFilter map[string]bool) {
	defer wg.Done()

	for {
		select {
		case file, ok := <-jobs:
			if !ok {
				return
			}

			vuln, err := f.processJSONFile(file, ecosystemFilter)
			if err != nil {
				errors <- fmt.Errorf("error processing %s: %w", file.Name, err)
				continue
			}

			if vuln != nil {
				results <- vuln
			}

		case <-ctx.Done():
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

	// Filter by ecosystem if specified
	if len(ecosystemFilter) > 0 {
		found := false
		for _, affected := range vuln.Affected {
			if ecosystemFilter[affected.Package.Ecosystem] {
				found = true
				break
			}
		}
		if !found {
			return nil, nil // Skip this vulnerability
		}
	}

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
