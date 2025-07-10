package cve

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/yourusername/vuln-datasync/internal/config"
	"github.com/yourusername/vuln-datasync/internal/types"
)

const (
	// Maximum file size for extraction (100MB)
	maxFileSize = 100 * 1024 * 1024
)

// Fetcher implements CVE vulnerability data fetching from CVE Project
type Fetcher struct {
	cfg         config.DataSourcesConfig
	httpClient  *http.Client
	workerCount int
	workDir     string
}

// New creates a new CVE fetcher
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

	// Create temporary working directory
	workDir, err := os.MkdirTemp("", "cve-vuln-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}

	return &Fetcher{
		cfg:         cfg,
		httpClient:  httpClient,
		workerCount: 5, // Conservative for large JSON files
		workDir:     workDir,
	}, nil
}

// FetchAll fetches all CVE vulnerabilities from CVE Project
func (f *Fetcher) FetchAll(ctx context.Context, ecosystems []string) ([]*types.CVEVulnerability, error) {
	log.Info().
		Strs("ecosystems", ecosystems).
		Str("source_url", f.cfg.CVEProjectURL).
		Msg("starting CVE vulnerability fetch")

	startTime := time.Now()

	// Download and extract CVE ZIP file
	zipPath, err := f.downloadCVEZip(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to download CVE ZIP: %w", err)
	}
	defer func() {
		if err := os.Remove(zipPath); err != nil {
			log.Warn().Err(err).Str("path", zipPath).Msg("failed to remove zip file")
		}
	}()

	extractPath, err := f.extractZip(zipPath)
	if err != nil {
		return nil, fmt.Errorf("failed to extract ZIP: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(extractPath); err != nil {
			log.Warn().Err(err).Str("path", extractPath).Msg("failed to remove extract path")
		}
	}()

	// Find all CVE JSON files
	jsonFiles, err := f.findCVEFiles(extractPath)
	if err != nil {
		return nil, fmt.Errorf("failed to find CVE files: %w", err)
	}

	log.Info().Int("json_files", len(jsonFiles)).Msg("found CVE JSON files")

	// Process files in parallel
	vulnerabilities, err := f.processFiles(ctx, jsonFiles, ecosystems)
	if err != nil {
		return nil, fmt.Errorf("failed to process files: %w", err)
	}

	duration := time.Since(startTime)
	log.Info().
		Int("total_vulnerabilities", len(vulnerabilities)).
		Dur("duration", duration).
		Msg("CVE fetch completed")

	return vulnerabilities, nil
}

// downloadCVEZip downloads the CVE Project ZIP file
func (f *Fetcher) downloadCVEZip(ctx context.Context) (string, error) {
	url := f.cfg.CVEProjectURL
	if url == "" {
		url = "https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip"
	}

	log.Info().Str("url", url).Msg("downloading CVE Project ZIP")

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to download ZIP: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Warn().Err(err).Msg("failed to close response body")
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download failed with status: %d", resp.StatusCode)
	}

	// Create temporary file for ZIP
	zipFile, err := os.CreateTemp(f.workDir, "cve-*.zip")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	defer func() {
		if err := zipFile.Close(); err != nil {
			log.Warn().Err(err).Msg("failed to close zip file")
		}
	}()

	// Copy response to file
	_, err = io.Copy(zipFile, resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to write ZIP file: %w", err)
	}

	log.Info().Str("path", zipFile.Name()).Msg("CVE ZIP downloaded successfully")
	return zipFile.Name(), nil
}

// extractZip extracts the downloaded ZIP file
func (f *Fetcher) extractZip(zipPath string) (string, error) {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return "", fmt.Errorf("failed to open ZIP: %w", err)
	}
	defer func() {
		if err := reader.Close(); err != nil {
			log.Warn().Err(err).Msg("failed to close zip reader")
		}
	}()

	// Create extraction directory
	extractDir := filepath.Join(f.workDir, "extracted")
	if err := os.MkdirAll(extractDir, 0750); err != nil {
		return "", fmt.Errorf("failed to create extract dir: %w", err)
	}

	log.Info().
		Str("zip_path", zipPath).
		Str("extract_dir", extractDir).
		Msg("extracting CVE ZIP file")

	// Extract files
	for _, file := range reader.File {
		if file.FileInfo().IsDir() {
			continue
		}

		// Only extract JSON files from cves directory
		if !strings.Contains(file.Name, "/cves/") || !strings.HasSuffix(file.Name, ".json") {
			continue
		}

		rc, err := file.Open()
		if err != nil {
			log.Warn().Err(err).Str("file", file.Name).Msg("failed to open file in ZIP")
			continue
		}

		// Create destination file with security validation
		fileName := filepath.Base(file.Name)
		// Prevent zip slip attacks
		if strings.Contains(fileName, "..") || strings.Contains(fileName, "/") || strings.Contains(fileName, "\\") {
			log.Warn().Str("filename", fileName).Msg("skipping potentially malicious filename")
			if closeErr := rc.Close(); closeErr != nil {
				log.Warn().Err(closeErr).Msg("failed to close file reader")
			}
			continue
		}

		destPath := filepath.Join(extractDir, fileName)
		// Final validation of destination path
		if err := f.validateDestinationPath(destPath, extractDir); err != nil {
			log.Warn().Err(err).Str("path", destPath).Msg("skipping invalid destination path")
			if closeErr := rc.Close(); closeErr != nil {
				log.Warn().Err(closeErr).Msg("failed to close file reader")
			}
			continue
		}

		destFile, err := os.Create(destPath) // #nosec G304 -- Destination path is validated by validateDestinationPath above
		if err != nil {
			if closeErr := rc.Close(); closeErr != nil {
				log.Warn().Err(closeErr).Msg("failed to close file reader")
			}
			log.Warn().Err(err).Str("file", file.Name).Msg("failed to create destination file")
			continue
		}

		// Copy content with size limit to prevent decompression bombs
		limitedReader := io.LimitReader(rc, maxFileSize)
		_, err = io.Copy(destFile, limitedReader)
		if closeErr := destFile.Close(); closeErr != nil {
			log.Warn().Err(closeErr).Msg("failed to close destination file")
		}
		if closeErr := rc.Close(); closeErr != nil {
			log.Warn().Err(closeErr).Msg("failed to close file reader")
		}

		if err != nil {
			log.Warn().Err(err).Str("file", file.Name).Msg("failed to extract file")
			continue
		}
	}

	log.Info().Msg("CVE ZIP extraction completed")
	return extractDir, nil
}

// findCVEFiles finds all CVE JSON files in the extracted directory
func (f *Fetcher) findCVEFiles(extractDir string) ([]string, error) {
	var jsonFiles []string

	err := filepath.Walk(extractDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasSuffix(path, ".json") {
			jsonFiles = append(jsonFiles, path)
		}

		return nil
	})

	return jsonFiles, err
}

// processFiles processes CVE JSON files in parallel
func (f *Fetcher) processFiles(ctx context.Context, jsonFiles []string, ecosystems []string) ([]*types.CVEVulnerability, error) {
	var (
		vulnerabilities []*types.CVEVulnerability
		mu              sync.Mutex
		wg              sync.WaitGroup
		fileCh          = make(chan string, len(jsonFiles))
	)

	// Send files to channel
	for _, file := range jsonFiles {
		fileCh <- file
	}
	close(fileCh)

	// Start workers
	for i := 0; i < f.workerCount; i++ {
		wg.Add(1)
		go f.processWorker(ctx, fileCh, &vulnerabilities, &mu, &wg, ecosystems)
	}

	// Wait for completion
	wg.Wait()
	return vulnerabilities, nil
}

// processWorker processes files in a separate goroutine
func (f *Fetcher) processWorker(ctx context.Context, fileCh <-chan string, vulnerabilities *[]*types.CVEVulnerability, mu *sync.Mutex, wg *sync.WaitGroup, ecosystems []string) {
	defer wg.Done()

	for filePath := range fileCh {
		select {
		case <-ctx.Done():
			return
		default:
			// Continue processing
		}

		vuln := f.processFile(filePath, ecosystems)
		if vuln != nil {
			mu.Lock()
			*vulnerabilities = append(*vulnerabilities, vuln)
			mu.Unlock()
		}
	}
}

// processFile processes a single file and applies filtering
func (f *Fetcher) processFile(filePath string, ecosystems []string) *types.CVEVulnerability {
	vuln, err := f.parseCVEFile(filePath)
	if err != nil {
		log.Warn().Err(err).Str("file", filePath).Msg("failed to parse CVE file")
		return nil
	}

	if vuln == nil {
		return nil
	}

	// CVE vulnerabilities don't map directly to ecosystems like OSV does
	// Include all CVEs for now, let the merger handle ecosystem mapping
	// Future enhancement: could filter based on CVE references or affected products

	return vuln
}

// parseCVEFile parses a single CVE JSON file
func (f *Fetcher) parseCVEFile(filePath string) (*types.CVEVulnerability, error) {
	// Validate file path for security
	if err := f.validateFilePath(filePath); err != nil {
		return nil, fmt.Errorf("invalid file path: %w", err)
	}

	data, err := os.ReadFile(filePath) // #nosec G304 -- File path is validated by validateFilePath above
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	var vuln types.CVEVulnerability
	if err := json.Unmarshal(data, &vuln); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	// Validate required fields
	if vuln.CVEMetadata.CVEID == "" {
		return nil, nil // Skip invalid CVEs
	}

	// Only include published CVEs
	if vuln.CVEMetadata.State != "PUBLISHED" {
		return nil, nil
	}

	return &vuln, nil
}

// validateFilePath ensures the file path is safe and within expected boundaries
func (f *Fetcher) validateFilePath(filePath string) error {
	// Clean the path to prevent directory traversal
	cleanPath := filepath.Clean(filePath)

	// Check for directory traversal attempts
	if strings.Contains(cleanPath, "..") {
		return fmt.Errorf("invalid file path: contains directory traversal")
	}

	// Ensure the path is within the work directory
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}

	absWorkDir, err := filepath.Abs(f.workDir)
	if err != nil {
		return fmt.Errorf("failed to get absolute work directory: %w", err)
	}

	if !strings.HasPrefix(absPath, absWorkDir) {
		return fmt.Errorf("file path is outside work directory")
	}

	return nil
}

// validateDestinationPath ensures destination path is safe for file extraction
func (f *Fetcher) validateDestinationPath(destPath, baseDir string) error {
	// Clean the paths
	cleanDest := filepath.Clean(destPath)
	cleanBase := filepath.Clean(baseDir)

	// Get absolute paths
	absDest, err := filepath.Abs(cleanDest)
	if err != nil {
		return fmt.Errorf("failed to get absolute destination path: %w", err)
	}

	absBase, err := filepath.Abs(cleanBase)
	if err != nil {
		return fmt.Errorf("failed to get absolute base path: %w", err)
	}

	// Ensure destination is within the base directory
	if !strings.HasPrefix(absDest, absBase+string(filepath.Separator)) {
		return fmt.Errorf("destination path is outside base directory")
	}

	return nil
}

// Cleanup removes temporary files
func (f *Fetcher) Cleanup() error {
	if f.workDir != "" {
		return os.RemoveAll(f.workDir)
	}
	return nil
}
