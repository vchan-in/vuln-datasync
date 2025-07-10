package gitlab

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"

	"github.com/yourusername/vuln-datasync/internal/config"
	"github.com/yourusername/vuln-datasync/internal/types"
)

// Fetcher implements GitLab vulnerability data fetching
type Fetcher struct {
	cfg         config.DataSourcesConfig
	workerCount int
	repoURL     string
	workDir     string
}

// New creates a new GitLab fetcher
func New(cfg config.DataSourcesConfig) (*Fetcher, error) {
	repoURL := cfg.GitLabRepoURL
	if repoURL == "" {
		repoURL = "https://gitlab.com/gitlab-org/security-products/gemnasium-db.git"
	}

	// Create temporary working directory
	workDir, err := os.MkdirTemp("", "gitlab-vuln-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}

	return &Fetcher{
		cfg:         cfg,
		workerCount: 10, // Conservative for Git operations
		repoURL:     repoURL,
		workDir:     workDir,
	}, nil
}

// FetchAll fetches all GitLab vulnerabilities
func (f *Fetcher) FetchAll(ctx context.Context, ecosystems []string) ([]*types.GitLabVulnerability, error) {
	log.Info().
		Strs("ecosystems", ecosystems).
		Str("repo_url", f.repoURL).
		Msg("starting GitLab vulnerability fetch")

	startTime := time.Now()

	// Clone or update repository
	if err := f.cloneOrUpdateRepo(ctx); err != nil {
		return nil, fmt.Errorf("failed to clone/update repository: %w", err)
	}

	// Find all YAML vulnerability files
	yamlFiles, err := f.findVulnerabilityFiles()
	if err != nil {
		return nil, fmt.Errorf("failed to find vulnerability files: %w", err)
	}

	log.Info().Int("yaml_files", len(yamlFiles)).Msg("found YAML vulnerability files")

	// Process files in parallel
	vulnerabilities, err := f.processFiles(ctx, yamlFiles, ecosystems)
	if err != nil {
		return nil, fmt.Errorf("failed to process files: %w", err)
	}

	duration := time.Since(startTime)
	log.Info().
		Int("total_vulnerabilities", len(vulnerabilities)).
		Dur("duration", duration).
		Msg("GitLab fetch completed")

	return vulnerabilities, nil
}

// cloneOrUpdateRepo clones the repository or updates if it exists
func (f *Fetcher) cloneOrUpdateRepo(ctx context.Context) error {
	repoPath := filepath.Join(f.workDir, "gemnasium-db")

	// Check if repo already exists
	if _, err := os.Stat(filepath.Join(repoPath, ".git")); err == nil {
		// Repository exists, try to update
		log.Info().Str("path", repoPath).Msg("updating existing repository")

		repo, err := git.PlainOpen(repoPath)
		if err != nil {
			return fmt.Errorf("failed to open existing repo: %w", err)
		}

		workTree, err := repo.Worktree()
		if err != nil {
			return fmt.Errorf("failed to get worktree: %w", err)
		}

		err = workTree.PullContext(ctx, &git.PullOptions{
			ReferenceName: plumbing.ReferenceName("refs/heads/master"),
		})
		if err != nil && err != git.NoErrAlreadyUpToDate {
			log.Warn().Err(err).Msg("failed to pull updates, continuing with existing version")
		}

		return nil
	}

	// Repository doesn't exist, clone it
	log.Info().
		Str("url", f.repoURL).
		Str("path", repoPath).
		Msg("cloning GitLab vulnerability repository")

	_, err := git.PlainCloneContext(ctx, repoPath, false, &git.CloneOptions{
		URL:           f.repoURL,
		ReferenceName: plumbing.ReferenceName("refs/heads/master"),
		SingleBranch:  true,
		Depth:         1, // Shallow clone for efficiency
	})

	if err != nil {
		return fmt.Errorf("failed to clone repository: %w", err)
	}

	log.Info().Msg("repository cloned successfully")
	return nil
}

// findVulnerabilityFiles finds all YAML vulnerability files in the repository
func (f *Fetcher) findVulnerabilityFiles() ([]string, error) {
	var yamlFiles []string
	repoPath := filepath.Join(f.workDir, "gemnasium-db")

	err := filepath.WalkDir(repoPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip .git directory
		if d.IsDir() && d.Name() == ".git" {
			return filepath.SkipDir
		}

		// Look for YAML files in vulnerability directories
		if !d.IsDir() && (strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml")) {
			// Check if this is in a vulnerability-related directory
			if strings.Contains(path, "advisories") ||
				strings.Contains(path, "vulnerabilities") ||
				strings.Contains(path, "gems") ||
				strings.Contains(path, "npm") ||
				strings.Contains(path, "pypi") ||
				strings.Contains(path, "go") ||
				strings.Contains(path, "maven") ||
				strings.Contains(path, "nuget") {
				yamlFiles = append(yamlFiles, path)
			}
		}

		return nil
	})

	return yamlFiles, err
}

// processFiles processes YAML files in parallel
func (f *Fetcher) processFiles(ctx context.Context, yamlFiles []string, ecosystems []string) ([]*types.GitLabVulnerability, error) {
	ecosystemFilter := f.createEcosystemFilter(ecosystems)

	var (
		vulnerabilities []*types.GitLabVulnerability
		mu              sync.Mutex
		wg              sync.WaitGroup
		fileCh          = make(chan string, len(yamlFiles))
	)

	// Send files to channel
	for _, file := range yamlFiles {
		fileCh <- file
	}
	close(fileCh)

	// Start workers
	for i := 0; i < f.workerCount; i++ {
		wg.Add(1)
		go f.processWorker(ctx, fileCh, &vulnerabilities, &mu, &wg, ecosystemFilter, ecosystems)
	}

	// Wait for completion
	wg.Wait()
	return vulnerabilities, nil
}

// createEcosystemFilter creates a map for faster ecosystem lookup
func (f *Fetcher) createEcosystemFilter(ecosystems []string) map[string]bool {
	ecosystemFilter := make(map[string]bool)
	for _, eco := range ecosystems {
		ecosystemFilter[strings.ToLower(eco)] = true
	}
	return ecosystemFilter
}

// processWorker processes files in a separate goroutine
func (f *Fetcher) processWorker(ctx context.Context, fileCh <-chan string, vulnerabilities *[]*types.GitLabVulnerability, mu *sync.Mutex, wg *sync.WaitGroup, ecosystemFilter map[string]bool, ecosystems []string) {
	defer wg.Done()

	for filePath := range fileCh {
		select {
		case <-ctx.Done():
			return
		default:
		}

		vuln := f.processFile(filePath, ecosystemFilter, ecosystems)
		if vuln != nil {
			mu.Lock()
			*vulnerabilities = append(*vulnerabilities, vuln)
			mu.Unlock()
		}
	}
}

// processFile processes a single file and applies filtering
func (f *Fetcher) processFile(filePath string, ecosystemFilter map[string]bool, ecosystems []string) *types.GitLabVulnerability {
	vuln, err := f.parseVulnerabilityFile(filePath)
	if err != nil {
		log.Warn().Err(err).Str("file", filePath).Msg("failed to parse vulnerability file")
		return nil
	}

	if vuln == nil {
		return nil
	}

	// Apply ecosystem filter if specified
	if len(ecosystems) > 0 {
		ecosystem := f.extractEcosystem(filePath)
		if !ecosystemFilter[strings.ToLower(ecosystem)] {
			return nil
		}
	}

	return vuln
}

// parseVulnerabilityFile parses a single YAML vulnerability file
func (f *Fetcher) parseVulnerabilityFile(filePath string) (*types.GitLabVulnerability, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	var vuln types.GitLabVulnerability
	if err := yaml.Unmarshal(data, &vuln); err != nil {
		return nil, fmt.Errorf("failed to unmarshal YAML: %w", err)
	}

	// Validate required fields
	if vuln.Identifier == "" || vuln.Title == "" {
		return nil, nil // Skip invalid vulnerabilities
	}

	// Extract ecosystem from file path if not present
	if vuln.PackageSlug == "" {
		vuln.PackageSlug = f.extractPackageFromPath(filePath)
	}

	return &vuln, nil
}

// extractEcosystem extracts the ecosystem from the file path
func (f *Fetcher) extractEcosystem(filePath string) string {
	if strings.Contains(filePath, "/gems/") {
		return "rubygems"
	}
	if strings.Contains(filePath, "/npm/") {
		return "npm"
	}
	if strings.Contains(filePath, "/pypi/") {
		return "pypi"
	}
	if strings.Contains(filePath, "/go/") {
		return "go"
	}
	if strings.Contains(filePath, "/maven/") {
		return "maven"
	}
	if strings.Contains(filePath, "/nuget/") {
		return "nuget"
	}
	return "unknown"
}

// extractPackageFromPath extracts package name from file path
func (f *Fetcher) extractPackageFromPath(filePath string) string {
	// Extract package name from path structure
	parts := strings.Split(filePath, "/")
	for i, part := range parts {
		if part == "gems" || part == "npm" || part == "pypi" ||
			part == "go" || part == "maven" || part == "nuget" {
			if i+1 < len(parts) {
				return parts[i+1]
			}
		}
	}
	return ""
}

// Cleanup removes temporary files
func (f *Fetcher) Cleanup() error {
	if f.workDir != "" {
		return os.RemoveAll(f.workDir)
	}
	return nil
}
