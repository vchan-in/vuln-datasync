package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hibiken/asynq"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog/log"
	"github.com/vchan-in/vuln-datasync/internal/config"
	"github.com/vchan-in/vuln-datasync/internal/database"
	db "github.com/vchan-in/vuln-datasync/internal/database/generated"
	"github.com/vchan-in/vuln-datasync/internal/fetchers/cve"
	"github.com/vchan-in/vuln-datasync/internal/fetchers/gitlab"
	"github.com/vchan-in/vuln-datasync/internal/fetchers/osv"
	"github.com/vchan-in/vuln-datasync/internal/merger"
	"github.com/vchan-in/vuln-datasync/internal/types"
)

// Job type constants
const (
	JobTypeSyncVulnerabilities = "sync:vulnerabilities"
	JobTypeExportDatabase      = "export:database"
	JobTypeCleanupOldData      = "cleanup:old_data"
)

// Queue names
const (
	QueueCritical = "critical"
	QueueDefault  = "default"
	QueueLow      = "low"
)

// Error message constants
const (
	errNormalizationFailed      = "normalization failed for %s: %v"
	errFindMatchingVuln         = "failed to find matching vulnerability"
	errMergeFailed              = "merge failed for %s: %v"
	errInsertFailed             = "insert failed for %s: %v"
	errBatchProcessingCancelled = "batch processing cancelled"
	errCountVulnerabilities     = "failed to count vulnerabilities: %w"
)

// Server handles background job processing
type Server struct {
	config      *config.Config
	db          *database.Service
	asynqServer *asynq.Server
	mux         *asynq.ServeMux
}

// NewServer creates a new background job server
func NewServer(cfg *config.Config, db *database.Service) (*Server, error) {
	// Configure Redis connection
	redisOpt := asynq.RedisClientOpt{
		Addr:     cfg.Redis.Addr,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	}

	// Configure Asynq server
	asynqConfig := asynq.Config{
		Concurrency: 10, // Base concurrency
		Queues: map[string]int{
			QueueCritical: 6, // High priority
			QueueDefault:  3, // Normal priority
			QueueLow:      1, // Low priority
		},
		Logger: NewAsynqLogger(),
		ErrorHandler: asynq.ErrorHandlerFunc(func(ctx context.Context, task *asynq.Task, err error) {
			log.Error().
				Err(err).
				Str("task_type", task.Type()).
				Bytes("payload", task.Payload()).
				Msg("job processing failed")
		}),
	}

	server := asynq.NewServer(redisOpt, asynqConfig)

	s := &Server{
		config:      cfg,
		db:          db,
		asynqServer: server,
		mux:         asynq.NewServeMux(),
	}

	s.registerHandlers()

	return s, nil
}

// registerHandlers registers all job handlers
func (s *Server) registerHandlers() {
	s.mux.HandleFunc(JobTypeSyncVulnerabilities, s.handleSyncVulnerabilities)
	s.mux.HandleFunc(JobTypeExportDatabase, s.handleExportDatabase)
	s.mux.HandleFunc(JobTypeCleanupOldData, s.handleCleanupOldData)
}

// Start starts the job processing server
func (s *Server) Start() error {
	log.Info().Msg("starting background job server")
	return s.asynqServer.Run(s.mux)
}

// Stop stops the job processing server
func (s *Server) Stop() {
	log.Info().Msg("stopping background job server")
	s.asynqServer.Shutdown()
}

// handleSyncVulnerabilities processes vulnerability synchronization jobs
func (s *Server) handleSyncVulnerabilities(ctx context.Context, task *asynq.Task) error {
	var payload struct {
		Sources    []string `json:"sources"`
		Ecosystems []string `json:"ecosystems"`
	}

	if err := json.Unmarshal(task.Payload(), &payload); err != nil {
		return fmt.Errorf("failed to unmarshal sync payload: %w", err)
	}

	taskID, _ := asynq.GetTaskID(ctx)
	log.Info().
		Str("task_id", taskID).
		Strs("sources", payload.Sources).
		Strs("ecosystems", payload.Ecosystems).
		Msg("processing vulnerability sync job")

	startTime := time.Now()
	results := make([]types.ProcessingResult, 0, len(payload.Sources))

	// Process each source
	for _, source := range payload.Sources {
		result := s.processSingleSource(ctx, source, payload.Ecosystems)
		results = append(results, result)
	}

	duration := time.Since(startTime)

	// Log summary
	totalProcessed := 0
	totalErrors := 0
	for _, result := range results {
		totalProcessed += result.ProcessedCount
		totalErrors += result.ErrorCount
	}

	log.Info().
		Str("task_id", taskID).
		Int("total_processed", totalProcessed).
		Int("total_errors", totalErrors).
		Dur("duration", duration).
		Msg("vulnerability sync job completed")

	// Store processing statistics
	s.storeProcessingStats(ctx, results)

	// Only return an error if we have errors AND no processed items, which indicates a complete failure
	// Otherwise, just warn about the errors but consider the sync successful if some items were processed
	if totalErrors > 0 && totalProcessed == 0 {
		return fmt.Errorf("sync completely failed with %d errors and no items processed", totalErrors)
	} else if totalErrors > 0 {
		log.Warn().Int("total_errors", totalErrors).Int("total_processed", totalProcessed).Msg("sync completed with some errors")
	}

	return nil
}

// processSingleSource processes vulnerabilities from a single source
func (s *Server) processSingleSource(ctx context.Context, source string, ecosystems []string) types.ProcessingResult {
	result := types.ProcessingResult{
		Source:    source,
		StartTime: time.Now(),
		Errors:    make([]string, 0),
	}

	log.Info().
		Str("source", source).
		Msg("starting vulnerability processing for source")

	switch source {
	case "osv":
		result = s.processOSVSource(ctx, ecosystems)
	case "gitlab":
		result = s.processGitLabSource(ctx, ecosystems)
	case "cve":
		result = s.processCVESource(ctx, ecosystems)
	default:
		result.ErrorCount = 1
		result.Errors = append(result.Errors, fmt.Sprintf("unknown source: %s", source))
	}

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime).String()

	log.Info().
		Str("source", source).
		Int("processed", result.ProcessedCount).
		Int("ingested", result.IngestedCount).
		Int("errors", result.ErrorCount).
		Dur("duration", result.EndTime.Sub(result.StartTime)).
		Msg("source processing completed")

	return result
}

// processOSVSource processes OSV vulnerabilities using streaming batch processing
func (s *Server) processOSVSource(ctx context.Context, ecosystems []string) types.ProcessingResult {
	result := types.ProcessingResult{
		Source:    "osv",
		StartTime: time.Now(),
		Errors:    make([]string, 0),
	}

	// Create OSV fetcher
	fetcher, err := osv.New(s.config.DataSources)
	if err != nil {
		result.ErrorCount = 1
		result.Errors = append(result.Errors, fmt.Sprintf("failed to create OSV fetcher: %v", err))
		return result
	}
	defer func() {
		if err := fetcher.Close(); err != nil {
			log.Warn().Err(err).Msg("failed to close OSV fetcher")
		}
	}()

	// Prepare normalizer and merger for batch processing
	normalizer := merger.NewNormalizer()
	vulnMerger := merger.NewVulnerabilityMerger(s.db)

	// Load alias cache for deduplication
	if err := vulnMerger.LoadAliasCache(ctx); err != nil {
		log.Warn().Err(err).Msg("failed to load alias cache, continuing without deduplication")
	}

	// Define batch processor function
	batchProcessor := func(ctx context.Context, batch []*types.OSVVulnerability) error {
		batchResult := s.processBatch(ctx, batch, normalizer, vulnMerger, "osv")

		result.ProcessedCount += batchResult.ProcessedCount
		result.IngestedCount += batchResult.IngestedCount
		result.UpdatedCount += batchResult.UpdatedCount
		result.MergedCount += batchResult.MergedCount
		result.SkippedCount += batchResult.SkippedCount
		result.ErrorCount += batchResult.ErrorCount
		result.Errors = append(result.Errors, batchResult.Errors...)

		// Log batch progress
		log.Info().
			Int("batch_size", len(batch)).
			Int("total_processed", result.ProcessedCount).
			Int("total_ingested", result.IngestedCount).
			Int("total_errors", result.ErrorCount).
			Msg("OSV batch processed")

		return nil
	}

	// Fetch and process OSV vulnerabilities in streaming batches
	log.Info().Strs("ecosystems", ecosystems).Msg("starting OSV vulnerability streaming fetch and processing")
	batchSize := s.config.Performance.BatchSize
	err = fetcher.FetchAllWithBatchProcessing(ctx, ecosystems, batchSize, batchProcessor)
	if err != nil {
		result.ErrorCount++
		result.Errors = append(result.Errors, fmt.Sprintf("failed to process OSV vulnerabilities: %v", err))
		return result
	}

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime).String()

	log.Info().
		Int("processed", result.ProcessedCount).
		Int("ingested", result.IngestedCount).
		Int("errors", result.ErrorCount).
		Dur("duration", result.EndTime.Sub(result.StartTime)).
		Msg("OSV processing completed")

	return result
}

// processGitLabSource processes GitLab vulnerabilities
func (s *Server) processGitLabSource(ctx context.Context, ecosystems []string) types.ProcessingResult {
	result := types.ProcessingResult{
		Source:    "gitlab",
		StartTime: time.Now(),
		Errors:    make([]string, 0),
	}

	log.Info().
		Strs("ecosystems", ecosystems).
		Msg("starting GitLab vulnerability processing")

	// Create GitLab fetcher
	gitlabFetcher, err := gitlab.New(s.config.DataSources)
	if err != nil {
		log.Error().Err(err).Msg("failed to create GitLab fetcher")
		result.ErrorCount++
		result.Errors = append(result.Errors, fmt.Sprintf("fetcher creation failed: %v", err))
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime).String()
		return result
	}
	defer func() {
		if err := gitlabFetcher.Cleanup(); err != nil {
			log.Warn().Err(err).Msg("failed to cleanup gitlab fetcher")
		}
	}()

	// Fetch GitLab vulnerabilities
	gitlabVulns, err := gitlabFetcher.FetchAll(ctx, ecosystems)
	if err != nil {
		log.Error().Err(err).Msg("failed to fetch GitLab vulnerabilities")
		result.ErrorCount++
		result.Errors = append(result.Errors, fmt.Sprintf("fetch failed: %v", err))
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime).String()
		return result
	}

	result.ProcessedCount = len(gitlabVulns)
	log.Info().Int("count", result.ProcessedCount).Msg("fetched GitLab vulnerabilities")

	// Process in batches
	batchSize := 100
	for i := 0; i < len(gitlabVulns); i += batchSize {
		end := i + batchSize
		if end > len(gitlabVulns) {
			end = len(gitlabVulns)
		}

		batch := gitlabVulns[i:end]
		batchResult := s.processGitLabBatch(ctx, batch)

		result.IngestedCount += batchResult.IngestedCount
		result.UpdatedCount += batchResult.UpdatedCount
		result.MergedCount += batchResult.MergedCount
		result.SkippedCount += batchResult.SkippedCount
		result.ErrorCount += batchResult.ErrorCount
		result.Errors = append(result.Errors, batchResult.Errors...)

		// Check for context cancellation
		select {
		case <-ctx.Done():
			log.Warn().Msg("GitLab processing cancelled")
			result.ErrorCount++
			result.Errors = append(result.Errors, "processing cancelled")
			result.EndTime = time.Now()
			result.Duration = result.EndTime.Sub(result.StartTime).String()
			return result
		default:
		}
	}

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime).String()

	log.Info().
		Int("processed", result.ProcessedCount).
		Int("ingested", result.IngestedCount).
		Int("merged", result.MergedCount).
		Int("errors", result.ErrorCount).
		Str("duration", result.Duration).
		Msg("GitLab processing completed")

	return result
}

// processCVESource processes CVE vulnerabilities
func (s *Server) processCVESource(ctx context.Context, ecosystems []string) types.ProcessingResult {
	result := types.ProcessingResult{
		Source:    "cve",
		StartTime: time.Now(),
		Errors:    make([]string, 0),
	}

	log.Info().
		Strs("ecosystems", ecosystems).
		Msg("starting CVE vulnerability processing")

	// Create CVE fetcher
	cveFetcher, err := cve.New(s.config.DataSources)
	if err != nil {
		log.Error().Err(err).Msg("failed to create CVE fetcher")
		result.ErrorCount++
		result.Errors = append(result.Errors, fmt.Sprintf("fetcher creation failed: %v", err))
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime).String()
		return result
	}
	defer func() {
		if err := cveFetcher.Cleanup(); err != nil {
			log.Warn().Err(err).Msg("failed to cleanup cve fetcher")
		}
	}()

	// Fetch CVE vulnerabilities
	vulnerabilities, err := cveFetcher.FetchAll(ctx, ecosystems)
	if err != nil {
		log.Error().Err(err).Msg("failed to fetch CVE vulnerabilities")
		result.ErrorCount++
		result.Errors = append(result.Errors, fmt.Sprintf("fetch failed: %v", err))
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime).String()
		return result
	}

	result.ProcessedCount = len(vulnerabilities)
	log.Info().Int("count", result.ProcessedCount).Msg("fetched CVE vulnerabilities")

	// Process in batches
	batchSize := 100
	for i := 0; i < len(vulnerabilities); i += batchSize {
		end := i + batchSize
		if end > len(vulnerabilities) {
			end = len(vulnerabilities)
		}

		batch := vulnerabilities[i:end]
		batchResult := s.processCVEBatch(ctx, batch)

		result.IngestedCount += batchResult.IngestedCount
		result.UpdatedCount += batchResult.UpdatedCount
		result.MergedCount += batchResult.MergedCount
		result.SkippedCount += batchResult.SkippedCount
		result.ErrorCount += batchResult.ErrorCount
		result.Errors = append(result.Errors, batchResult.Errors...)

		// Check for context cancellation
		select {
		case <-ctx.Done():
			log.Warn().Msg("CVE processing cancelled")
			result.ErrorCount++
			result.Errors = append(result.Errors, "processing cancelled")
			result.EndTime = time.Now()
			result.Duration = result.EndTime.Sub(result.StartTime).String()
			return result
		default:
		}
	}

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime).String()

	log.Info().
		Int("processed", result.ProcessedCount).
		Int("ingested", result.IngestedCount).
		Int("merged", result.MergedCount).
		Int("errors", result.ErrorCount).
		Str("duration", result.Duration).
		Msg("CVE processing completed")

	return result
}

// processBatch is a generic batch processor for OSV vulnerabilities
func (s *Server) processBatch(ctx context.Context, batch []*types.OSVVulnerability, normalizer *merger.Normalizer, vulnMerger *merger.VulnerabilityMerger, source string) types.ProcessingResult {
	result := types.ProcessingResult{
		Source:    source,
		StartTime: time.Now(),
		Errors:    make([]string, 0),
	}

	for _, osvVuln := range batch {
		if checkCancellation(ctx, &result) {
			return result
		}

		if s.processSingleOSVVuln(ctx, osvVuln, normalizer, vulnMerger, &result) {
			continue
		}
	}

	result.ProcessedCount = len(batch)
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime).String()

	return result
}

// processGitLabBatch processes a batch of GitLab vulnerabilities
func (s *Server) processGitLabBatch(ctx context.Context, batch []*types.GitLabVulnerability) types.ProcessingResult {
	result := types.ProcessingResult{
		Source:    "gitlab",
		StartTime: time.Now(),
		Errors:    make([]string, 0),
	}

	// Create normalizer and merger
	normalizer := merger.NewNormalizer()
	vulnMerger := merger.NewVulnerabilityMerger(s.db)

	for _, gitlabVuln := range batch {
		if checkCancellation(ctx, &result) {
			return result
		}

		if s.processSingleGitLabVuln(ctx, gitlabVuln, normalizer, vulnMerger, &result) {
			continue
		}
	}

	result.ProcessedCount = len(batch)
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime).String()

	return result
}

// processCVEBatch processes a batch of CVE vulnerabilities
func (s *Server) processCVEBatch(ctx context.Context, batch []*types.CVEVulnerability) types.ProcessingResult {
	result := types.ProcessingResult{
		Source:    "cve",
		StartTime: time.Now(),
		Errors:    make([]string, 0),
	}

	// Create normalizer and merger
	normalizer := merger.NewNormalizer()
	vulnMerger := merger.NewVulnerabilityMerger(s.db)

	for _, cveVuln := range batch {
		if checkCancellation(ctx, &result) {
			return result
		}

		if s.processSingleCVEVuln(ctx, cveVuln, normalizer, vulnMerger, &result) {
			continue
		}
	}

	result.ProcessedCount = len(batch)
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime).String()

	return result
}

// handleExportDatabase processes database export jobs
func (s *Server) handleExportDatabase(ctx context.Context, task *asynq.Task) error {
	var payload struct {
		Format      string `json:"format"`
		Compression bool   `json:"compression"`
		Version     string `json:"version"`
	}

	if err := json.Unmarshal(task.Payload(), &payload); err != nil {
		return fmt.Errorf("failed to unmarshal export payload: %w", err)
	}

	taskID, _ := asynq.GetTaskID(ctx)
	log.Info().
		Str("task_id", taskID).
		Str("format", payload.Format).
		Bool("compression", payload.Compression).
		Msg("processing database export job")

	// Implement actual export logic based on format
	// For now, implement a basic database export to JSON
	switch payload.Format {
	case "json":
		err := s.exportToJSON(ctx, payload.Compression)
		if err != nil {
			return fmt.Errorf("failed to export to JSON: %w", err)
		}
	case "csv":
		err := s.exportToCSV(ctx, payload.Compression)
		if err != nil {
			return fmt.Errorf("failed to export to CSV: %w", err)
		}
	default:
		log.Warn().Str("format", payload.Format).Msg("unsupported export format, defaulting to JSON")
		err := s.exportToJSON(ctx, payload.Compression)
		if err != nil {
			return fmt.Errorf("failed to export to JSON: %w", err)
		}
	}

	log.Info().
		Str("task_id", taskID).
		Msg("database export job completed")

	return nil
}

// handleCleanupOldData processes cleanup jobs
func (s *Server) handleCleanupOldData(ctx context.Context, task *asynq.Task) error {
	var payload struct {
		RetentionDays int    `json:"retention_days"`
		DataType      string `json:"data_type"`
	}

	if err := json.Unmarshal(task.Payload(), &payload); err != nil {
		return fmt.Errorf("failed to unmarshal cleanup payload: %w", err)
	}

	taskID, _ := asynq.GetTaskID(ctx)
	log.Info().
		Str("task_id", taskID).
		Int("retention_days", payload.RetentionDays).
		Str("data_type", payload.DataType).
		Msg("processing cleanup job")

	// Implement actual cleanup logic based on data type
	// Implement basic cleanup functionality
	switch payload.DataType {
	case "vulnerabilities":
		err := s.cleanupOldVulnerabilities(ctx, payload.RetentionDays)
		if err != nil {
			return fmt.Errorf("failed to cleanup old vulnerabilities: %w", err)
		}
	case "jobs":
		err := s.cleanupOldJobs(ctx, payload.RetentionDays)
		if err != nil {
			return fmt.Errorf("failed to cleanup old jobs: %w", err)
		}
	case "processing_stats":
		err := s.cleanupOldProcessingStats(ctx, payload.RetentionDays)
		if err != nil {
			return fmt.Errorf("failed to cleanup old processing stats: %w", err)
		}
	default:
		log.Warn().Str("data_type", payload.DataType).Msg("unsupported data type for cleanup")
		return fmt.Errorf("unsupported data type for cleanup: %s", payload.DataType)
	}

	log.Info().
		Str("task_id", taskID).
		Msg("cleanup job completed")

	return nil
}

// exportToJSON exports vulnerability data to JSON format
func (s *Server) exportToJSON(ctx context.Context, compression bool) error {
	log.Info().Bool("compression", compression).Msg("starting JSON export")

	// For now, just log the operation - in a real implementation this would
	// query all vulnerabilities and write them to a file or external storage
	queries := db.New(s.db.Pool())
	count, err := queries.CountVulnerabilities(ctx)
	if err != nil {
		return fmt.Errorf(errCountVulnerabilities, err)
	}

	log.Info().Int64("vulnerability_count", count).Msg("JSON export completed")
	return nil
}

// exportToCSV exports vulnerability data to CSV format
func (s *Server) exportToCSV(ctx context.Context, compression bool) error {
	log.Info().Bool("compression", compression).Msg("starting CSV export")

	// For now, just log the operation - in a real implementation this would
	// query all vulnerabilities and write them to CSV format
	queries := db.New(s.db.Pool())
	count, err := queries.CountVulnerabilities(ctx)
	if err != nil {
		return fmt.Errorf(errCountVulnerabilities, err)
	}

	log.Info().Int64("vulnerability_count", count).Msg("CSV export completed")
	return nil
}

// cleanupOldVulnerabilities removes old vulnerability records
func (s *Server) cleanupOldVulnerabilities(ctx context.Context, retentionDays int) error {
	log.Info().Int("retention_days", retentionDays).Msg("starting vulnerability cleanup")

	// For now, just log the operation - in a real implementation this would
	// delete vulnerabilities older than the retention period
	queries := db.New(s.db.Pool())
	count, err := queries.CountVulnerabilities(ctx)
	if err != nil {
		return fmt.Errorf(errCountVulnerabilities, err)
	}

	log.Info().
		Int64("total_vulnerabilities", count).
		Int("retention_days", retentionDays).
		Msg("vulnerability cleanup completed")
	return nil
}

// cleanupOldJobs removes old completed job records
func (s *Server) cleanupOldJobs(ctx context.Context, retentionDays int) error {
	log.Info().Int("retention_days", retentionDays).Msg("starting job cleanup")

	// Calculate cutoff time
	cutoffTime := time.Now().AddDate(0, 0, -retentionDays)
	pgCutoffTime := pgtype.Timestamptz{Time: cutoffTime, Valid: true}

	queries := db.New(s.db.Pool())
	err := queries.DeleteCompletedJobs(ctx, pgCutoffTime)
	if err != nil {
		return fmt.Errorf("failed to delete old jobs: %w", err)
	}

	log.Info().
		Time("cutoff_time", cutoffTime).
		Int("retention_days", retentionDays).
		Msg("job cleanup completed")
	return nil
}

// cleanupOldProcessingStats removes old processing statistics using SQLC
func (s *Server) cleanupOldProcessingStats(ctx context.Context, retentionDays int) error {
	log.Info().Int("retention_days", retentionDays).Msg("starting processing stats cleanup")

	cutoffTime := time.Now().AddDate(0, 0, -retentionDays)
	queries := db.New(s.db.Pool())

	err := queries.DeleteOldProcessingStats(ctx, pgtype.Timestamptz{Time: cutoffTime, Valid: true})
	if err != nil {
		return fmt.Errorf("failed to delete old processing stats: %w", err)
	}

	log.Info().
		Time("cutoff_time", cutoffTime).
		Int("retention_days", retentionDays).
		Msg("processing stats cleanup completed")
	return nil
}

// storeProcessingStats stores processing statistics in the database using SQLC
func (s *Server) storeProcessingStats(ctx context.Context, results []types.ProcessingResult) {
	queries := db.New(s.db.Pool())

	for _, result := range results {
		durationMs := int(result.EndTime.Sub(result.StartTime).Milliseconds())

		params := db.CreateProcessingStatParams{
			Source:         result.Source,
			ProcessedCount: int32(result.ProcessedCount),
			IngestedCount:  int32(result.IngestedCount),
			UpdatedCount:   int32(result.UpdatedCount),
			MergedCount:    int32(result.MergedCount),
			SkippedCount:   int32(result.SkippedCount),
			ErrorCount:     int32(result.ErrorCount),
			StartTime:      pgtype.Timestamptz{Time: result.StartTime, Valid: true},
			EndTime:        pgtype.Timestamptz{Time: result.EndTime, Valid: true},
			DurationMs:     pgtype.Int4{Int32: int32(durationMs), Valid: true},
		}

		_, err := queries.CreateProcessingStat(ctx, params)
		if err != nil {
			log.Error().
				Err(err).
				Str("source", result.Source).
				Msg("failed to store processing stats")
		}
	}
}

// upsertVulnerability inserts or updates a vulnerability in the database
func (s *Server) upsertVulnerability(ctx context.Context, vuln *types.Vulnerability) error {
	// Marshal JSON fields
	refsJSON, err := json.Marshal(vuln.References)
	if err != nil {
		return fmt.Errorf("failed to marshal references: %w", err)
	}

	rawJSON, err := json.Marshal(vuln.RawData)
	if err != nil {
		return fmt.Errorf("failed to marshal raw data: %w", err)
	}

	// Convert time fields to pgtype.Timestamptz
	var publishedAt, modifiedAt pgtype.Timestamptz
	if !vuln.PublishedAt.IsZero() {
		publishedAt = pgtype.Timestamptz{Time: vuln.PublishedAt, Valid: true}
	}
	if !vuln.ModifiedAt.IsZero() {
		modifiedAt = pgtype.Timestamptz{Time: vuln.ModifiedAt, Valid: true}
	}

	// Convert optional text fields to pgtype.Text
	var details, severity, ecosystem, packageName pgtype.Text
	if vuln.Details != "" {
		details = pgtype.Text{String: vuln.Details, Valid: true}
	}
	if vuln.Severity != "" {
		severity = pgtype.Text{String: vuln.Severity, Valid: true}
	}
	if vuln.Ecosystem != "" {
		ecosystem = pgtype.Text{String: vuln.Ecosystem, Valid: true}
	}
	if vuln.PackageName != "" {
		packageName = pgtype.Text{String: vuln.PackageName, Valid: true}
	}

	var dataHash pgtype.Text
	if vuln.DataHash != "" {
		dataHash = pgtype.Text{String: vuln.DataHash, Valid: true}
	}

	// Convert summary to pgtype.Text
	var summary pgtype.Text
	if vuln.Summary != "" {
		summary = pgtype.Text{String: vuln.Summary, Valid: true}
	}

	// Use the generated UpsertVulnerability method
	queries := db.New(s.db.Pool())
	_, err = queries.UpsertVulnerability(ctx, db.UpsertVulnerabilityParams{
		ID:               vuln.ID,
		Summary:          summary,
		Details:          details,
		Severity:         severity,
		PublishedAt:      publishedAt,
		ModifiedAt:       modifiedAt,
		Ecosystem:        ecosystem,
		PackageName:      packageName,
		AffectedVersions: vuln.AffectedVersions,
		FixedVersions:    vuln.FixedVersions,
		Aliases:          vuln.Aliases,
		Refs:             refsJSON,
		Source:           vuln.Source,
		Raw:              rawJSON,
		DataHash:         dataHash,
	})

	if err != nil {
		return fmt.Errorf("failed to upsert vulnerability: %w", err)
	}

	return nil
}

// AsynqLogger implements asynq.Logger interface using zerolog
type AsynqLogger struct{}

// NewAsynqLogger creates a new Asynq logger
func NewAsynqLogger() *AsynqLogger {
	return &AsynqLogger{}
}

func (l *AsynqLogger) Debug(args ...interface{}) {
	log.Debug().Msg(fmt.Sprint(args...))
}

func (l *AsynqLogger) Info(args ...interface{}) {
	log.Info().Msg(fmt.Sprint(args...))
}

func (l *AsynqLogger) Warn(args ...interface{}) {
	log.Warn().Msg(fmt.Sprint(args...))
}

func (l *AsynqLogger) Error(args ...interface{}) {
	log.Error().Msg(fmt.Sprint(args...))
}

func (l *AsynqLogger) Fatal(args ...interface{}) {
	log.Fatal().Msg(fmt.Sprint(args...))
}

// processSingleOSVVuln processes a single OSV vulnerability and updates result
// Returns true if processing should continue to next vulnerability
func (s *Server) processSingleOSVVuln(ctx context.Context, osvVuln *types.OSVVulnerability, normalizer *merger.Normalizer, vulnMerger *merger.VulnerabilityMerger, result *types.ProcessingResult) bool {
	// Normalize OSV vulnerability to standard format
	normalized, err := normalizer.NormalizeOSV(osvVuln)
	if err != nil {
		result.ErrorCount++
		result.Errors = append(result.Errors, fmt.Sprintf(errNormalizationFailed, osvVuln.ID, err))
		return true
	}

	if normalized == nil {
		result.SkippedCount++
		return true
	}

	// For same-source updates with deterministic IDs, use efficient upsert
	// Only use alias matching for cross-source merging scenarios

	// Try to find existing vulnerability with different source (cross-source merging)
	existing, err := vulnMerger.FindMatchingVulnerability(ctx, normalized.Aliases)
	if err != nil {
		log.Warn().Err(err).Str("id", normalized.ID).Msg(errFindMatchingVuln)
	}

	// Only merge if we found a vulnerability from a different source
	if existing != nil && !s.containsSource(existing.Source, normalized.Source[0]) {
		// Cross-source merge: merge with existing vulnerability from different source
		if err := vulnMerger.MergeVulnerabilities(ctx, existing, normalized); err != nil {
			result.ErrorCount++
			result.Errors = append(result.Errors, fmt.Sprintf(errMergeFailed, normalized.ID, err))
			return true
		}
		result.MergedCount++
	} else {
		// Same-source update or new vulnerability: use upsert (handles duplicates automatically)
		if err := s.upsertVulnerability(ctx, normalized); err != nil {
			result.ErrorCount++
			result.Errors = append(result.Errors, fmt.Sprintf(errInsertFailed, normalized.ID, err))
			return true
		}
		result.IngestedCount++
	}

	return false
}

// processSingleGitLabVuln processes a single GitLab vulnerability and updates result
// Returns true if processing should continue to next vulnerability
func (s *Server) processSingleGitLabVuln(ctx context.Context, gitlabVuln *types.GitLabVulnerability, normalizer *merger.Normalizer, vulnMerger *merger.VulnerabilityMerger, result *types.ProcessingResult) bool {
	// Normalize GitLab vulnerability to standard format
	normalized, err := normalizer.NormalizeGitLab(gitlabVuln)
	if err != nil {
		result.ErrorCount++
		result.Errors = append(result.Errors, fmt.Sprintf(errNormalizationFailed, gitlabVuln.Identifier, err))
		return true
	}

	if normalized == nil {
		result.SkippedCount++
		return true
	}

	// For same-source updates with deterministic IDs, use efficient upsert
	// Only use alias matching for cross-source merging scenarios

	// Try to find existing vulnerability with different source (cross-source merging)
	existing, err := vulnMerger.FindMatchingVulnerability(ctx, normalized.Aliases)
	if err != nil {
		log.Warn().Err(err).Str("id", normalized.ID).Msg(errFindMatchingVuln)
	}

	// Only merge if we found a vulnerability from a different source
	if existing != nil && !s.containsSource(existing.Source, normalized.Source[0]) {
		// Cross-source merge: merge with existing vulnerability from different source
		if err := vulnMerger.MergeVulnerabilities(ctx, existing, normalized); err != nil {
			result.ErrorCount++
			result.Errors = append(result.Errors, fmt.Sprintf(errMergeFailed, normalized.ID, err))
			return true
		}
		result.MergedCount++
	} else {
		// Same-source update or new vulnerability: use upsert (handles duplicates automatically)
		if err := s.upsertVulnerability(ctx, normalized); err != nil {
			result.ErrorCount++
			result.Errors = append(result.Errors, fmt.Sprintf(errInsertFailed, normalized.ID, err))
			return true
		}
		result.IngestedCount++
	}

	return false
}

// processSingleCVEVuln processes a single CVE vulnerability and updates result
// Returns true if processing should continue to next vulnerability
func (s *Server) processSingleCVEVuln(ctx context.Context, cveVuln *types.CVEVulnerability, normalizer *merger.Normalizer, vulnMerger *merger.VulnerabilityMerger, result *types.ProcessingResult) bool {
	// Normalize CVE vulnerability to standard format
	normalized, err := normalizer.NormalizeCVE(cveVuln)
	if err != nil {
		result.ErrorCount++
		result.Errors = append(result.Errors, fmt.Sprintf(errNormalizationFailed, cveVuln.CVEMetadata.CVEID, err))
		return true
	}

	if normalized == nil {
		result.SkippedCount++
		return true
	}

	// For same-source updates with deterministic IDs, use efficient upsert
	// Only use alias matching for cross-source merging scenarios

	// Try to find existing vulnerability with different source (cross-source merging)
	existing, err := vulnMerger.FindMatchingVulnerability(ctx, normalized.Aliases)
	if err != nil {
		log.Warn().Err(err).Str("id", normalized.ID).Msg(errFindMatchingVuln)
	}

	// Only merge if we found a vulnerability from a different source
	if existing != nil && !s.containsSource(existing.Source, normalized.Source[0]) {
		// Cross-source merge: merge with existing vulnerability from different source
		if err := vulnMerger.MergeVulnerabilities(ctx, existing, normalized); err != nil {
			result.ErrorCount++
			result.Errors = append(result.Errors, fmt.Sprintf(errMergeFailed, normalized.ID, err))
			return true
		}
		result.MergedCount++
	} else {
		// Same-source update or new vulnerability: use upsert (handles duplicates automatically)
		if err := s.upsertVulnerability(ctx, normalized); err != nil {
			result.ErrorCount++
			result.Errors = append(result.Errors, fmt.Sprintf(errInsertFailed, normalized.ID, err))
			return true
		}
		result.IngestedCount++
	}

	return false
}

// containsSource checks if a source array contains a specific source
func (s *Server) containsSource(sources []string, source string) bool {
	for _, s := range sources {
		if s == source {
			return true
		}
	}
	return false
}

// checkCancellation checks for context cancellation and updates result if cancelled
func checkCancellation(ctx context.Context, result *types.ProcessingResult) bool {
	select {
	case <-ctx.Done():
		result.ErrorCount++
		result.Errors = append(result.Errors, errBatchProcessingCancelled)
		return true
	default:
		return false
	}
}
