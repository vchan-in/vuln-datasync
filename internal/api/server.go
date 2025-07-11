package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/hibiken/asynq"
	"github.com/rs/zerolog/log"
	"github.com/vchan-in/vuln-datasync/internal/config"
	"github.com/vchan-in/vuln-datasync/internal/database"
	db "github.com/vchan-in/vuln-datasync/internal/database/generated"
	"github.com/vchan-in/vuln-datasync/internal/types"
)

// Server represents the HTTP API server
type Server struct {
	config      *config.Config
	db          *database.Service
	asynqClient *asynq.Client
	router      *mux.Router
}

// NewServer creates a new API server
func NewServer(cfg *config.Config, db *database.Service, asynqClient *asynq.Client) *Server {
	s := &Server{
		config:      cfg,
		db:          db,
		asynqClient: asynqClient,
		router:      mux.NewRouter(),
	}

	s.setupRoutes()
	return s
}

// Router returns the configured router
func (s *Server) Router() *mux.Router {
	return s.router
}

// setupRoutes configures all API routes
func (s *Server) setupRoutes() {
	// Add logging middleware
	s.router.Use(s.loggingMiddleware)
	s.router.Use(s.corsMiddleware)

	// Health check endpoint
	s.router.HandleFunc("/health", s.handleHealth).Methods("GET")
	s.router.HandleFunc("/metrics", s.handleMetrics).Methods("GET")

	// API versioned routes
	api := s.router.PathPrefix("/api/v1").Subrouter()

	// Sync endpoints
	api.HandleFunc("/sync", s.handleSync).Methods("POST")
	api.HandleFunc("/sync/status", s.handleSyncStatus).Methods("GET")

	// Job management
	api.HandleFunc("/jobs/status", s.handleJobStatus).Methods("GET")
	api.HandleFunc("/jobs/{id}", s.handleJobDetails).Methods("GET")

	// Export endpoints
	api.HandleFunc("/export", s.handleExport).Methods("POST")
	api.HandleFunc("/exports", s.handleListExports).Methods("GET")

	// Statistics
	api.HandleFunc("/stats", s.handleStats).Methods("GET")
}

// handleHealth returns system health status
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	health := &types.HealthStatus{
		Status:    "healthy",
		Timestamp: time.Now(),
		Checks:    make(map[string]types.CheckResult),
	}

	// Check database
	dbStart := time.Now()
	dbErr := s.db.Health(ctx)
	health.Checks["database"] = types.CheckResult{
		Status:  statusFromError(dbErr),
		Message: messageFromError(dbErr),
		Latency: time.Since(dbStart),
	}

	// Overall status
	if dbErr != nil {
		health.Status = "unhealthy"
	}

	w.Header().Set("Content-Type", "application/json")

	statusCode := http.StatusOK
	if health.Status != "healthy" {
		statusCode = http.StatusServiceUnavailable
	}

	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(health); err != nil {
		log.Error().Err(err).Msg("failed to encode health response")
	}
}

// handleMetrics returns system metrics
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get vulnerability statistics
	var vulnStats struct {
		Total       int64            `json:"total"`
		BySource    map[string]int64 `json:"by_source"`
		ByEcosystem map[string]int64 `json:"by_ecosystem"`
	}

	// Query total vulnerabilities using SQLC
	queries := db.New(s.db.Pool())
	var err error
	vulnStats.Total, err = queries.CountVulnerabilities(ctx)
	if err != nil {
		log.Error().Err(err).Msg("failed to get total vulnerability count")
	}

	// Get database stats
	dbStats := s.db.Stats()

	metrics := &types.MetricsData{
		VulnerabilitiesTotal:    vulnStats.Total,
		VulnerabilitiesBySource: vulnStats.BySource,
		SystemStats: types.SystemStats{
			DatabaseConnections: dbStats.AcquiredConns(),
		},
		Timestamp: time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(metrics); err != nil {
		log.Error().Err(err).Msg("failed to encode metrics response")
	}
}

// handleSync triggers vulnerability synchronization
func (s *Server) handleSync(w http.ResponseWriter, r *http.Request) {
	var req types.SyncRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Default sources if not specified
	if len(req.Sources) == 0 {
		req.Sources = []string{"osv", "gitlab", "cve"}
	}

	log.Info().
		Strs("sources", req.Sources).
		Bool("async", req.Async).
		Msg("sync request received")

	if req.Async {
		// Queue background job
		payload := map[string]interface{}{
			"sources":    req.Sources,
			"ecosystems": req.Ecosystems,
		}

		payloadBytes, _ := json.Marshal(payload)
		task := asynq.NewTask("sync:vulnerabilities", payloadBytes)

		// Enqueue to the default queue with retry options
		opts := []asynq.Option{
			asynq.Queue("default"),
			asynq.MaxRetry(3),
			asynq.Timeout(30 * time.Minute),
		}

		info, err := s.asynqClient.Enqueue(task, opts...)
		if err != nil {
			log.Error().Err(err).Msg("failed to enqueue sync job")
			http.Error(w, "Failed to queue sync job", http.StatusInternalServerError)
			return
		}

		response := &types.SyncResponse{
			Status:  "accepted",
			JobID:   info.ID,
			Message: "Sync job queued successfully",
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Error().Err(err).Msg("failed to encode sync response")
		}
	} else {
		// Synchronous processing (not implemented yet)
		response := &types.SyncResponse{
			Status:  "error",
			Message: "Synchronous sync not implemented yet",
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotImplemented)
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Error().Err(err).Msg("failed to encode sync response")
		}
	}
}

// handleSyncStatus returns current sync status
func (s *Server) handleSyncStatus(w http.ResponseWriter, r *http.Request) {
	// This would query recent processing stats
	status := map[string]interface{}{
		"status":    "idle",
		"last_sync": time.Now().Add(-1 * time.Hour), // Mock data
		"message":   "No active sync operations",
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(status); err != nil {
		log.Error().Err(err).Msg("failed to encode status response")
	}
}

// handleJobStatus returns job queue status
func (s *Server) handleJobStatus(w http.ResponseWriter, r *http.Request) {
	// This would query Asynq for job statistics
	status := map[string]interface{}{
		"active_jobs":    0,
		"pending_jobs":   0,
		"failed_jobs":    0,
		"completed_jobs": 0,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(status); err != nil {
		log.Error().Err(err).Msg("failed to encode job status response")
	}
}

// handleJobDetails returns details for a specific job
func (s *Server) handleJobDetails(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	jobID := vars["id"]

	// This would query job details from Asynq
	jobDetails := map[string]interface{}{
		"id":      jobID,
		"status":  "not_found",
		"message": "Job not found or not implemented",
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(jobDetails); err != nil {
		log.Error().Err(err).Msg("failed to encode job details response")
	}
}

// handleExport triggers database export
func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	var req map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Queue export job
	response := map[string]interface{}{
		"status":  "accepted",
		"message": "Export job queued (not implemented)",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Error().Err(err).Msg("failed to encode export response")
	}
}

// handleListExports returns list of exports
func (s *Server) handleListExports(w http.ResponseWriter, r *http.Request) {
	exports := []map[string]interface{}{
		{
			"version":    "2025-07-10",
			"created_at": time.Now(),
			"status":     "completed",
			"size":       "1.2GB",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(exports); err != nil {
		log.Error().Err(err).Msg("failed to encode exports response")
	}
}

// handleStats returns system statistics
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get basic vulnerability count using SQLC
	queries := db.New(s.db.Pool())
	totalCount, err := queries.CountVulnerabilities(ctx)
	if err != nil {
		log.Error().Err(err).Msg("failed to get vulnerability count")
	}

	stats := map[string]interface{}{
		"vulnerabilities_total": totalCount,
		"last_updated":          time.Now(),
		"status":                "active",
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(stats); err != nil {
		log.Error().Err(err).Msg("failed to encode stats response")
	}
}

// loggingMiddleware logs HTTP requests
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap the response writer to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(wrapped, r)

		log.Info().
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Str("remote_addr", r.RemoteAddr).
			Int("status_code", wrapped.statusCode).
			Dur("duration", time.Since(start)).
			Msg("HTTP request")
	})
}

// corsMiddleware adds CORS headers
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Helper functions
func statusFromError(err error) string {
	if err != nil {
		return "unhealthy"
	}
	return "healthy"
}

func messageFromError(err error) string {
	if err != nil {
		return err.Error()
	}
	return "OK"
}
