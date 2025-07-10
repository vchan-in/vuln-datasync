package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hibiken/asynq"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/vchan-in/vuln-datasync/internal/api"
	"github.com/vchan-in/vuln-datasync/internal/config"
	"github.com/vchan-in/vuln-datasync/internal/database"
	"github.com/vchan-in/vuln-datasync/internal/jobs"
)

func main() {
	// Configure structured logging
	setupLogging()

	log.Info().Msg("starting vulnerability data synchronization system")

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load configuration")
	}

	log.Info().
		Str("db_host", cfg.Database.Host).
		Str("redis_addr", cfg.Redis.Addr).
		Int("osv_workers", cfg.Performance.OSVWorkers).
		Msg("configuration loaded")

	// Initialize database
	db, err := database.New(cfg.Database)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialize database")
	}
	defer db.Close()

	log.Info().Msg("database connection established")

	// Initialize Asynq client for job creation
	asynqClient := asynq.NewClient(asynq.RedisClientOpt{
		Addr:     cfg.Redis.Addr,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	})
	defer func() {
		if err := asynqClient.Close(); err != nil {
			log.Warn().Err(err).Msg("failed to close asynq client")
		}
	}()

	// Initialize background job server
	jobServer, err := jobs.NewServer(cfg, db)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialize job server")
	}

	// Start background job processing
	go func() {
		log.Info().Msg("starting background job server")
		if err := jobServer.Start(); err != nil {
			log.Fatal().Err(err).Msg("background job server failed")
		}
	}()

	// Give the job server a moment to initialize
	time.Sleep(2 * time.Second)
	log.Info().Msg("job server initialization complete")

	// Initialize HTTP API
	apiServer := api.NewServer(cfg, db, asynqClient)
	httpServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:      apiServer.Router(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start HTTP server
	go func() {
		log.Info().
			Int("port", cfg.Server.Port).
			Msg("starting HTTP server")

		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("HTTP server failed")
		}
	}()

	log.Info().Msg("vulnerability data synchronization system started successfully")

	// Wait for shutdown signal
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)
	<-shutdown

	log.Info().Msg("shutdown signal received, starting graceful shutdown")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown HTTP server
	if err := httpServer.Shutdown(ctx); err != nil {
		log.Error().Err(err).Msg("HTTP server shutdown failed")
	}

	// Shutdown background job server
	jobServer.Stop()

	log.Info().Msg("vulnerability data synchronization system stopped")
}

func setupLogging() {
	// Configure zerolog for human-readable output in development
	if os.Getenv("ENVIRONMENT") != "production" {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	}

	// Set log level from environment
	logLevel := zerolog.InfoLevel
	if level := os.Getenv("LOG_LEVEL"); level != "" {
		if parsedLevel, err := zerolog.ParseLevel(level); err == nil {
			logLevel = parsedLevel
		}
	}
	zerolog.SetGlobalLevel(logLevel)

	log.Info().
		Str("level", logLevel.String()).
		Msg("logging configured")
}
