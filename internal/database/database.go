package database

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
	"github.com/yourusername/vuln-datasync/internal/config"
)

// Service represents the database service
type Service struct {
	pool *pgxpool.Pool
}

// New creates a new database service
func New(cfg config.DatabaseConfig) (*Service, error) {
	// Configure connection pool
	poolConfig, err := pgxpool.ParseConfig(cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("failed to parse database DSN: %w", err)
	}

	// Set pool configuration based on config with bounds checking
	// Prevent integer overflow when converting to int32
	if cfg.MaxConns > 2147483647 || cfg.MaxConns < 0 {
		return nil, fmt.Errorf("MaxConns value %d is out of valid range (0-2147483647)", cfg.MaxConns)
	}
	if cfg.MinConns > 2147483647 || cfg.MinConns < 0 {
		return nil, fmt.Errorf("MinConns value %d is out of valid range (0-2147483647)", cfg.MinConns)
	}

	poolConfig.MaxConns = int32(cfg.MaxConns) // #nosec G115 -- Integer overflow protection is implemented above
	poolConfig.MinConns = int32(cfg.MinConns) // #nosec G115 -- Integer overflow protection is implemented above
	poolConfig.MaxConnLifetime = time.Duration(cfg.MaxLifetime) * time.Minute
	poolConfig.MaxConnIdleTime = time.Duration(cfg.MaxIdleTime) * time.Minute
	poolConfig.HealthCheckPeriod = 1 * time.Minute

	// Create connection pool
	pool, err := pgxpool.NewWithConfig(context.Background(), poolConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create database pool: %w", err)
	}

	// Test the connection
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	log.Info().
		Int32("max_conns", poolConfig.MaxConns).
		Int32("min_conns", poolConfig.MinConns).
		Msg("database connection pool initialized")

	return &Service{
		pool: pool,
	}, nil
}

// Close closes the database connection pool
func (s *Service) Close() {
	if s.pool != nil {
		s.pool.Close()
		log.Info().Msg("database connection pool closed")
	}
}

// Pool returns the underlying connection pool
func (s *Service) Pool() *pgxpool.Pool {
	return s.pool
}

// Health checks the database health
func (s *Service) Health(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	return s.pool.Ping(ctx)
}

// Stats returns database pool statistics
func (s *Service) Stats() *pgxpool.Stat {
	return s.pool.Stat()
}
