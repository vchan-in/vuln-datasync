package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config represents the application configuration
type Config struct {
	Server      ServerConfig      `json:"server"`
	Database    DatabaseConfig    `json:"database"`
	Redis       RedisConfig       `json:"redis"`
	Performance PerformanceConfig `json:"performance"`
	DataSources DataSourcesConfig `json:"data_sources"`
	Scheduling  SchedulingConfig  `json:"scheduling"`
}

// ServerConfig contains HTTP server configuration
type ServerConfig struct {
	Port int    `json:"port"`
	Host string `json:"host"`
}

// DatabaseConfig contains PostgreSQL configuration
type DatabaseConfig struct {
	DSN         string `json:"dsn"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Database    string `json:"database"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	SSLMode     string `json:"ssl_mode"`
	MaxConns    int    `json:"max_conns"`
	MinConns    int    `json:"min_conns"`
	MaxLifetime int    `json:"max_lifetime"`  // minutes
	MaxIdleTime int    `json:"max_idle_time"` // minutes
}

// RedisConfig contains Redis configuration
type RedisConfig struct {
	Addr     string `json:"addr"`
	Password string `json:"password"`
	DB       int    `json:"db"`
}

// PerformanceConfig contains performance tuning parameters
type PerformanceConfig struct {
	OSVWorkers    int `json:"osv_workers"`
	GitLabWorkers int `json:"gitlab_workers"`
	CVEWorkers    int `json:"cve_workers"`
	BatchSize     int `json:"batch_size"`
}

// DataSourcesConfig contains data source configurations
type DataSourcesConfig struct {
	OSVBucket     string `json:"osv_bucket"`
	GitLabRepoURL string `json:"gitlab_repo_url"`
	CVEProjectURL string `json:"cve_project_url"`
}

// SchedulingConfig contains scheduling configuration
type SchedulingConfig struct {
	SyncInterval   string `json:"sync_interval"`
	ExportInterval string `json:"export_interval"`
}

// Load loads configuration from environment variables
func Load() (*Config, error) {
	cfg := &Config{
		Server: ServerConfig{
			Port: getEnvInt("SERVER_PORT", 8080),
			Host: getEnv("SERVER_HOST", "0.0.0.0"),
		},
		Database: DatabaseConfig{
			DSN:         getEnv("DB_DSN", ""),
			Host:        getEnv("DB_HOST", "localhost"),
			Port:        getEnvInt("DB_PORT", 5432),
			Database:    getEnv("DB_NAME", "vulndb"),
			Username:    getEnv("DB_USER", "postgres"),
			Password:    getEnv("DB_PASSWORD", ""),
			SSLMode:     getEnv("DB_SSL_MODE", "disable"),
			MaxConns:    getEnvInt("DB_MAX_CONNS", 100),
			MinConns:    getEnvInt("DB_MIN_CONNS", 20),
			MaxLifetime: getEnvInt("DB_MAX_LIFETIME", 30),
			MaxIdleTime: getEnvInt("DB_MAX_IDLE_TIME", 5),
		},
		Redis: RedisConfig{
			Addr:     getEnv("REDIS_ADDR", "localhost:6379"),
			Password: getEnv("REDIS_PASSWORD", ""),
			DB:       getEnvInt("REDIS_DB", 0),
		},
		Performance: PerformanceConfig{
			OSVWorkers:    getEnvInt("OSV_WORKERS", 20),
			GitLabWorkers: getEnvInt("GITLAB_WORKERS", 10),
			CVEWorkers:    getEnvInt("CVE_WORKERS", 5),
			BatchSize:     getEnvInt("BATCH_SIZE", 1000),
		},
		DataSources: DataSourcesConfig{
			OSVBucket:     getEnv("OSV_BUCKET", "osv-vulnerabilities"),
			GitLabRepoURL: getEnv("GITLAB_REPO_URL", "https://gitlab.com/gitlab-org/security-products/gemnasium-db.git"),
			CVEProjectURL: getEnv("CVE_PROJECT_URL", "https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip"),
		},
		Scheduling: SchedulingConfig{
			SyncInterval:   getEnv("SYNC_INTERVAL", "@daily"),
			ExportInterval: getEnv("EXPORT_INTERVAL", "@weekly"),
		},
	}

	// Build DSN if not provided directly
	if cfg.Database.DSN == "" {
		cfg.Database.DSN = buildDSN(cfg.Database)
	}

	// Validate required configuration
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return cfg, nil
}

// validate validates the configuration
func (c *Config) validate() error {
	if c.Database.DSN == "" {
		return fmt.Errorf("database DSN is required")
	}

	if c.Redis.Addr == "" {
		return fmt.Errorf("Redis address is required")
	}

	if c.Performance.OSVWorkers <= 0 {
		return fmt.Errorf("OSV workers must be greater than 0")
	}

	if c.Performance.BatchSize <= 0 {
		return fmt.Errorf("batch size must be greater than 0")
	}

	return nil
}

// buildDSN builds a PostgreSQL DSN from individual components
func buildDSN(db DatabaseConfig) string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		db.Host, db.Port, db.Username, db.Password, db.Database, db.SSLMode,
	)
}

// getEnv returns the value of an environment variable or a default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvInt returns an environment variable as an integer or a default value
func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

// GetDataSourcesFromEnv returns enabled data sources from environment
func GetDataSourcesFromEnv() []string {
	sources := getEnv("ENABLED_SOURCES", "osv,gitlab,cve")
	if sources == "" {
		return []string{"osv", "gitlab", "cve"}
	}

	result := make([]string, 0)
	for _, source := range strings.Split(sources, ",") {
		trimmed := strings.TrimSpace(source)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}

	return result
}
