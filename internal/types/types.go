package types

import (
	"time"
)

// Vulnerability represents a normalized vulnerability record
type Vulnerability struct {
	ID               string                 `json:"id" db:"id"`
	Summary          string                 `json:"summary" db:"summary"`
	Details          string                 `json:"details" db:"details"`
	Severity         string                 `json:"severity" db:"severity"`
	PublishedAt      time.Time              `json:"published_at" db:"published_at"`
	ModifiedAt       time.Time              `json:"modified_at" db:"modified_at"`
	Ecosystem        string                 `json:"ecosystem" db:"ecosystem"`
	PackageName      string                 `json:"package_name" db:"package_name"`
	AffectedVersions []string               `json:"affected_versions" db:"affected_versions"`
	FixedVersions    []string               `json:"fixed_versions" db:"fixed_versions"`
	Aliases          []string               `json:"aliases" db:"aliases"`
	References       map[string]interface{} `json:"references" db:"refs"`
	Source           []string               `json:"source" db:"source"`
	RawData          map[string]interface{} `json:"raw_data" db:"raw"`
	DataHash         string                 `json:"data_hash" db:"data_hash"`
	CreatedAt        time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time              `json:"updated_at" db:"updated_at"`
}

// OSVVulnerability represents vulnerability data in OSV format
type OSVVulnerability struct {
	ID               string                 `json:"id"`
	Summary          string                 `json:"summary,omitempty"`
	Details          string                 `json:"details,omitempty"`
	Aliases          []string               `json:"aliases,omitempty"`
	Modified         string                 `json:"modified"`
	Published        string                 `json:"published,omitempty"`
	References       []Reference            `json:"references,omitempty"`
	Affected         []Affected             `json:"affected,omitempty"`
	Severity         []Severity             `json:"severity,omitempty"`
	DatabaseSpecific map[string]interface{} `json:"database_specific,omitempty"`
}

// Reference represents a vulnerability reference
type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// Affected represents affected package information
type Affected struct {
	Package           Package                `json:"package"`
	Ranges            []Range                `json:"ranges,omitempty"`
	Versions          []string               `json:"versions,omitempty"`
	DatabaseSpecific  map[string]interface{} `json:"database_specific,omitempty"`
	EcosystemSpecific map[string]interface{} `json:"ecosystem_specific,omitempty"`
}

// Package represents package information
type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

// Range represents a version range
type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

// Event represents a range event
type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

// Severity represents severity information
type Severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// GitLabVulnerability represents vulnerability data in GitLab format
type GitLabVulnerability struct {
	Identifier       string   `yaml:"identifier" json:"identifier"`
	Title            string   `yaml:"title" json:"title"`
	Description      string   `yaml:"description" json:"description"`
	CVE              string   `yaml:"cve" json:"cve,omitempty"`
	UUID             string   `yaml:"uuid" json:"uuid,omitempty"`
	CVSS             string   `yaml:"cvss" json:"cvss,omitempty"`
	PublishedDate    string   `yaml:"published_date" json:"published_date,omitempty"`
	ModifiedDate     string   `yaml:"modified_date" json:"modified_date,omitempty"`
	PackageSlug      string   `yaml:"package_slug" json:"package_slug"`
	AffectedRange    string   `yaml:"affected_range" json:"affected_range,omitempty"`
	FixedVersions    []string `yaml:"fixed_versions" json:"fixed_versions,omitempty"`
	AffectedVersions []string `yaml:"affected_versions" json:"affected_versions,omitempty"`
	NotImpacted      string   `yaml:"not_impacted" json:"not_impacted,omitempty"`
	Solution         string   `yaml:"solution" json:"solution,omitempty"`
	URLs             []string `yaml:"urls" json:"urls,omitempty"`
	Credit           []string `yaml:"credit" json:"credit,omitempty"`
}

// CVEVulnerability represents vulnerability data in CVE format
type CVEVulnerability struct {
	DataType    string    `json:"dataType"`
	DataVersion string    `json:"dataVersion"`
	CVEMetadata CVEMeta   `json:"cveMetadata"`
	Containers  Container `json:"containers"`
}

// CVEMeta represents CVE metadata
type CVEMeta struct {
	CVEID         string `json:"cveId"`
	AssignerOrgId string `json:"assignerOrgId"`
	State         string `json:"state"`
	DateUpdated   string `json:"dateUpdated,omitempty"`
	DatePublished string `json:"datePublished,omitempty"`
}

// Container represents CVE container data
type Container struct {
	CNA CVEData `json:"cna"`
}

// CVEData represents the main CVE data
type CVEData struct {
	Descriptions []Description            `json:"descriptions"`
	References   []CVEReference           `json:"references,omitempty"`
	Metrics      []map[string]interface{} `json:"metrics,omitempty"`
	Affected     []CVEAffected            `json:"affected,omitempty"`
}

// Description represents a CVE description
type Description struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

// CVEReference represents a CVE reference
type CVEReference struct {
	URL  string   `json:"url"`
	Tags []string `json:"tags,omitempty"`
}

// CVEAffected represents affected products in CVE format
type CVEAffected struct {
	Vendor   string       `json:"vendor,omitempty"`
	Product  string       `json:"product,omitempty"`
	Versions []CVEVersion `json:"versions,omitempty"`
}

// CVEVersion represents version information in CVE format
type CVEVersion struct {
	Version         string `json:"version"`
	Status          string `json:"status"`
	VersionType     string `json:"versionType,omitempty"`
	LessThan        string `json:"lessThan,omitempty"`
	LessThanOrEqual string `json:"lessThanOrEqual,omitempty"`
}

// ProcessingResult represents the result of processing vulnerabilities
type ProcessingResult struct {
	Source         string    `json:"source"`
	ProcessedCount int       `json:"processed_count"`
	IngestedCount  int       `json:"ingested_count"`
	UpdatedCount   int       `json:"updated_count"`
	MergedCount    int       `json:"merged_count"`
	SkippedCount   int       `json:"skipped_count"`
	ErrorCount     int       `json:"error_count"`
	Errors         []string  `json:"errors,omitempty"`
	StartTime      time.Time `json:"start_time"`
	EndTime        time.Time `json:"end_time"`
	Duration       string    `json:"duration"`
}

// JobStatus represents the status of a background job
type JobStatus struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Payload     map[string]interface{} `json:"payload"`
	State       string                 `json:"state"`
	Queue       string                 `json:"queue"`
	CreatedAt   time.Time              `json:"created_at"`
	ProcessedAt *time.Time             `json:"processed_at,omitempty"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
	Error       string                 `json:"error,omitempty"`
	Retried     int                    `json:"retried"`
	MaxRetry    int                    `json:"max_retry"`
}

// SyncRequest represents a sync request
type SyncRequest struct {
	Sources    []string `json:"sources"`
	Ecosystems []string `json:"ecosystems,omitempty"`
	Async      bool     `json:"async"`
}

// SyncResponse represents a sync response
type SyncResponse struct {
	Status  string             `json:"status"`
	JobID   string             `json:"job_id,omitempty"`
	Results []ProcessingResult `json:"results,omitempty"`
	Message string             `json:"message"`
}

// HealthStatus represents system health status
type HealthStatus struct {
	Status    string                 `json:"status"`
	Timestamp time.Time              `json:"timestamp"`
	Checks    map[string]CheckResult `json:"checks"`
}

// CheckResult represents a health check result
type CheckResult struct {
	Status  string        `json:"status"`
	Message string        `json:"message,omitempty"`
	Latency time.Duration `json:"latency,omitempty"`
}

// MetricsData represents system metrics
type MetricsData struct {
	VulnerabilitiesTotal    int64            `json:"vulnerabilities_total"`
	VulnerabilitiesBySource map[string]int64 `json:"vulnerabilities_by_source"`
	ProcessingStats         ProcessingStats  `json:"processing_stats"`
	SystemStats             SystemStats      `json:"system_stats"`
	Timestamp               time.Time        `json:"timestamp"`
}

// ProcessingStats represents processing statistics
type ProcessingStats struct {
	LastSyncTime     *time.Time `json:"last_sync_time"`
	TotalProcessed   int64      `json:"total_processed"`
	TotalMerged      int64      `json:"total_merged"`
	ProcessingErrors int64      `json:"processing_errors"`
}

// SystemStats represents system statistics
type SystemStats struct {
	DatabaseConnections int32         `json:"database_connections"`
	QueueDepth          int           `json:"queue_depth"`
	CacheHitRate        float64       `json:"cache_hit_rate"`
	Uptime              time.Duration `json:"uptime"`
}
