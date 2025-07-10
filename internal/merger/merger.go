package merger

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/yourusername/vuln-datasync/internal/database"
	"github.com/yourusername/vuln-datasync/internal/types"
)

// Source type constants for priority-based merging
const (
	SourceOSV    = "osv"
	SourceGitLab = "gitlab"
	SourceCVE    = "cve"
)

// Source priority levels (lower number = higher priority)
const (
	PriorityOSV    = 1 // Highest: Comprehensive, well-structured
	PriorityGitLab = 2 // Medium: Curated advisories
	PriorityCVE    = 3 // Lowest: Raw vulnerability data
)

// VulnerabilityMerger handles merging vulnerability data from different sources
type VulnerabilityMerger struct {
	db         *database.Service
	aliasCache map[string]string // alias -> vulnerability_id mapping
}

// NewVulnerabilityMerger creates a new vulnerability merger
func NewVulnerabilityMerger(db *database.Service) *VulnerabilityMerger {
	return &VulnerabilityMerger{
		db:         db,
		aliasCache: make(map[string]string),
	}
}

// LoadAliasCache loads all vulnerability aliases into memory for fast lookup
func (m *VulnerabilityMerger) LoadAliasCache(ctx context.Context) error {
	start := time.Now()

	// Query to get all aliases and their vulnerability IDs
	query := `
		SELECT id, unnest(aliases) as alias 
		FROM vulnerabilities 
		WHERE aliases IS NOT NULL AND array_length(aliases, 1) > 0
	`

	rows, err := m.db.Pool().Query(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to query vulnerability aliases: %w", err)
	}
	defer rows.Close()

	aliasCount := 0
	for rows.Next() {
		var vulnID, alias string
		if err := rows.Scan(&vulnID, &alias); err != nil {
			log.Error().Err(err).Msg("failed to scan alias row")
			continue
		}

		m.aliasCache[alias] = vulnID
		aliasCount++
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating alias rows: %w", err)
	}

	log.Info().
		Int("cached_aliases", aliasCount).
		Dur("load_time", time.Since(start)).
		Msg("vulnerability alias cache loaded")

	return nil
}

// FindMatchingVulnerability finds an existing vulnerability with matching aliases
func (m *VulnerabilityMerger) FindMatchingVulnerability(ctx context.Context, aliases []string) (*types.Vulnerability, error) {
	if len(aliases) == 0 {
		return nil, nil
	}

	// Check cache first for performance
	for _, alias := range aliases {
		if vulnID, exists := m.aliasCache[alias]; exists {
			return m.getVulnerabilityByID(ctx, vulnID)
		}
	}

	// Fallback to database query if not in cache
	query := `
		SELECT id, summary, details, severity, published_at, modified_at, 
		       ecosystem, package_name, affected_versions, fixed_versions, 
		       aliases, refs, source, raw, data_hash, created_at, updated_at
		FROM vulnerabilities 
		WHERE aliases && $1
		ORDER BY 
			CASE 
				WHEN 'osv' = ANY(source) THEN 1
				WHEN 'gitlab' = ANY(source) THEN 2  
				WHEN 'cve' = ANY(source) THEN 3
				ELSE 4
			END
		LIMIT 1
	`

	row := m.db.Pool().QueryRow(ctx, query, aliases)

	vuln := &types.Vulnerability{}
	var refsJSON, rawJSON, sourceJSON []byte

	err := row.Scan(
		&vuln.ID, &vuln.Summary, &vuln.Details, &vuln.Severity,
		&vuln.PublishedAt, &vuln.ModifiedAt, &vuln.Ecosystem, &vuln.PackageName,
		&vuln.AffectedVersions, &vuln.FixedVersions, &vuln.Aliases,
		&refsJSON, &sourceJSON, &rawJSON, &vuln.DataHash,
		&vuln.CreatedAt, &vuln.UpdatedAt,
	)

	if err != nil {
		if err.Error() == "no rows in result set" {
			return nil, nil // No match found
		}
		return nil, fmt.Errorf("failed to query vulnerability: %w", err)
	}

	// Unmarshal JSON fields
	if err := json.Unmarshal(refsJSON, &vuln.References); err != nil {
		log.Error().Err(err).Msg("failed to unmarshal references")
	}
	if err := json.Unmarshal(rawJSON, &vuln.RawData); err != nil {
		log.Error().Err(err).Msg("failed to unmarshal raw data")
	}
	if err := json.Unmarshal(sourceJSON, &vuln.Source); err != nil {
		log.Error().Err(err).Msg("failed to unmarshal source")
	}

	return vuln, nil
}

// MergeVulnerabilities merges new vulnerability data with existing vulnerability
func (m *VulnerabilityMerger) MergeVulnerabilities(ctx context.Context, existing *types.Vulnerability, new *types.Vulnerability) error {
	newPriority := getSourcePriority(new.Source)
	existingPriority := getSourcePriority(existing.Source)

	log.Info().
		Str("existing_id", existing.ID).
		Str("new_source", fmt.Sprintf("%v", new.Source)).
		Str("existing_source", fmt.Sprintf("%v", existing.Source)).
		Int("new_priority", newPriority).
		Int("existing_priority", existingPriority).
		Msg("merging vulnerability data")

	// Determine merge strategy based on source priority
	var mergedVuln *types.Vulnerability

	if newPriority < existingPriority {
		// New source has higher priority, use it as base
		mergedVuln = mergWithPriority(new, existing)
	} else if newPriority > existingPriority {
		// Existing source has higher priority, preserve it
		mergedVuln = mergWithPriority(existing, new)
	} else {
		// Same priority, merge preserving existing as base
		mergedVuln = mergWithPriority(existing, new)
	}

	// Update merged source tracking
	mergedVuln.Source = mergeSourceArrays(existing.Source, new.Source)
	mergedVuln.UpdatedAt = time.Now()

	// Update in database
	return m.updateVulnerability(ctx, mergedVuln)
}

// mergWithPriority merges two vulnerabilities with priority-based field selection
func mergWithPriority(primary, secondary *types.Vulnerability) *types.Vulnerability {
	merged := &types.Vulnerability{
		ID:        primary.ID, // Always keep the primary ID
		CreatedAt: primary.CreatedAt,
		UpdatedAt: time.Now(),
	}

	// Use primary data as base, supplement with secondary data where missing
	merged.Summary = selectString(primary.Summary, secondary.Summary)
	merged.Details = selectString(primary.Details, secondary.Details)
	merged.Severity = selectString(primary.Severity, secondary.Severity)
	merged.Ecosystem = selectString(primary.Ecosystem, secondary.Ecosystem)
	merged.PackageName = selectString(primary.PackageName, secondary.PackageName)

	// Use primary timestamps, fallback to secondary
	merged.PublishedAt = selectTime(primary.PublishedAt, secondary.PublishedAt)
	merged.ModifiedAt = selectTime(primary.ModifiedAt, secondary.ModifiedAt)

	// Merge arrays (combining and deduplicating)
	merged.Aliases = mergeStringArrays(primary.Aliases, secondary.Aliases)
	merged.AffectedVersions = mergeStringArrays(primary.AffectedVersions, secondary.AffectedVersions)
	merged.FixedVersions = mergeStringArrays(primary.FixedVersions, secondary.FixedVersions)

	// Merge references and raw data
	merged.References = mergeMapData(primary.References, secondary.References)
	merged.RawData = mergeRawData(primary.RawData, secondary.RawData)

	// Calculate new data hash
	merged.DataHash = calculateDataHash(merged.RawData)

	return merged
}

// getSourcePriority returns the priority of a source array (lower = higher priority)
func getSourcePriority(sources []string) int {
	if containsSource(sources, SourceOSV) {
		return PriorityOSV
	}
	if containsSource(sources, SourceGitLab) {
		return PriorityGitLab
	}
	if containsSource(sources, SourceCVE) {
		return PriorityCVE
	}
	return 999 // Unknown source, lowest priority
}

// containsSource checks if a source array contains a specific source
func containsSource(sources []string, source string) bool {
	for _, s := range sources {
		if s == source {
			return true
		}
	}
	return false
}

// mergeSourceArrays combines two source arrays without duplicates
func mergeSourceArrays(existing, new []string) []string {
	sourceSet := make(map[string]bool)

	// Add existing sources
	for _, source := range existing {
		sourceSet[source] = true
	}

	// Add new sources
	for _, source := range new {
		sourceSet[source] = true
	}

	// Convert back to slice
	result := make([]string, 0, len(sourceSet))
	for source := range sourceSet {
		result = append(result, source)
	}

	return result
}

// mergeStringArrays combines two string arrays without duplicates
func mergeStringArrays(primary, secondary []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0)

	// Add primary items first
	for _, item := range primary {
		if !seen[item] {
			result = append(result, item)
			seen[item] = true
		}
	}

	// Add secondary items if not already present
	for _, item := range secondary {
		if !seen[item] {
			result = append(result, item)
			seen[item] = true
		}
	}

	return result
}

// mergeMapData merges two map[string]interface{} with primary taking precedence
func mergeMapData(primary, secondary map[string]interface{}) map[string]interface{} {
	if primary == nil && secondary == nil {
		return nil
	}
	if primary == nil {
		return secondary
	}
	if secondary == nil {
		return primary
	}

	result := make(map[string]interface{})

	// Copy secondary data first
	for k, v := range secondary {
		result[k] = v
	}

	// Override with primary data
	for k, v := range primary {
		result[k] = v
	}

	return result
}

// mergeRawData merges raw data preserving both sources
func mergeRawData(primary, secondary map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})

	if secondary != nil {
		result["secondary_source"] = secondary
	}
	if primary != nil {
		result["primary_source"] = primary
	}

	return result
}

// selectString returns the first non-empty string
func selectString(primary, secondary string) string {
	if primary != "" {
		return primary
	}
	return secondary
}

// selectTime returns the first non-zero time
func selectTime(primary, secondary time.Time) time.Time {
	if !primary.IsZero() {
		return primary
	}
	return secondary
}

// calculateDataHash calculates a hash for the vulnerability data
func calculateDataHash(data map[string]interface{}) string {
	// Simplified hash calculation - in production, use the learnings from ossdeps
	if data == nil {
		return ""
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return ""
	}

	// Return a simple hash representation
	return fmt.Sprintf("%x", len(jsonData))
}

// getVulnerabilityByID retrieves a vulnerability by ID
func (m *VulnerabilityMerger) getVulnerabilityByID(ctx context.Context, id string) (*types.Vulnerability, error) {
	query := `
		SELECT id, summary, details, severity, published_at, modified_at, 
		       ecosystem, package_name, affected_versions, fixed_versions, 
		       aliases, refs, source, raw, data_hash, created_at, updated_at
		FROM vulnerabilities 
		WHERE id = $1
	`

	row := m.db.Pool().QueryRow(ctx, query, id)

	vuln := &types.Vulnerability{}
	var refsJSON, rawJSON, sourceJSON []byte

	err := row.Scan(
		&vuln.ID, &vuln.Summary, &vuln.Details, &vuln.Severity,
		&vuln.PublishedAt, &vuln.ModifiedAt, &vuln.Ecosystem, &vuln.PackageName,
		&vuln.AffectedVersions, &vuln.FixedVersions, &vuln.Aliases,
		&refsJSON, &sourceJSON, &rawJSON, &vuln.DataHash,
		&vuln.CreatedAt, &vuln.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to get vulnerability by ID: %w", err)
	}

	// Unmarshal JSON fields
	if err := json.Unmarshal(refsJSON, &vuln.References); err != nil {
		log.Error().Err(err).Msg("failed to unmarshal references")
	}
	if err := json.Unmarshal(rawJSON, &vuln.RawData); err != nil {
		log.Error().Err(err).Msg("failed to unmarshal raw data")
	}
	if err := json.Unmarshal(sourceJSON, &vuln.Source); err != nil {
		log.Error().Err(err).Msg("failed to unmarshal source")
	}

	return vuln, nil
}

// updateVulnerability updates a vulnerability in the database
func (m *VulnerabilityMerger) updateVulnerability(ctx context.Context, vuln *types.Vulnerability) error {
	// Marshal JSON fields
	refsJSON, err := json.Marshal(vuln.References)
	if err != nil {
		return fmt.Errorf("failed to marshal references: %w", err)
	}

	rawJSON, err := json.Marshal(vuln.RawData)
	if err != nil {
		return fmt.Errorf("failed to marshal raw data: %w", err)
	}

	sourceJSON, err := json.Marshal(vuln.Source)
	if err != nil {
		return fmt.Errorf("failed to marshal source: %w", err)
	}

	query := `
		UPDATE vulnerabilities SET
			summary = $2, details = $3, severity = $4, published_at = $5, 
			modified_at = $6, ecosystem = $7, package_name = $8, 
			affected_versions = $9, fixed_versions = $10, aliases = $11, 
			refs = $12, source = $13, raw = $14, data_hash = $15, updated_at = $16
		WHERE id = $1
	`

	_, err = m.db.Pool().Exec(ctx, query,
		vuln.ID, vuln.Summary, vuln.Details, vuln.Severity,
		vuln.PublishedAt, vuln.ModifiedAt, vuln.Ecosystem, vuln.PackageName,
		vuln.AffectedVersions, vuln.FixedVersions, vuln.Aliases,
		refsJSON, sourceJSON, rawJSON, vuln.DataHash, vuln.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to update vulnerability: %w", err)
	}

	// Update alias cache
	for _, alias := range vuln.Aliases {
		m.aliasCache[alias] = vuln.ID
	}

	log.Info().
		Str("vulnerability_id", vuln.ID).
		Strs("source", vuln.Source).
		Int("aliases_count", len(vuln.Aliases)).
		Msg("vulnerability updated successfully")

	return nil
}
