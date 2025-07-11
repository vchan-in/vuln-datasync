package merger

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog/log"
	"github.com/vchan-in/vuln-datasync/internal/database"
	db "github.com/vchan-in/vuln-datasync/internal/database/generated"
	"github.com/vchan-in/vuln-datasync/internal/types"
	"github.com/vchan-in/vuln-datasync/internal/utils"
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

	// Use SQLC generated query
	queries := db.New(m.db.Pool())
	aliases, err := queries.GetAllAliases(ctx)
	if err != nil {
		return fmt.Errorf("failed to query vulnerability aliases: %w", err)
	}

	aliasCount := 0
	for _, aliasRow := range aliases {
		// Type assertions for interface{} types
		if alias, ok := aliasRow.Alias.(string); ok {
			m.aliasCache[alias] = aliasRow.ID
			aliasCount++
		}
	}

	log.Info().
		Int("cached_aliases", aliasCount).
		Dur("load_time", time.Since(start)).
		Msg("vulnerability alias cache loaded")

	return nil
}

// FindMatchingVulnerability finds an existing vulnerability with matching aliases using SQLC
func (m *VulnerabilityMerger) FindMatchingVulnerability(ctx context.Context, aliases []string) (*types.Vulnerability, error) {
	if len(aliases) == 0 {
		return nil, nil
	}

	// Filter out any VULN IDs from aliases (safety check - should not happen)
	filteredAliases := m.filterValidAliases(aliases)
	if len(filteredAliases) == 0 {
		return nil, nil
	}

	// Check cache first for performance
	for _, alias := range filteredAliases {
		if vulnID, exists := m.aliasCache[alias]; exists {
			return m.getVulnerabilityByID(ctx, vulnID)
		}
	}

	// Fallback to database query using SQLC with priority ordering
	queries := db.New(m.db.Pool())
	dbVuln, err := queries.GetVulnerabilityByAliasWithPriority(ctx, filteredAliases)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return nil, nil // No match found
		}
		return nil, fmt.Errorf("failed to query vulnerability: %w", err)
	}

	// Convert pgtype values to regular types
	if summary.Valid {
		vuln.Summary = summary.String
	}
	if details.Valid {
		vuln.Details = details.String
	}
	if severity.Valid {
		vuln.Severity = severity.String
	}
	if ecosystem.Valid {
		vuln.Ecosystem = ecosystem.String
	}
	if packageName.Valid {
		vuln.PackageName = packageName.String
	}
	if dataHash.Valid {
		vuln.DataHash = dataHash.String
	}
	if publishedAt.Valid {
		vuln.PublishedAt = publishedAt.Time
	}
	if modifiedAt.Valid {
		vuln.ModifiedAt = modifiedAt.Time
	}
	if createdAt.Valid {
		vuln.CreatedAt = createdAt.Time
	}
	if updatedAt.Valid {
		vuln.UpdatedAt = updatedAt.Time
	}

	// Convert array fields
	if affectedVersions.Valid {
		vuln.AffectedVersions = affectedVersions.Elements
	}
	if fixedVersions.Valid {
		vuln.FixedVersions = fixedVersions.Elements
	}
	if aliasesArray.Valid {
		vuln.Aliases = aliasesArray.Elements
	}
	if sourceArray.Valid {
		vuln.Source = sourceArray.Elements
	}

	// Convert from database model to types model
	vuln := m.convertDBVulnToType(dbVuln)
	return vuln, nil
}

// filterValidAliases filters out VULN IDs from aliases to ensure we only match on original source IDs
func (m *VulnerabilityMerger) filterValidAliases(aliases []string) []string {
	filtered := make([]string, 0, len(aliases))
	for _, alias := range aliases {
		// Skip any VULN IDs - these should never be used for matching
		if !utils.ValidateCustomVulnID(alias) {
			filtered = append(filtered, alias)
		} else {
			log.Warn().
				Str("alias", alias).
				Msg("Filtered out VULN ID from alias matching - this should not happen")
		}
	}
	return filtered
}

// MergeVulnerabilities merges new vulnerability data with existing vulnerability
func (m *VulnerabilityMerger) MergeVulnerabilities(ctx context.Context, existing *types.Vulnerability, new *types.Vulnerability) error {
	// Skip merge if same source and same data hash (no changes)
	if len(existing.Source) == 1 && len(new.Source) == 1 &&
		existing.Source[0] == new.Source[0] &&
		existing.DataHash != "" && new.DataHash != "" &&
		existing.DataHash == new.DataHash {

		log.Debug().
			Str("existing_id", existing.ID).
			Str("source", existing.Source[0]).
			Str("data_hash", existing.DataHash).
			Msg("skipping merge - same source and identical data hash")
		return nil
	}

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

// getVulnerabilityByID retrieves a vulnerability by ID using SQLC
func (m *VulnerabilityMerger) getVulnerabilityByID(ctx context.Context, id string) (*types.Vulnerability, error) {
	queries := db.New(m.db.Pool())
	dbVuln, err := queries.GetVulnerabilityByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get vulnerability by ID: %w", err)
	}

	// Convert from database model to types model
	vuln := m.convertDBVulnToType(dbVuln)
	return vuln, nil
}

// convertDBVulnToType converts a database vulnerability model to types model
func (m *VulnerabilityMerger) convertDBVulnToType(dbVuln db.Vulnerability) *types.Vulnerability {
	vuln := &types.Vulnerability{
		ID:               dbVuln.ID,
		AffectedVersions: dbVuln.AffectedVersions,
		FixedVersions:    dbVuln.FixedVersions,
		Aliases:          dbVuln.Aliases,
		Source:           dbVuln.Source,
	}

	// Convert pgtype values to regular types
	if dbVuln.Summary.Valid {
		vuln.Summary = dbVuln.Summary.String
	}
	if dbVuln.Details.Valid {
		vuln.Details = dbVuln.Details.String
	}
	if dbVuln.Severity.Valid {
		vuln.Severity = dbVuln.Severity.String
	}
	if dbVuln.Ecosystem.Valid {
		vuln.Ecosystem = dbVuln.Ecosystem.String
	}
	if dbVuln.PackageName.Valid {
		vuln.PackageName = dbVuln.PackageName.String
	}
	if dbVuln.DataHash.Valid {
		vuln.DataHash = dbVuln.DataHash.String
	}
	if dbVuln.PublishedAt.Valid {
		vuln.PublishedAt = dbVuln.PublishedAt.Time
	}
	if dbVuln.ModifiedAt.Valid {
		vuln.ModifiedAt = dbVuln.ModifiedAt.Time
	}
	if dbVuln.CreatedAt.Valid {
		vuln.CreatedAt = dbVuln.CreatedAt.Time
	}
	if dbVuln.UpdatedAt.Valid {
		vuln.UpdatedAt = dbVuln.UpdatedAt.Time
	}

	// Unmarshal JSON fields
	if len(dbVuln.Refs) > 0 {
		if err := json.Unmarshal(dbVuln.Refs, &vuln.References); err != nil {
			log.Error().Err(err).Msg("failed to unmarshal references")
		}
	}
	if len(dbVuln.Raw) > 0 {
		if err := json.Unmarshal(dbVuln.Raw, &vuln.RawData); err != nil {
			log.Error().Err(err).Msg("failed to unmarshal raw data")
		}
	}

	return vuln
}

// updateVulnerability updates a vulnerability in the database using SQLC
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

	// Convert to SQLC parameters
	params := db.UpdateVulnerabilityParams{
		ID:               vuln.ID,
		Summary:          pgtype.Text{String: vuln.Summary, Valid: vuln.Summary != ""},
		Details:          pgtype.Text{String: vuln.Details, Valid: vuln.Details != ""},
		Severity:         pgtype.Text{String: vuln.Severity, Valid: vuln.Severity != ""},
		PublishedAt:      pgtype.Timestamptz{Time: vuln.PublishedAt, Valid: !vuln.PublishedAt.IsZero()},
		ModifiedAt:       pgtype.Timestamptz{Time: vuln.ModifiedAt, Valid: !vuln.ModifiedAt.IsZero()},
		Ecosystem:        pgtype.Text{String: vuln.Ecosystem, Valid: vuln.Ecosystem != ""},
		PackageName:      pgtype.Text{String: vuln.PackageName, Valid: vuln.PackageName != ""},
		AffectedVersions: vuln.AffectedVersions,
		FixedVersions:    vuln.FixedVersions,
		Aliases:          vuln.Aliases,
		Refs:             refsJSON,
		Source:           vuln.Source,
		Raw:              rawJSON,
		DataHash:         pgtype.Text{String: vuln.DataHash, Valid: vuln.DataHash != ""},
	}

	queries := db.New(m.db.Pool())
	_, err = queries.UpdateVulnerability(ctx, params)
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
