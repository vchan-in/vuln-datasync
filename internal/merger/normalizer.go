package merger

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/yourusername/vuln-datasync/internal/types"
)

// Normalizer converts different vulnerability formats to the standard format
type Normalizer struct{}

// NewNormalizer creates a new vulnerability normalizer
func NewNormalizer() *Normalizer {
	return &Normalizer{}
}

// NormalizeOSV converts OSV vulnerability to standard format
func (n *Normalizer) NormalizeOSV(osv *types.OSVVulnerability) (*types.Vulnerability, error) {
	vuln := &types.Vulnerability{
		ID:               osv.ID,
		Summary:          osv.Summary,
		Details:          osv.Details,
		Aliases:          osv.Aliases,
		References:       make(map[string]interface{}),
		Source:           []string{"osv"},
		AffectedVersions: []string{},
		FixedVersions:    []string{},
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	n.extractOSVTimestamps(osv, vuln)
	n.extractOSVSeverity(osv, vuln)
	n.extractOSVAffected(osv, vuln)
	n.extractOSVReferences(osv, vuln)

	// Store raw data
	rawData, _ := json.Marshal(osv)
	vuln.RawData = map[string]interface{}{
		"osv": string(rawData),
	}

	// Generate data hash
	vuln.DataHash = n.generateHash(vuln)
	return vuln, nil
}

// extractOSVTimestamps extracts timestamps from OSV
func (n *Normalizer) extractOSVTimestamps(osv *types.OSVVulnerability, vuln *types.Vulnerability) {
	if osv.Published != "" {
		if t, err := time.Parse(time.RFC3339, osv.Published); err == nil {
			vuln.PublishedAt = t
		}
	}
	if osv.Modified != "" {
		if t, err := time.Parse(time.RFC3339, osv.Modified); err == nil {
			vuln.ModifiedAt = t
		}
	}
}

// extractOSVSeverity extracts severity from OSV
func (n *Normalizer) extractOSVSeverity(osv *types.OSVVulnerability, vuln *types.Vulnerability) {
	if len(osv.Severity) > 0 {
		vuln.Severity = osv.Severity[0].Score
	}
}

// extractOSVAffected extracts affected package information from OSV
func (n *Normalizer) extractOSVAffected(osv *types.OSVVulnerability, vuln *types.Vulnerability) {
	if len(osv.Affected) == 0 {
		return
	}

	affected := osv.Affected[0]
	vuln.Ecosystem = affected.Package.Ecosystem
	vuln.PackageName = affected.Package.Name

	// Extract version information
	vuln.AffectedVersions = append(vuln.AffectedVersions, affected.Versions...)

	// Extract ranges
	for _, r := range affected.Ranges {
		for _, event := range r.Events {
			if event.Fixed != "" {
				vuln.FixedVersions = append(vuln.FixedVersions, event.Fixed)
			}
		}
	}
}

// extractOSVReferences extracts references from OSV
func (n *Normalizer) extractOSVReferences(osv *types.OSVVulnerability, vuln *types.Vulnerability) {
	refs := make(map[string]interface{})
	for _, ref := range osv.References {
		refs[ref.Type] = ref.URL
	}
	vuln.References = refs
}

// NormalizeGitLab converts GitLab vulnerability to standard format
func (n *Normalizer) NormalizeGitLab(gitlab *types.GitLabVulnerability) (*types.Vulnerability, error) {
	vuln := &types.Vulnerability{
		ID:               gitlab.Identifier,
		Summary:          gitlab.Title,
		Details:          gitlab.Description,
		Aliases:          []string{},
		References:       make(map[string]interface{}),
		Source:           []string{"gitlab"},
		AffectedVersions: gitlab.AffectedVersions,
		FixedVersions:    gitlab.FixedVersions,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	// Add CVE to aliases if present
	if gitlab.CVE != "" {
		vuln.Aliases = append(vuln.Aliases, gitlab.CVE)
	}

	// Parse timestamps
	if gitlab.PublishedDate != "" {
		if t, err := time.Parse("2006-01-02", gitlab.PublishedDate); err == nil {
			vuln.PublishedAt = t
		}
	}
	if gitlab.ModifiedDate != "" {
		if t, err := time.Parse("2006-01-02", gitlab.ModifiedDate); err == nil {
			vuln.ModifiedAt = t
		}
	}

	// Extract severity from CVSS
	if gitlab.CVSS != "" {
		vuln.Severity = gitlab.CVSS
	}

	// Extract ecosystem from package slug
	vuln.Ecosystem = n.extractEcosystemFromPackageSlug(gitlab.PackageSlug)
	vuln.PackageName = gitlab.PackageSlug

	// Convert references
	refs := make(map[string]interface{})
	for i, url := range gitlab.URLs {
		refs[fmt.Sprintf("url_%d", i)] = url
	}
	if gitlab.Solution != "" {
		refs["solution"] = gitlab.Solution
	}
	vuln.References = refs

	// Store raw data
	rawData, _ := json.Marshal(gitlab)
	vuln.RawData = map[string]interface{}{
		"gitlab": string(rawData),
	}

	// Generate data hash
	vuln.DataHash = n.generateHash(vuln)

	return vuln, nil
}

// NormalizeCVE converts CVE vulnerability to standard format
func (n *Normalizer) NormalizeCVE(cve *types.CVEVulnerability) (*types.Vulnerability, error) {
	vuln := &types.Vulnerability{
		ID:               cve.CVEMetadata.CVEID,
		Aliases:          []string{},
		References:       make(map[string]interface{}),
		Source:           []string{"cve"},
		AffectedVersions: []string{},
		FixedVersions:    []string{},
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	n.extractCVEDescriptions(cve, vuln)
	n.extractCVETimestamps(cve, vuln)
	n.extractCVESeverity(cve, vuln)
	n.extractCVEAffected(cve, vuln)
	n.extractCVEReferences(cve, vuln)

	// Store raw data
	rawData, _ := json.Marshal(cve)
	vuln.RawData = map[string]interface{}{
		"cve": string(rawData),
	}

	// Generate data hash
	vuln.DataHash = n.generateHash(vuln)
	return vuln, nil
}

// extractCVEDescriptions extracts description and summary from CVE
func (n *Normalizer) extractCVEDescriptions(cve *types.CVEVulnerability, vuln *types.Vulnerability) {
	if len(cve.Containers.CNA.Descriptions) == 0 {
		return
	}

	// Try to find English description first
	for _, desc := range cve.Containers.CNA.Descriptions {
		if desc.Lang == "en" {
			vuln.Details = desc.Value
			vuln.Summary = n.extractSummary(desc.Value)
			return
		}
	}

	// Use first description if no English found
	vuln.Details = cve.Containers.CNA.Descriptions[0].Value
	vuln.Summary = n.extractSummary(vuln.Details)
}

// extractCVETimestamps extracts timestamps from CVE
func (n *Normalizer) extractCVETimestamps(cve *types.CVEVulnerability, vuln *types.Vulnerability) {
	if cve.CVEMetadata.DatePublished != "" {
		if t, err := time.Parse("2006-01-02T15:04:05.000Z", cve.CVEMetadata.DatePublished); err == nil {
			vuln.PublishedAt = t
		}
	}
	if cve.CVEMetadata.DateUpdated != "" {
		if t, err := time.Parse("2006-01-02T15:04:05.000Z", cve.CVEMetadata.DateUpdated); err == nil {
			vuln.ModifiedAt = t
		}
	}
}

// extractCVESeverity extracts severity from CVE metrics
func (n *Normalizer) extractCVESeverity(cve *types.CVEVulnerability, vuln *types.Vulnerability) {
	for _, metric := range cve.Containers.CNA.Metrics {
		if cvss3, ok := metric["cvssV3_1"]; ok {
			if cvssMap, ok := cvss3.(map[string]interface{}); ok {
				if baseScore, ok := cvssMap["baseScore"]; ok {
					vuln.Severity = fmt.Sprintf("%.1f", baseScore)
					return
				}
			}
		}
	}
}

// extractCVEAffected extracts affected products and versions from CVE
func (n *Normalizer) extractCVEAffected(cve *types.CVEVulnerability, vuln *types.Vulnerability) {
	for _, affected := range cve.Containers.CNA.Affected {
		if affected.Vendor == "" || affected.Product == "" {
			continue
		}

		vuln.PackageName = fmt.Sprintf("%s/%s", affected.Vendor, affected.Product)
		n.extractVersionsFromAffected(affected, vuln)
	}
}

// extractVersionsFromAffected extracts version information from affected entry
func (n *Normalizer) extractVersionsFromAffected(affected types.CVEAffected, vuln *types.Vulnerability) {
	for _, version := range affected.Versions {
		switch version.Status {
		case "affected":
			vuln.AffectedVersions = append(vuln.AffectedVersions, version.Version)
		case "unaffected":
			vuln.FixedVersions = append(vuln.FixedVersions, version.Version)
		}

		if version.LessThan != "" {
			vuln.FixedVersions = append(vuln.FixedVersions, version.Version)
		}
	}
}

// extractCVEReferences extracts references from CVE
func (n *Normalizer) extractCVEReferences(cve *types.CVEVulnerability, vuln *types.Vulnerability) {
	refs := make(map[string]interface{})
	for i, ref := range cve.Containers.CNA.References {
		refs[fmt.Sprintf("url_%d", i)] = ref.URL
		if len(ref.Tags) > 0 {
			refs[fmt.Sprintf("tags_%d", i)] = strings.Join(ref.Tags, ",")
		}
	}
	vuln.References = refs
}

// extractEcosystemFromPackageSlug extracts ecosystem from GitLab package slug
func (n *Normalizer) extractEcosystemFromPackageSlug(packageSlug string) string {
	parts := strings.Split(packageSlug, "/")
	if len(parts) > 0 {
		first := strings.ToLower(parts[0])
		// Map common package managers
		switch first {
		case "gem", "ruby":
			return "rubygems"
		case "npm", "node":
			return "npm"
		case "pip", "python", "pypi":
			return "pypi"
		case "go", "golang":
			return "go"
		case "maven", "java":
			return "maven"
		case "nuget", "dotnet", ".net":
			return "nuget"
		default:
			return first
		}
	}
	return "unknown"
}

// extractSummary extracts a short summary from a long description
func (n *Normalizer) extractSummary(description string) string {
	if len(description) <= 100 {
		return description
	}

	// Find the first sentence
	sentences := strings.Split(description, ". ")
	if len(sentences) > 0 && len(sentences[0]) <= 100 {
		return sentences[0] + "."
	}

	// Truncate to 100 characters
	if len(description) > 97 {
		return description[:97] + "..."
	}

	return description
}

// generateHash generates a SHA256 hash of the vulnerability data
func (n *Normalizer) generateHash(vuln *types.Vulnerability) string {
	// Create a consistent string representation for hashing
	hashData := fmt.Sprintf("%s|%s|%s|%s|%v|%v",
		vuln.ID,
		vuln.Summary,
		vuln.Details,
		vuln.Severity,
		vuln.AffectedVersions,
		vuln.FixedVersions,
	)

	hash := sha256.Sum256([]byte(hashData))
	return hex.EncodeToString(hash[:])
}

// MergeVulnerabilities merges vulnerabilities with the same ID from different sources
func (n *Normalizer) MergeVulnerabilities(existing *types.Vulnerability, new *types.Vulnerability) *types.Vulnerability {
	merged := *existing // Copy existing

	// Merge sources
	sourceMap := make(map[string]bool)
	for _, source := range existing.Source {
		sourceMap[source] = true
	}
	for _, source := range new.Source {
		if !sourceMap[source] {
			merged.Source = append(merged.Source, source)
		}
	}

	// Merge aliases
	aliasMap := make(map[string]bool)
	for _, alias := range existing.Aliases {
		aliasMap[alias] = true
	}
	for _, alias := range new.Aliases {
		if !aliasMap[alias] {
			merged.Aliases = append(merged.Aliases, alias)
		}
	}

	// Use more detailed information
	if new.Details != "" && len(new.Details) > len(existing.Details) {
		merged.Details = new.Details
	}
	if new.Summary != "" && len(new.Summary) > len(existing.Summary) {
		merged.Summary = new.Summary
	}

	// Use most recent timestamps
	if new.ModifiedAt.After(existing.ModifiedAt) {
		merged.ModifiedAt = new.ModifiedAt
	}

	// Merge references
	for key, value := range new.References {
		merged.References[key] = value
	}

	// Merge raw data
	for key, value := range new.RawData {
		merged.RawData[key] = value
	}

	// Update hash and timestamp
	merged.DataHash = n.generateHash(&merged)
	merged.UpdatedAt = time.Now()

	return &merged
}
