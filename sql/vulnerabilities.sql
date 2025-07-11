-- name: GetVulnerabilityByID :one
SELECT * FROM vulnerabilities WHERE id = $1;

-- name: GetVulnerabilityByAlias :one
SELECT * FROM vulnerabilities WHERE $1 = ANY(aliases) LIMIT 1;

-- name: GetVulnerabilityByAliasWithPriority :one
SELECT * FROM vulnerabilities 
WHERE aliases && $1::text[]
ORDER BY 
    CASE 
        WHEN 'osv' = ANY(source) THEN 1
        WHEN 'gitlab' = ANY(source) THEN 2  
        WHEN 'cve' = ANY(source) THEN 3
        ELSE 4
    END
LIMIT 1;

-- name: GetVulnerabilitiesByAliases :many
SELECT * FROM vulnerabilities WHERE aliases && $1::text[];

-- name: GetVulnerabilitiesByEcosystem :many
SELECT * FROM vulnerabilities 
WHERE ecosystem = $1
ORDER BY published_at DESC
LIMIT $2 OFFSET $3;

-- name: GetVulnerabilitiesByPackage :many
SELECT * FROM vulnerabilities 
WHERE ecosystem = $1 AND package_name = $2
ORDER BY published_at DESC
LIMIT $3 OFFSET $4;

-- name: GetVulnerabilityByDataHash :one
SELECT * FROM vulnerabilities WHERE data_hash = $1;

-- name: CreateVulnerability :one
INSERT INTO vulnerabilities (
    id, summary, details, severity, published_at, modified_at,
    ecosystem, package_name, affected_versions, fixed_versions,
    aliases, refs, source, raw, data_hash
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15
) RETURNING *;

-- name: UpdateVulnerability :one
UPDATE vulnerabilities SET
    summary = $2,
    details = $3,
    severity = $4,
    published_at = $5,
    modified_at = $6,
    ecosystem = $7,
    package_name = $8,
    affected_versions = $9,
    fixed_versions = $10,
    aliases = $11,
    refs = $12,
    source = $13,
    raw = $14,
    data_hash = $15,
    updated_at = NOW()
WHERE id = $1
RETURNING *;

-- name: UpsertVulnerability :one
INSERT INTO vulnerabilities (
    id, summary, details, severity, published_at, modified_at,
    ecosystem, package_name, affected_versions, fixed_versions,
    aliases, refs, source, raw, data_hash
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15
) 
ON CONFLICT (id) DO UPDATE SET
    summary = EXCLUDED.summary,
    details = EXCLUDED.details,
    severity = EXCLUDED.severity,
    published_at = EXCLUDED.published_at,
    modified_at = EXCLUDED.modified_at,
    ecosystem = EXCLUDED.ecosystem,
    package_name = EXCLUDED.package_name,
    affected_versions = EXCLUDED.affected_versions,
    fixed_versions = EXCLUDED.fixed_versions,
    aliases = EXCLUDED.aliases,
    refs = EXCLUDED.refs,
    source = EXCLUDED.source,
    raw = EXCLUDED.raw,
    data_hash = EXCLUDED.data_hash,
    updated_at = NOW()
RETURNING *;

-- name: BatchUpsertVulnerabilities :copyfrom
INSERT INTO vulnerabilities (
    id, summary, details, severity, published_at, modified_at,
    ecosystem, package_name, affected_versions, fixed_versions,
    aliases, refs, source, raw, data_hash
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15
);

-- name: DeleteVulnerability :exec
DELETE FROM vulnerabilities WHERE id = $1;

-- name: CountVulnerabilities :one
SELECT COUNT(*) FROM vulnerabilities;

-- name: CountVulnerabilitiesBySource :many
SELECT 
    unnest(source) as source_name,
    COUNT(*) as count
FROM vulnerabilities 
GROUP BY source_name
ORDER BY count DESC;

-- name: CountVulnerabilitiesByEcosystem :many
SELECT ecosystem, COUNT(*) as count
FROM vulnerabilities 
WHERE ecosystem IS NOT NULL
GROUP BY ecosystem
ORDER BY count DESC;

-- name: GetRecentVulnerabilities :many
SELECT * FROM vulnerabilities 
WHERE created_at >= $1
ORDER BY created_at DESC
LIMIT $2;

-- name: GetUpdatedVulnerabilities :many
SELECT * FROM vulnerabilities 
WHERE updated_at >= $1
ORDER BY updated_at DESC
LIMIT $2;

-- name: GetVulnerabilityStats :one
SELECT * FROM vulnerability_stats;

-- name: GetAllAliases :many
SELECT id, unnest(aliases) as alias 
FROM vulnerabilities;
