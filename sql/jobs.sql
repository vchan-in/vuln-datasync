-- name: CreateJob :one
INSERT INTO jobs (type, payload, queue, priority, max_retry)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetJob :one
SELECT * FROM jobs WHERE id = $1;

-- name: GetPendingJobs :many
SELECT * FROM jobs 
WHERE state = 'pending' AND queue = $1
ORDER BY priority DESC, created_at ASC
LIMIT $2;

-- name: GetJobsByState :many
SELECT * FROM jobs 
WHERE state = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- name: UpdateJobState :one
UPDATE jobs SET
    state = $2,
    processed_at = CASE WHEN $2 = 'processing' THEN NOW() ELSE processed_at END,
    completed_at = CASE WHEN $2 IN ('completed', 'failed') THEN NOW() ELSE completed_at END,
    error_message = $3
WHERE id = $1
RETURNING *;

-- name: IncrementJobRetry :one
UPDATE jobs SET
    retried = retried + 1,
    state = CASE WHEN retried + 1 >= max_retry THEN 'failed' ELSE 'pending' END,
    error_message = $2
WHERE id = $1
RETURNING *;

-- name: DeleteCompletedJobs :exec
DELETE FROM jobs 
WHERE state IN ('completed', 'failed') 
AND completed_at < $1;

-- name: GetJobStats :one
SELECT 
    COUNT(*) FILTER (WHERE state = 'pending') as pending_count,
    COUNT(*) FILTER (WHERE state = 'processing') as processing_count,
    COUNT(*) FILTER (WHERE state = 'completed') as completed_count,
    COUNT(*) FILTER (WHERE state = 'failed') as failed_count,
    COUNT(*) as total_count
FROM jobs;

-- name: CreateProcessingStat :one
INSERT INTO processing_stats (
    source, processed_count, ingested_count, updated_count, 
    merged_count, skipped_count, error_count, 
    start_time, end_time, duration_ms
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
RETURNING *;

-- name: DeleteOldProcessingStats :exec
DELETE FROM processing_stats WHERE start_time < $1;
