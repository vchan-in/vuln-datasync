# API Testing Guide

This directory contains HTTP test files for the Vulnerability Data Synchronization API. These tests can be executed using VS Code with the REST Client extension or any HTTP client that supports `.http` files.

## Setup

1. **Install VS Code REST Client Extension** (recommended):
   - Install the "REST Client" extension by Huachao Mao
   - Open any `.http` file and click "Send Request" above each HTTP request

2. **Alternative HTTP Clients**:
   - IntelliJ IDEA HTTP Client
   - Postman (import the requests)
   - curl (copy the requests manually)

3. **Start the Services**:
   ```bash
   # Start Docker services
   docker compose up -d
   
   # Start the application
   make run-dev
   ```

## Test Files Overview

### `api.http`
Main API endpoints including health checks, sync triggers, and job management.

### `osv.http`
Tests specific to OSV (Open Source Vulnerabilities) data aggregation:
- Standard OSV sync
- Performance-optimized sync with high worker count
- Incremental updates

### `gitlab.http`
Tests for GitLab Advisory Database integration:
- GitLab advisory sync
- Custom repository configuration
- Performance tuning

### `cve.http`
Tests for CVE Project data aggregation:
- CVE data sync
- Custom source URLs
- Extract size limit testing

### `full-sync.http`
Comprehensive tests for multi-source data aggregation:
- Full system sync (all sources)
- Performance-optimized configurations
- Incremental and force refresh scenarios

### `jobs.http`
Job management and monitoring tests:
- Job status monitoring
- Queue management
- Scheduled job configuration

## Usage Examples

### Basic Health Check
```http
GET http://localhost:8080/health
```

### Trigger Full Data Sync
```http
POST http://localhost:8080/api/v1/sync
Content-Type: application/json

{
  "sources": ["osv", "gitlab", "cve"],
  "force": false,
  "async": true
}
```

### Monitor Sync Progress
```http
GET http://localhost:8080/api/v1/sync/status
```

### View Asynq Dashboard
Open http://localhost:8081 in your browser to view the Asynq job dashboard.

## Configuration Parameters

### Worker Configuration
- `osv_workers`: Number of OSV processing workers (optimal: 20-50)
- `gitlab_workers`: Number of GitLab processing workers (optimal: 10-15)
- `cve_workers`: Number of CVE processing workers (optimal: 5-10)

### Performance Tuning
- `batch_size`: Database batch size (optimal: 1000-5000)
- `force`: Force refresh existing data
- `incremental`: Only sync new data since last update
- `async`: Run sync in background (recommended for large datasets)

## Monitoring

### Asynq Dashboard
- URL: http://localhost:8081
- View active, pending, and completed jobs
- Monitor queue status and job performance
- Retry failed jobs

### Application Metrics
- Endpoint: http://localhost:8080/metrics
- Prometheus-compatible metrics
- Job execution times and success rates

### System Statistics
- Endpoint: http://localhost:8080/api/v1/stats
- Database record counts
- Last sync timestamps
- System health indicators

## Performance Testing

### Low Resource Usage
```json
{
  "sources": ["osv"],
  "config": {
    "osv_workers": 5,
    "batch_size": 100
  }
}
```

### High Performance
```json
{
  "sources": ["osv", "gitlab", "cve"],
  "config": {
    "osv_workers": 50,
    "gitlab_workers": 15,
    "cve_workers": 10,
    "batch_size": 5000
  }
}
```

## Troubleshooting

### Common Issues

1. **Connection Refused**: Ensure the application is running on port 8080
2. **Database Errors**: Check if PostgreSQL is running and accessible
3. **Redis Errors**: Ensure Redis is running for job queue functionality
4. **Timeout Errors**: Increase worker counts or reduce batch sizes

### Debugging

1. Check application logs for detailed error messages
2. Use the Asynq dashboard to monitor job failures
3. Verify environment configuration in `.env` file
4. Test individual endpoints before running full syncs

## Best Practices

1. **Start Small**: Begin with single-source syncs before attempting full syncs
2. **Monitor Resources**: Watch CPU and memory usage during large syncs
3. **Use Incremental Updates**: For regular updates, use incremental syncs
4. **Schedule Wisely**: Use the job scheduler for automated daily/weekly syncs
5. **Backup First**: Export database before major sync operations
