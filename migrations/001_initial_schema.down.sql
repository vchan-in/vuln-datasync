-- Drop tables in reverse order to handle dependencies

DROP VIEW IF EXISTS recent_processing;
DROP VIEW IF EXISTS vulnerability_stats;

DROP TRIGGER IF EXISTS update_vulnerabilities_updated_at ON vulnerabilities;
DROP FUNCTION IF EXISTS update_updated_at_column();

DROP TABLE IF EXISTS exports;
DROP TABLE IF EXISTS processing_stats;
DROP TABLE IF EXISTS jobs;
DROP TABLE IF EXISTS vulnerabilities;
