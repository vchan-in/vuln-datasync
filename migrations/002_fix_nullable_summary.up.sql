-- Fix summary field to allow NULL values for vulnerabilities without summaries
-- Some vulnerability sources (like OSV) have vulnerabilities without summaries

-- Remove NOT NULL constraint from summary field
ALTER TABLE vulnerabilities 
ALTER COLUMN summary DROP NOT NULL;
