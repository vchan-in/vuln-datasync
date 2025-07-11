-- Revert summary field to NOT NULL
ALTER TABLE vulnerabilities 
ALTER COLUMN summary SET NOT NULL;
