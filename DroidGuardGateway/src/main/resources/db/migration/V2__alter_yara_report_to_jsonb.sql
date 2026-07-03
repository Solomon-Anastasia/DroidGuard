ALTER TABLE analysis_jobs
    ALTER COLUMN yara_report TYPE jsonb USING yara_report::jsonb;