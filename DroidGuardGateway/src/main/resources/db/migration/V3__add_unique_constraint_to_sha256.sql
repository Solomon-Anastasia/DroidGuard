ALTER TABLE analysis_jobs
    ADD CONSTRAINT uk_analysis_jobs_sha256 UNIQUE (sha256);