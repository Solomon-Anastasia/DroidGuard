CREATE TABLE analysis_jobs
(
    job_id      BIGSERIAL PRIMARY KEY,
    sha256      VARCHAR(64) NOT NULL,
    app_name    VARCHAR(255),
    status      VARCHAR(50) NOT NULL,
    yara_report TEXT,
    created_at  TIMESTAMP   NOT NULL,
    updated_at  TIMESTAMP   NOT NULL
);

CREATE INDEX idx_analysis_jobs_sha256 ON analysis_jobs (sha256);