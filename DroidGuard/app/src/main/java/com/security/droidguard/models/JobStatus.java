package com.security.droidguard.models;

public class JobStatus {
    private String jobId;
    private String status; // PENDING, COMPLETED, FAILED
    private String yaraReport;

    public JobStatus(String jobId, String status, String yaraReport) {
        this.jobId = jobId;
        this.status = status;
        this.yaraReport = yaraReport;
    }

    public String getJobId() {
        return jobId;
    }

    public String getStatus() {
        return status;
    }

    public String getYaraReport() {
        return yaraReport;
    }

    public boolean isComplete() {
        return "COMPLETED".equalsIgnoreCase(status);
    }
}
