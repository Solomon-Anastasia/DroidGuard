package com.security.droidguard.gateway.model.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
@Entity
@Table(name = "analysis_jobs")
public class AnalysisJob {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "job_id", updatable = false, nullable = false)
    private Long jobId;

    @Column(name = "sha256", nullable = false, length = 64)
    private String sha256;

    @Column(name = "app_name")
    private String appName;

    @Column(name = "status", nullable = false)
    private String status; // PENDING, COMPLETED, FAILED, INTERRUPTED, DELETED

    @Column(name = "yara_report", columnDefinition = "TEXT")
    private String yaraReport;

    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    // For hibernate
    public AnalysisJob() {
    }

    public AnalysisJob(String sha256, String appName, String status) {
        this.sha256 = sha256;
        this.appName = appName;
        this.status = status;
    }

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}
