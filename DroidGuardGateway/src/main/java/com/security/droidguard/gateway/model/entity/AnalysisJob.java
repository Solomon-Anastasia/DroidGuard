package com.security.droidguard.gateway.model.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.util.Map;

import java.time.LocalDateTime;

@Getter
@Setter
@Entity
@Table(name = "analysis_jobs", uniqueConstraints = {
        @UniqueConstraint(name = "uk_analysis_jobs_sha256", columnNames = "sha256")
})
public class AnalysisJob {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "job_id", updatable = false, nullable = false)
    private Long jobId;

    @Column(name = "sha256", nullable = false, length = 64, unique = true)
    private String sha256;

    @Column(name = "app_name")
    private String appName;

    @Column(name = "status", nullable = false)
    private String status; // NEW, PENDING, COMPLETED, ABORTED, FAILED

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "yara_report", columnDefinition = "jsonb")
    private Map<String, Object> yaraReport;

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
