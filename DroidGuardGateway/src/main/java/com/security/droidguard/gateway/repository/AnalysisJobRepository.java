package com.security.droidguard.gateway.repository;

import com.security.droidguard.gateway.model.entity.AnalysisJob;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AnalysisJobRepository extends JpaRepository<AnalysisJob, Long> {
    Optional<AnalysisJob> findFirstBySha256(String sha256);

    int countByStatus(String status);

    @Query(value = "SELECT COUNT(*) FROM analysis_jobs WHERE yara_report->>'verdict' = 'clean'", nativeQuery = true)
    int countCleanJobs();

    @Query(value = "SELECT COUNT(*) FROM analysis_jobs WHERE yara_report->>'verdict' IN ('suspicious', 'malicious')", nativeQuery = true)
    int countSuspiciousAndMaliciousJobs();
}
