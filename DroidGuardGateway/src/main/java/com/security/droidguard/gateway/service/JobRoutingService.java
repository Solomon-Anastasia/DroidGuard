package com.security.droidguard.gateway.service;

import com.security.droidguard.gateway.model.dto.AnalysisJobMessage;
import com.security.droidguard.gateway.model.entity.AnalysisJob;
import com.security.droidguard.gateway.repository.AnalysisJobRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Map;
import java.util.Optional;

@Service
public class JobRoutingService {
    private final AnalysisJobRepository analysisJobRepository;
    private final StorageService storageService;
    private final QueueProducer queueProducer;

    @Autowired
    public JobRoutingService(AnalysisJobRepository analysisJobRepository,
                             StorageService storageService,
                             QueueProducer queueProducer) {
        this.analysisJobRepository = analysisJobRepository;
        this.storageService = storageService;
        this.queueProducer = queueProducer;
    }

    public Long createAndRouteJob(MultipartFile file, String sha256, String appName) throws IOException {
        String path = storageService.saveFile(file, sha256 + ".apk");

        Optional<AnalysisJob> existingJobOpt = analysisJobRepository.findFirstBySha256(sha256);

        AnalysisJob jobToProcess;
        if (existingJobOpt.isPresent()) { // If already exists (ABORTED)
            jobToProcess = existingJobOpt.get();
            jobToProcess.setStatus("PENDING");
            jobToProcess.setAppName(appName);
            jobToProcess.setYaraReport(null);
        } else {
            jobToProcess = new AnalysisJob(sha256, appName, "PENDING");
        }

        jobToProcess = analysisJobRepository.save(jobToProcess);

        queueProducer.sendJobToQueue(new AnalysisJobMessage(
                jobToProcess.getJobId(),
                sha256,
                path,
                appName
        ));

        return jobToProcess.getJobId();
    }

    public Optional<AnalysisJob> findJobByHash(String sha256) {
        return analysisJobRepository.findFirstBySha256(sha256);
    }

    public Optional<AnalysisJob> findJobById(Long jobId) {
        return analysisJobRepository.findById(jobId);
    }

    public void updateJobWithReport(Long jobId, Map<String, Object> yaraReport) {
        AnalysisJob job = analysisJobRepository.findById(jobId)
                .orElseThrow(() -> new IllegalArgumentException("AnalysisJob with ID " + jobId + " not found!"));

        if (job.getStatus() != null && "ABORTED".equalsIgnoreCase(job.getStatus().trim())) {
            System.out.println("Job " + jobId + " was cancelled by the user. Rejecting worker completion report");
            return;
        }

        job.setStatus("COMPLETED");
        job.setYaraReport(yaraReport);

        analysisJobRepository.save(job);
    }

    public void updateJobStatus(Long jobId, String status) {
        AnalysisJob job = analysisJobRepository.findById(jobId)
                .orElseThrow(() -> new IllegalArgumentException("AnalysisJob with ID " + jobId + " not found!"));

        job.setStatus(status);

        analysisJobRepository.save(job);
    }

    public int countTotalCompletedJobs() {
        return analysisJobRepository.countByStatus("COMPLETED");
    }

    public int countCleanJobs() {
        return analysisJobRepository.countCleanJobs();
    }

    public int countSuspiciousJobs() {
        return analysisJobRepository.countSuspiciousAndMaliciousJobs();
    }
}