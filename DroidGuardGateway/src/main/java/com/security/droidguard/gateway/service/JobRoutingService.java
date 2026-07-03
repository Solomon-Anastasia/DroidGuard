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
    private final AnalysisJobRepository jobRepository;
    private final StorageService storageService;
    private final QueueProducer queueProducer;

    @Autowired
    public JobRoutingService(AnalysisJobRepository jobRepository,
                             StorageService storageService,
                             QueueProducer queueProducer) {
        this.jobRepository = jobRepository;
        this.storageService = storageService;
        this.queueProducer = queueProducer;
    }

    public Long createAndRouteJob(MultipartFile file, String sha256, String appName) throws IOException {
        String path = storageService.saveFile(file, sha256 + ".apk");

        AnalysisJob newJob = new AnalysisJob(sha256, appName, "PENDING");
        newJob = jobRepository.save(newJob);

        queueProducer.sendJobToQueue(new AnalysisJobMessage(newJob.getJobId(), sha256, path, appName));

        return newJob.getJobId();
    }

    public Optional<AnalysisJob> findJobByHash(String sha256) {
        return jobRepository.findFirstBySha256(sha256);
    }

    public Optional<AnalysisJob> findJobById(Long jobId) {
        return jobRepository.findById(jobId);
    }

    public void updateJobWithReport(Long jobId, Map<String, Object> yaraReport) {
        AnalysisJob job = jobRepository.findById(jobId)
                .orElseThrow(() -> new IllegalArgumentException("AnalysisJob with ID " + jobId + " not found"));

        job.setStatus("COMPLETED");
        job.setYaraReport(yaraReport);

        jobRepository.save(job);
    }
}