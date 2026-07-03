package com.security.droidguard.gateway.controller;

import com.security.droidguard.gateway.model.dto.HashCheckResponse;
import com.security.droidguard.gateway.model.dto.StatusResponse;
import com.security.droidguard.gateway.model.dto.UploadResponse;
import com.security.droidguard.gateway.model.dto.WorkerCallbackRequest;
import com.security.droidguard.gateway.model.entity.AnalysisJob;
import com.security.droidguard.gateway.service.JobRoutingService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Optional;

@RestController
@RequestMapping("/api")
public class AnalysisController {
    private static final Logger logger = LoggerFactory.getLogger(AnalysisController.class);
    private final JobRoutingService jobRoutingService;

    @Autowired
    public AnalysisController(JobRoutingService jobRoutingService) {
        this.jobRoutingService = jobRoutingService;
    }

    @GetMapping("/check")
    public ResponseEntity<HashCheckResponse> checkHash(@RequestParam String hash) {
        logger.info("Checking SHA-256: {}", hash);

        Optional<AnalysisJob> existingJob = jobRoutingService.findJobByHash(hash);

        if (existingJob.isPresent()) {
            AnalysisJob job = existingJob.get();

            if ("COMPLETED".equals(job.getStatus())) {
                return ResponseEntity.ok(new HashCheckResponse(
                        "CACHED",
                        null,
                        job.getYaraReport()
                ));
            } else {
                return ResponseEntity.ok(new HashCheckResponse(
                        "PENDING",
                        String.valueOf(job.getJobId()),
                        null
                ));
            }
        }

        return ResponseEntity.ok(new HashCheckResponse("NEW", null, null));
    }

    @PostMapping("/analyze")
    public ResponseEntity<UploadResponse> uploadApk(@RequestParam("file") MultipartFile file,
                                                    @RequestParam("hash") String sha256,
                                                    @RequestParam("appName") String appName) {
        if (file.isEmpty() || sha256 == null || sha256.isBlank()) {
            return ResponseEntity.badRequest().build();
        }

        try {
            Long generatedJobId = jobRoutingService.createAndRouteJob(file, sha256, appName);

            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(new UploadResponse(String.valueOf(generatedJobId), "File accepted and sent for asynchronous analysis"));

        } catch (IOException ex) {
            logger.error("Error processing the APK file.", ex);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @GetMapping("/status/{jobId}")
    public ResponseEntity<StatusResponse> getJobStatus(@PathVariable Long jobId) {
        Optional<AnalysisJob> jobOpt = jobRoutingService.findJobById(jobId);

        if (jobOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }

        AnalysisJob job = jobOpt.get();

        return ResponseEntity.ok(new StatusResponse(
                job.getStatus(),
                "COMPLETED".equals(job.getStatus()) ? job.getYaraReport() : null
        ));
    }

    @PostMapping("/internal/complete")
    public ResponseEntity<Void> receiveWorkerReport(@RequestBody WorkerCallbackRequest request) {
        logger.info("Received analysis completion report for Job ID: {}", request.getJobId());

        if (request.getJobId() == null || request.getYaraReport() == null) {
            return ResponseEntity.badRequest().build();
        }

        try {
            jobRoutingService.updateJobWithReport(request.getJobId(), request.getYaraReport());

            return ResponseEntity.ok().build();
        } catch (Exception e) {
            logger.error("Failed to update job {} with worker report", request.getJobId(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
}