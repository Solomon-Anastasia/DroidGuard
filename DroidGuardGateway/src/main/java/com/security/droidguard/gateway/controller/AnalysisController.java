package com.security.droidguard.gateway.controller;

import com.security.droidguard.gateway.config.StorageProperties;
import com.security.droidguard.gateway.model.dto.HashCheckResponse;
import com.security.droidguard.gateway.model.dto.StatusResponse;
import com.security.droidguard.gateway.model.dto.UploadResponse;
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
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;

@RestController
@RequestMapping("/api")
public class AnalysisController {

    private static final Logger logger = LoggerFactory.getLogger(AnalysisController.class);

    private final StorageProperties storageProperties;
    private final JobRoutingService jobRoutingService;

    @Autowired
    public AnalysisController(StorageProperties storageProperties, JobRoutingService jobRoutingService) {
        this.storageProperties = storageProperties;
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
                        job.getYaraReport(),
                        null // jobId is not needed if it's already completed
                ));
            } else {
                return ResponseEntity.ok(new HashCheckResponse(
                        "PENDING",
                        null,
                        String.valueOf(job.getJobId())
                ));
            }
        }

        return ResponseEntity.ok(new HashCheckResponse("NEW", null, null));
    }

    @PostMapping("/analyze")
    public ResponseEntity<UploadResponse> uploadApk(@RequestParam("file") MultipartFile file,
                                                    @RequestParam("hash") String sha256) {
        if (file.isEmpty()) {
            return ResponseEntity.badRequest().build();
        }

        if (sha256 == null || sha256.isBlank()) {
            return ResponseEntity.badRequest().build();
        }

        try {
            String originalFilename = file.getOriginalFilename();
            String appName = originalFilename != null ? originalFilename : "UnknownApp";

            String finalFilename = sha256 + ".apk";
            Path targetLocation = Paths.get(storageProperties.getUploadDir())
                    .toAbsolutePath().normalize().resolve(finalFilename);

            if (!Files.exists(targetLocation)) {
                Files.copy(file.getInputStream(), targetLocation);
                logger.info("Successfully saved NEW APK as: {}", targetLocation);
            } else {
                logger.info("APK with hash {} already exists on disk. Skipping file write.", sha256);
            }

            Long generatedJobId = jobRoutingService.createAndRouteJob(file, sha256, appName);

            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(new UploadResponse(String.valueOf(generatedJobId), "File accepted and sent for asynchronous analysis."));

        } catch (IOException ex) {
            logger.error("Error saving the APK file to disk.", ex);
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
}