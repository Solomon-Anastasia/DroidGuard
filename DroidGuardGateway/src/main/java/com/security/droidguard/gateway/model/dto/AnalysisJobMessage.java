package com.security.droidguard.gateway.model.dto;

import java.io.Serializable;

public record AnalysisJobMessage(
        Long jobId,
        String sha256,
        String storagePath,
        String appName
) implements Serializable {}