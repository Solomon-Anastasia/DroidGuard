package com.security.droidguard.gateway.model.dto;

import lombok.Getter;
import lombok.Setter;

import java.util.Map;

@Setter
@Getter
public class WorkerCallbackRequest {
    private Long jobId;
    private Map<String, Object> yaraReport;
}