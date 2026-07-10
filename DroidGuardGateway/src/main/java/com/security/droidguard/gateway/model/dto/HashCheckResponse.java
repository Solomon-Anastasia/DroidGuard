package com.security.droidguard.gateway.model.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.Map;

// Exclude null fields
@JsonInclude(JsonInclude.Include.NON_NULL)
public record HashCheckResponse(String state, String jobId, Map<String, Object> yaraReport) {
}
