package com.security.droidguard.gateway.model.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record StatusResponse(
        String status,
        Map<String, Object> yaraReport
) {
}