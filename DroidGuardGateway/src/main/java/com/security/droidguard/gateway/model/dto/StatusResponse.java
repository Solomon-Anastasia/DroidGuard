package com.security.droidguard.gateway.model.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record StatusResponse(
        String status,
        String yaraReport
) {
}