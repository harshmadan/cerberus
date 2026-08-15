package com.cerberus.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuditLogResponse {
    private String actorEmail;
    private String action;
    private String ipAddress;
    private String userAgent;
    private String metadata;
    private Instant timestamp;
}
