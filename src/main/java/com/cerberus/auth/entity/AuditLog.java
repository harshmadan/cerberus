package com.cerberus.auth.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "audit_logs")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuditLog {

    @Id
    @GeneratedValue
    private UUID id;

    // Deliberately a plain string, not a foreign key to User. We want this
    // record to survive even if the user account is later deleted, and we
    // want to log failed-login attempts for emails that never became users.
    @Column(nullable = false)
    private String actorEmail;

    // e.g. "LOGIN_SUCCESS", "LOGIN_FAILURE", "PASSWORD_RESET_REQUESTED",
    // "ROLE_ASSIGNED". Kept as a free string now; Day 6 is where we wire
    // up the AOP interceptor that actually populates these automatically.
    @Column(nullable = false)
    private String action;

    private String ipAddress;

    private String userAgent;

    @Column(columnDefinition = "TEXT")
    private String metadata;   // JSON blob for action-specific details

    @Column(updatable = false)
    private Instant timestamp;

    @PrePersist
    void onCreate() {
        timestamp = Instant.now();
    }
}
