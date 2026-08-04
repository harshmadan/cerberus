package com.cerberus.auth.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "refresh_tokens")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RefreshToken {

    @Id
    @GeneratedValue
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    // Store a HASH of the token, never the raw value -- same principle as
    // passwords. If this table were ever leaked, raw tokens would let
    // someone impersonate every user directly.
    @Column(nullable = false, unique = true)
    private String tokenHash;

    // All tokens issued from one original login share a familyId. On Day 3,
    // this is how we detect theft: if a token from an already-rotated
    // family gets reused, we revoke the whole family at once.
    @Column(nullable = false)
    private UUID familyId;

    @Column(nullable = false)
    private Instant expiresAt;

    @Builder.Default
    private boolean revoked = false;

    @Column(updatable = false)
    private Instant createdAt;

    @PrePersist
    void onCreate() {
        createdAt = Instant.now();
    }
}
