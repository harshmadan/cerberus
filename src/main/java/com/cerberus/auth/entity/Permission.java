package com.cerberus.auth.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Entity
@Table(name = "permissions")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Permission {

    @Id
    @GeneratedValue
    private UUID id;

    // Convention: "resource:action" -- e.g. "user:read", "user:delete",
    // "audit:read". This naming pattern makes @PreAuthorize checks on
    // Day 4 read almost like plain English.
    @Column(unique = true, nullable = false)
    private String name;
}
