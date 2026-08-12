package com.cerberus.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserSummaryResponse {
    private UUID id;
    private String email;
    private boolean enabled;
    private Set<String> roles;
    // Same principle as RegisterRequest -- this DTO is a deliberate,
    // narrow view. It exposes roles for an admin to see, but never the
    // password hash, even though the User entity has that field.
}
