package com.cerberus.auth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class AssignRoleRequest {
    @NotBlank
    private String roleName;   // e.g. "ROLE_ADMIN"
}
