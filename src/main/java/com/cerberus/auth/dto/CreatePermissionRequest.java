package com.cerberus.auth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class CreatePermissionRequest {
    @NotBlank
    private String name;   // e.g. "reports:read" -- resource:action convention
}
