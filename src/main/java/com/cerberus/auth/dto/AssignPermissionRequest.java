package com.cerberus.auth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class AssignPermissionRequest {
    @NotBlank
    private String permissionName;
}
