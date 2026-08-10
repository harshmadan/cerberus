package com.cerberus.auth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.*;

@Data
public class RefreshRequest {
    @NotBlank
    private String refreshToken;
}
