package com.cerberus.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponse {
    private String accessToken;
    // refreshToken field intentionally left out for now -- that's Day 3.
    // Today, login only returns an access token.
}
