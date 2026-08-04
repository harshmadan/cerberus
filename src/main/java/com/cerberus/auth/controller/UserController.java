package com.cerberus.auth.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/users")
public class UserController {

    // This endpoint is NOT in the permitAll list in SecurityConfig, so
    // reaching it at all proves the JwtAuthenticationFilter successfully
    // validated a token and populated the SecurityContext. If you call this
    // with no token, or a bad one, you should get 401/403 -- try both.
    @GetMapping("/me")
    public Map<String, Object> me(Authentication authentication) {
        return Map.of(
                "email", authentication.getName(),
                "authorities", authentication.getAuthorities()
        );
    }
}
