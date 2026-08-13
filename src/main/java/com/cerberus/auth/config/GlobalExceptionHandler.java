package com.cerberus.auth.config;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.Map;

// @RestControllerAdvice applies these handlers globally, across every
// controller -- one place to keep error-response formatting consistent,
// instead of try/catch scattered through every endpoint.
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(IllegalStateException.class)
    public ResponseEntity<Map<String, String>> handleIllegalState(IllegalStateException ex) {
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(Map.of("error", ex.getMessage()));
    }

    @ExceptionHandler(com.cerberus.auth.security.TokenReuseException.class)
    public ResponseEntity<Map<String, String>> handleTokenReuse(com.cerberus.auth.security.TokenReuseException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", ex.getMessage()));
    }

    @ExceptionHandler(com.cerberus.auth.security.InvalidTokenException.class)
    public ResponseEntity<Map<String, String>> handleInvalidToken(com.cerberus.auth.security.InvalidTokenException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(Map.of("error", ex.getMessage()));
    }

    @ExceptionHandler(DisabledException.class)
    public ResponseEntity<Map<String, String>> handleDisabled(DisabledException ex) {
        // Thrown by DaoAuthenticationProvider automatically when
        // UserDetails.isEnabled() is false -- i.e. exactly the case Day 5
        // introduced: registered, but hasn't clicked the verification link.
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(Map.of("error", "Please verify your email before logging in"));
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<Map<String, String>> handleBadCredentials(BadCredentialsException ex) {
        // Deliberately vague message -- "Invalid email or password" rather
        // than "no such user" vs "wrong password". Confirming *which* part
        // was wrong is a small information leak that helps attackers
        // enumerate valid emails in your system.
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "Invalid email or password"));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, String>> handleValidation(MethodArgumentNotValidException ex) {
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getFieldErrors()
                .forEach(err -> errors.put(err.getField(), err.getDefaultMessage()));
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errors);
    }
}
