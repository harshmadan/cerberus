package com.cerberus.auth.security;

// Distinct from TokenReuseException (refresh-token specific) and from
// IllegalStateException (used for conflict-style errors, e.g. duplicate
// email). This one maps to 400 Bad Request -- the token itself is
// malformed/expired/already-used, not a conflict with existing state.
public class InvalidTokenException extends RuntimeException {
    public InvalidTokenException(String message) {
        super(message);
    }
}
