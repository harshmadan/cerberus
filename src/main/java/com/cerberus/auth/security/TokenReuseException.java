package com.cerberus.auth.security;

// Thrown when a refresh token is invalid, expired, or -- the interesting
// case -- has already been rotated away and is being presented again.
// All three cases are handled identically by the caller: reject, and if
// it's reuse specifically, the whole token family already got revoked
// by the time this is thrown.
public class TokenReuseException extends RuntimeException {
    public TokenReuseException(String message) {
        super(message);
    }
}
