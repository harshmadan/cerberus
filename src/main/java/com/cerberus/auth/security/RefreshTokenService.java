package com.cerberus.auth.security;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    // Spring Boot autoconfigures this bean automatically the moment
    // spring-boot-starter-data-redis is on the classpath and a Redis
    // connection is reachable -- no manual config needed, unlike the
    // JPA repositories which we had to write ourselves.
    private final StringRedisTemplate redisTemplate;

    // Absolute session lifetime: even with perfect rotation, a session
    // can't outlive this. Forces a real re-login weekly, which limits how
    // long a compromised-but-undetected token could theoretically be useful.
    private static final Duration TTL = Duration.ofDays(7);

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public record IssuedToken(String refreshToken, String familyId) {}
    public record RotationResult(String subjectEmail, String refreshToken) {}

    /** Called at login. Starts a brand new token family. */
    public IssuedToken issue(String subjectEmail) {
        String familyId = UUID.randomUUID().toString();
        String rawToken = generateRawToken();
        storeCurrentToken(familyId, subjectEmail, rawToken);
        return new IssuedToken(familyId + "." + rawToken, familyId);
    }

    /**
     * Validates the presented token and, if valid, rotates it: issues a new
     * raw token for the SAME family and invalidates the old one. If the
     * presented token doesn't match what's currently stored for its family,
     * that's reuse -- the entire family is revoked on the spot.
     */
    public RotationResult rotate(String presentedToken) {
        String[] parts = splitToken(presentedToken);
        String familyId = parts[0];
        String rawToken = parts[1];
        String key = redisKey(familyId);

        String stored = redisTemplate.opsForValue().get(key);
        if (stored == null) {
            // Either it never existed, or the TTL expired naturally.
            throw new TokenReuseException("Refresh token expired or invalid");
        }

        String[] storedParts = stored.split("\\|", 2);
        String subjectEmail = storedParts[0];
        String storedHash = storedParts[1];

        if (!storedHash.equals(sha256(rawToken))) {
            // The family exists, but this ISN'T the current valid token for
            // it -- meaning it was already rotated away at some point.
            // Somebody is presenting a stale token. Treat as theft: kill
            // the whole family immediately, forcing a genuine re-login.
            redisTemplate.delete(key);
            throw new TokenReuseException("Token reuse detected -- session revoked");
        }

        // Legitimate use -- rotate. Same family, new raw token + hash.
        String newRawToken = generateRawToken();
        storeCurrentToken(familyId, subjectEmail, newRawToken);

        return new RotationResult(subjectEmail, familyId + "." + newRawToken);
    }

    /** Called at logout -- immediately kills the family, no waiting for TTL. */
    public void revoke(String presentedToken) {
        String familyId = splitToken(presentedToken)[0];
        redisTemplate.delete(redisKey(familyId));
    }

    private void storeCurrentToken(String familyId, String subjectEmail, String rawToken) {
        String value = subjectEmail + "|" + sha256(rawToken);
        redisTemplate.opsForValue().set(redisKey(familyId), value, TTL);
    }

    private String redisKey(String familyId) {
        return "refresh_token:family:" + familyId;
    }

    private String[] splitToken(String token) {
        String[] parts = token.split("\\.", 2);
        if (parts.length != 2) {
            throw new TokenReuseException("Malformed refresh token");
        }
        return parts;
    }

    private String generateRawToken() {
        byte[] bytes = new byte[32];
        SECURE_RANDOM.nextBytes(bytes);   // cryptographically secure, unlike
                                            // java.util.Random -- important
                                            // since this IS the credential
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(input.getBytes()));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e); // SHA-256 is always available -- this never actually fires
        }
    }
}
