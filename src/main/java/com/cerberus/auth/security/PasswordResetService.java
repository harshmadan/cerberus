package com.cerberus.auth.security;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;

@Service
@RequiredArgsConstructor
public class PasswordResetService {

    private final StringRedisTemplate redisTemplate;

    // Deliberately much shorter than the email-verification TTL -- a
    // password reset link is a more sensitive capability (immediate
    // account takeover if intercepted), so it should go stale fast.
    private static final Duration TTL = Duration.ofHours(1);
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public String issueToken(String email) {
        String token = generateToken();
        redisTemplate.opsForValue().set(key(token), email, TTL);
        return token;
    }

    public String consumeToken(String token) {
        String redisKey = key(token);
        String email = redisTemplate.opsForValue().get(redisKey);
        if (email == null) {
            throw new InvalidTokenException("Reset link is invalid or has expired");
        }
        redisTemplate.delete(redisKey);
        return email;
    }

    private String key(String token) {
        return "password_reset:" + token;
    }

    private String generateToken() {
        byte[] bytes = new byte[32];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
