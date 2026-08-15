package com.cerberus.auth.security;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
@RequiredArgsConstructor
public class LoginAttemptService {

    private final StringRedisTemplate redisTemplate;

    private static final int MAX_ATTEMPTS = 5;
    private static final Duration LOCKOUT_WINDOW = Duration.ofMinutes(15);

    public void recordFailure(String email) {
        String key = key(email);
        Long attempts = redisTemplate.opsForValue().increment(key);
        if (attempts != null && attempts == 1L) {
            redisTemplate.expire(key, LOCKOUT_WINDOW);
        }
    }

    public boolean isLocked(String email) {
        String value = redisTemplate.opsForValue().get(key(email));
        return value != null && Integer.parseInt(value) >= MAX_ATTEMPTS;
    }

    public void resetAttempts(String email) {
        redisTemplate.delete(key(email));
    }

    private String key(String email) {
        return "login_attempts:" + email;
    }

    // Design note: this is intentionally Redis-only, with a TTL-based
    // auto-unlock, rather than flipping User.accountNonLocked in Postgres
    // permanently. A DB-based lock would need a separate admin "unlock"
    // endpoint to ever recover from -- annoying for a legitimate user who
    // just mistyped their password five times. Self-expiring after 15
    // minutes is friendlier UX while still stopping a sustained attack.
}
