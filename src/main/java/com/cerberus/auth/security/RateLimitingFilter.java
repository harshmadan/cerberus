package com.cerberus.auth.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.Set;

@Component
@RequiredArgsConstructor
public class RateLimitingFilter extends OncePerRequestFilter {

    private final StringRedisTemplate redisTemplate;

    private static final int MAX_REQUESTS = 5;
    private static final Duration WINDOW = Duration.ofMinutes(1);

    // Only the endpoints that are actually attractive to brute-force --
    // rate-limiting every GET in the app would be pointless overhead.
    private static final Set<String> RATE_LIMITED_PATHS = Set.of(
            "/api/auth/login",
            "/api/auth/register",
            "/api/auth/forgot-password"
    );

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        if (!RATE_LIMITED_PATHS.contains(request.getRequestURI())) {
            filterChain.doFilter(request, response);
            return;
        }

        String ip = extractClientIp(request);
        String key = "rate_limit:" + request.getRequestURI() + ":" + ip;

        // INCR is atomic in Redis, even under heavy concurrency -- this is
        // the property that makes this whole approach reliable without
        // needing any locking of our own. First request in a fresh window
        // returns 1; we set the TTL only on that first call, which is what
        // makes "1 minute" mean "1 minute from the FIRST request", not a
        // sliding window that never actually resets.
        Long count = redisTemplate.opsForValue().increment(key);
        if (count != null && count == 1L) {
            redisTemplate.expire(key, WINDOW);
        }

        if (count != null && count > MAX_REQUESTS) {
            response.setStatus(429); // Too Many Requests
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"Too many requests -- please try again shortly\"}");
            return; // short-circuit -- never reaches the controller
        }

        filterChain.doFilter(request, response);
    }

    private String extractClientIp(HttpServletRequest request) {
        // X-Forwarded-For matters once this sits behind a reverse proxy or
        // load balancer (Day 7's Docker setup, or any real deployment) --
        // request.getRemoteAddr() would otherwise just return the proxy's
        // own IP for every single request, making rate limiting useless.
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
