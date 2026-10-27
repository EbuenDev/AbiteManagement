package com.enterprise.auth.security;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class RateLimiterService {

    private final Map<String, Bucket> preLoginBuckets = new ConcurrentHashMap<>();
    private final Map<String, Bucket> loginBuckets = new ConcurrentHashMap<>();

    /**
     * Attempts to consume a token for pre-login requests.
     * Rate limit: 15 requests per minute per IP.
     */
    public boolean allowPreLogin(String ipAddress) {
        Bucket bucket = preLoginBuckets.computeIfAbsent(ipAddress, this::createPreLoginBucket);
        return bucket.tryConsume(1);
    }

    /**
     * Attempts to consume a token for login verification requests.
     * Rate limit: 5 requests per minute per IP + identifier key.
     */
    public boolean allowLogin(String ipAddress, String identifier) {
        String key = ipAddress + ":" + (identifier != null ? identifier.trim().toLowerCase() : "anon");
        Bucket bucket = loginBuckets.computeIfAbsent(key, this::createLoginBucket);
        return bucket.tryConsume(1);
    }

    private Bucket createPreLoginBucket(String key) {
        Bandwidth limit = Bandwidth.classic(15, Refill.greedy(15, Duration.ofMinutes(1)));
        return Bucket.builder()
                .addLimit(limit)
                .build();
    }

    private Bucket createLoginBucket(String key) {
        Bandwidth limit = Bandwidth.classic(5, Refill.greedy(5, Duration.ofMinutes(1)));
        return Bucket.builder()
                .addLimit(limit)
                .build();
    }

    /**
     * Resets rate limiting state (useful for test suites).
     */
    public void reset() {
        preLoginBuckets.clear();
        loginBuckets.clear();
    }
}
