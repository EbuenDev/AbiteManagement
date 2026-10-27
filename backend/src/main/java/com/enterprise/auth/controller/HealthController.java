package com.enterprise.auth.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Map;

@RestController
@RequestMapping("/api/health")
public class HealthController {

    private final JdbcTemplate jdbcTemplate;

    public HealthController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @GetMapping
    public ResponseEntity<Map<String, Object>> getHealth() {
        boolean dbHealthy = false;
        Integer roleCount = 0;
        try {
            roleCount = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM roles", Integer.class);
            dbHealthy = true;
        } catch (Exception ex) {
            // DB connection failure will show in health status
        }

        return ResponseEntity.ok(Map.of(
            "status", dbHealthy ? "UP" : "DEGRADED",
            "timestamp", Instant.now().toString(),
            "database", dbHealthy ? "CONNECTED" : "DISCONNECTED",
            "rolesCount", roleCount != null ? roleCount : 0
        ));
    }
}
