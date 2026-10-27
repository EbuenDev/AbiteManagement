package com.enterprise.auth.controller;

import com.enterprise.auth.audit.AuditService;
import com.enterprise.auth.dto.request.AdminResetPasswordRequest;
import com.enterprise.auth.dto.request.CreateUserRequest;
import com.enterprise.auth.dto.request.UpdateUserStatusRequest;
import com.enterprise.auth.dto.response.UserResponse;
import com.enterprise.auth.entity.User;
import com.enterprise.auth.security.CustomUserDetails;
import com.enterprise.auth.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN')")
    public ResponseEntity<UserResponse> createUser(
            @Valid @RequestBody CreateUserRequest request,
            @AuthenticationPrincipal CustomUserDetails userDetails,
            HttpServletRequest servletRequest
    ) {
        User actor = userDetails != null ? userDetails.getUser() : null;
        String ip = AuditService.extractClientIp(servletRequest);
        String agent = servletRequest.getHeader("User-Agent");

        UserResponse createdUser = userService.createUser(request, actor, ip, agent);
        return new ResponseEntity<>(createdUser, HttpStatus.CREATED);
    }

    @GetMapping
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN')")
    public ResponseEntity<Page<UserResponse>> listUsers(
            @AuthenticationPrincipal CustomUserDetails userDetails,
            @PageableDefault(page = 0, size = 20, sort = "createdAt", direction = Sort.Direction.DESC) Pageable pageable
    ) {
        User actor = userDetails != null ? userDetails.getUser() : null;
        Page<UserResponse> users = userService.listUsers(actor, pageable);
        return ResponseEntity.ok(users);
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN')")
    public ResponseEntity<UserResponse> getUserById(
            @PathVariable UUID id,
            @AuthenticationPrincipal CustomUserDetails userDetails
    ) {
        User actor = userDetails != null ? userDetails.getUser() : null;
        UserResponse user = userService.getUserById(id, actor);
        return ResponseEntity.ok(user);
    }

    @PatchMapping("/{id}/status")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN')")
    public ResponseEntity<UserResponse> updateUserStatus(
            @PathVariable UUID id,
            @Valid @RequestBody UpdateUserStatusRequest request,
            @AuthenticationPrincipal CustomUserDetails userDetails,
            HttpServletRequest servletRequest
    ) {
        User actor = userDetails != null ? userDetails.getUser() : null;
        String ip = AuditService.extractClientIp(servletRequest);
        String agent = servletRequest.getHeader("User-Agent");

        UserResponse updated = userService.updateUserStatus(id, request.status(), actor, ip, agent);
        return ResponseEntity.ok(updated);
    }

    @PostMapping("/{id}/reset-password")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN')")
    public ResponseEntity<Map<String, String>> adminResetPassword(
            @PathVariable UUID id,
            @Valid @RequestBody AdminResetPasswordRequest request,
            @AuthenticationPrincipal CustomUserDetails userDetails,
            HttpServletRequest servletRequest
    ) {
        User actor = userDetails != null ? userDetails.getUser() : null;
        String ip = AuditService.extractClientIp(servletRequest);
        String agent = servletRequest.getHeader("User-Agent");

        userService.adminResetPassword(id, request, actor, ip, agent);
        return ResponseEntity.ok(Map.of("message", "User password reset successfully"));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN')")
    public ResponseEntity<Map<String, String>> deleteUser(
            @PathVariable UUID id,
            @AuthenticationPrincipal CustomUserDetails userDetails,
            HttpServletRequest servletRequest
    ) {
        User actor = userDetails != null ? userDetails.getUser() : null;
        String ip = AuditService.extractClientIp(servletRequest);
        String agent = servletRequest.getHeader("User-Agent");

        userService.deleteUser(id, actor, ip, agent);
        return ResponseEntity.ok(Map.of("message", "User account deleted successfully"));
    }
}
