package com.enterprise.auth.service;

import com.enterprise.auth.audit.AuditService;
import com.enterprise.auth.dto.request.CreateUserRequest;
import com.enterprise.auth.dto.response.UserResponse;
import com.enterprise.auth.entity.*;
import com.enterprise.auth.exception.ApiException;
import com.enterprise.auth.exception.ErrorCode;
import com.enterprise.auth.repository.RoleRepository;
import com.enterprise.auth.repository.UserRepository;
import com.enterprise.auth.util.SecurityUtils;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuditService auditService;

    public UserService(
            UserRepository userRepository,
            RoleRepository roleRepository,
            PasswordEncoder passwordEncoder,
            AuditService auditService
    ) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.auditService = auditService;
    }

    @Transactional
    public UserResponse createUser(CreateUserRequest request, User actor, String ipAddress, String userAgent) {
        boolean isActorSuperAdmin = hasRole(actor, RoleName.ROLE_SUPER_ADMIN);
        boolean isActorAdmin = hasRole(actor, RoleName.ROLE_ADMIN);

        // Authorization boundary checks
        if (!isActorSuperAdmin && !isActorAdmin) {
            throw new ApiException(HttpStatus.FORBIDDEN, ErrorCode.FORBIDDEN,
                    "Only Super Administrators and Administrators can create accounts");
        }

        if (request.role() == RoleName.ROLE_SUPER_ADMIN) {
            throw new ApiException(HttpStatus.FORBIDDEN, ErrorCode.FORBIDDEN,
                    "Super Admin accounts cannot be created via the user management API");
        }

        if (isActorAdmin && request.role() != RoleName.ROLE_STAFF) {
            throw new ApiException(HttpStatus.FORBIDDEN, ErrorCode.FORBIDDEN,
                    "Administrators are only permitted to create Staff accounts");
        }

        // Check uniqueness constraints
        if (userRepository.existsByUsername(request.username().trim())) {
            throw new ApiException(HttpStatus.CONFLICT, ErrorCode.USERNAME_ALREADY_EXISTS,
                    "The username '" + request.username() + "' is already registered");
        }

        if (userRepository.existsByEmail(request.email().trim().toLowerCase())) {
            throw new ApiException(HttpStatus.CONFLICT, ErrorCode.EMAIL_ALREADY_EXISTS,
                    "The email '" + request.email() + "' is already registered");
        }

        Role targetRole = roleRepository.findByCode(request.role())
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, ErrorCode.ROLE_NOT_FOUND,
                        "Role '" + request.role() + "' does not exist"));

        // Generate cryptographic client-salt for ephemeral proof derivations
        String clientSalt = SecurityUtils.generateSecureRandomHex(32);
        String encodedPassword = passwordEncoder.encode(request.initialPassword());

        User newUser = new User(
                request.username().trim(),
                request.email().trim().toLowerCase(),
                encodedPassword,
                clientSalt,
                UserStatus.ACTIVE
        );
        newUser.addRole(targetRole);

        UserSecuritySettings settings = new UserSecuritySettings(newUser);
        newUser.setSecuritySettings(settings);

        User savedUser = userRepository.save(newUser);

        auditService.recordEvent(
                actor != null ? actor.getId() : null,
                "USER_CREATED",
                ipAddress,
                userAgent,
                String.format("Created user '%s' with role '%s'", savedUser.getUsername(), targetRole.getCode())
        );

        return UserResponse.fromEntity(savedUser);
    }

    @Transactional
    public UserResponse updateUserStatus(UUID targetUserId, UserStatus newStatus, User actor, String ipAddress, String userAgent) {
        User targetUser = userRepository.findById(targetUserId)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, ErrorCode.USER_NOT_FOUND,
                        "Target user not found"));

        boolean isActorSuperAdmin = hasRole(actor, RoleName.ROLE_SUPER_ADMIN);
        boolean isActorAdmin = hasRole(actor, RoleName.ROLE_ADMIN);

        if (!isActorSuperAdmin && !isActorAdmin) {
            throw new ApiException(HttpStatus.FORBIDDEN, ErrorCode.FORBIDDEN,
                    "Insufficient privileges to modify user account status");
        }

        // Strict boundary: Admin cannot modify Super Admin or other Admins
        boolean isTargetSuperAdmin = hasRole(targetUser, RoleName.ROLE_SUPER_ADMIN);
        boolean isTargetAdmin = hasRole(targetUser, RoleName.ROLE_ADMIN);

        if (isActorAdmin && (isTargetSuperAdmin || isTargetAdmin)) {
            throw new ApiException(HttpStatus.FORBIDDEN, ErrorCode.FORBIDDEN,
                    "Administrators can only modify Staff account statuses");
        }

        // Super Admin cannot deactivate themselves through this endpoint to prevent lockout
        if (isActorSuperAdmin && targetUser.getId().equals(actor.getId()) && newStatus != UserStatus.ACTIVE) {
            throw new ApiException(HttpStatus.BAD_REQUEST, ErrorCode.VALIDATION_FAILED,
                    "Super Administrators cannot deactivate or suspend their own account");
        }

        UserStatus previousStatus = targetUser.getStatus();
        targetUser.setStatus(newStatus);
        User updatedUser = userRepository.save(targetUser);

        auditService.recordEvent(
                actor.getId(),
                "USER_STATUS_UPDATED",
                ipAddress,
                userAgent,
                String.format("Updated user '%s' status from %s to %s",
                        updatedUser.getUsername(), previousStatus, newStatus)
        );

        return UserResponse.fromEntity(updatedUser);
    }

    @Transactional(readOnly = true)
    public UserResponse getUserById(UUID id, User actor) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, ErrorCode.USER_NOT_FOUND,
                        "User not found"));

        boolean isActorSuperAdmin = hasRole(actor, RoleName.ROLE_SUPER_ADMIN);
        boolean isActorAdmin = hasRole(actor, RoleName.ROLE_ADMIN);

        if (isActorAdmin && hasRole(user, RoleName.ROLE_SUPER_ADMIN)) {
            throw new ApiException(HttpStatus.FORBIDDEN, ErrorCode.FORBIDDEN,
                    "Access to Super Administrator profile is restricted");
        }

        return UserResponse.fromEntity(user);
    }

    @Transactional(readOnly = true)
    public Page<UserResponse> listUsers(User actor, Pageable pageable) {
        boolean isActorSuperAdmin = hasRole(actor, RoleName.ROLE_SUPER_ADMIN);

        Page<User> users;
        if (isActorSuperAdmin) {
            users = userRepository.findAll(pageable);
        } else {
            // Admins can only see Staff accounts
            users = userRepository.findAllByRoleCode(RoleName.ROLE_STAFF, pageable);
        }

        return users.map(UserResponse::fromEntity);
    }

    public static boolean hasRole(User user, RoleName roleName) {
        if (user == null || user.getRoles() == null) return false;
        return user.getRoles().stream().anyMatch(r -> r.getCode() == roleName);
    }
}
