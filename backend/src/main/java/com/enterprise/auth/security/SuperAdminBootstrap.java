package com.enterprise.auth.security;

import com.enterprise.auth.audit.AuditService;
import com.enterprise.auth.entity.*;
import com.enterprise.auth.repository.RoleRepository;
import com.enterprise.auth.repository.UserRepository;
import com.enterprise.auth.util.SecurityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
public class SuperAdminBootstrap implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(SuperAdminBootstrap.class);

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuditService auditService;

    @Value("${app.bootstrap.superadmin.enabled:true}")
    private boolean bootstrapEnabled;

    @Value("${app.bootstrap.superadmin.username:superadmin}")
    private String bootstrapUsername;

    @Value("${app.bootstrap.superadmin.email:superadmin@enterprise.local}")
    private String bootstrapEmail;

    @Value("${app.bootstrap.superadmin.password:SuperAdmin#2026!ChangeMeNow}")
    private String bootstrapPassword;

    public SuperAdminBootstrap(
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

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        if (!bootstrapEnabled) {
            log.info("Super Admin bootstrap is disabled via configuration.");
            return;
        }

        boolean superAdminExists = userRepository.existsByRoleCode(RoleName.ROLE_SUPER_ADMIN);
        if (superAdminExists) {
            log.info("Super Administrator account already present in database. Skipping bootstrap.");
            return;
        }

        log.warn("================================================================================");
        log.warn("No Super Administrator detected. Initializing one-time bootstrap setup...");
        log.warn("================================================================================");

        Role superAdminRole = roleRepository.findByCode(RoleName.ROLE_SUPER_ADMIN)
                .orElseThrow(() -> new IllegalStateException("ROLE_SUPER_ADMIN missing from database. Verify Flyway migrations."));

        String clientSalt = SecurityUtils.generateSecureRandomHex(32);
        String encodedPassword = passwordEncoder.encode(bootstrapPassword);

        User superAdmin = new User(
                bootstrapUsername.trim(),
                bootstrapEmail.trim().toLowerCase(),
                encodedPassword,
                clientSalt,
                UserStatus.ACTIVE
        );
        superAdmin.addRole(superAdminRole);

        UserSecuritySettings settings = new UserSecuritySettings(superAdmin);
        superAdmin.setSecuritySettings(settings);

        User saved = userRepository.saveAndFlush(superAdmin);

        auditService.recordEvent(
                saved.getId(),
                "BOOTSTRAP_SUPERADMIN_CREATED",
                "127.0.0.1",
                "SYSTEM_BOOTSTRAP",
                "Initial Super Administrator account initialized via secure bootstrap"
        );

        log.info("Super Administrator '{}' successfully bootstrapped with email '{}'.",
                saved.getUsername(), saved.getEmail());
        log.warn("IMPORTANT: Update the bootstrap password immediately and disable BOOTSTRAP_SUPERADMIN_ENABLED in production.");
    }
}
