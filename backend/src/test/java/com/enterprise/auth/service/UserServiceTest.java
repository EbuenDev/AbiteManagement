package com.enterprise.auth.service;

import com.enterprise.auth.audit.AuditService;
import com.enterprise.auth.dto.request.CreateUserRequest;
import com.enterprise.auth.dto.response.UserResponse;
import com.enterprise.auth.entity.*;
import com.enterprise.auth.exception.ApiException;
import com.enterprise.auth.exception.ErrorCode;
import com.enterprise.auth.repository.RoleRepository;
import com.enterprise.auth.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private AuditService auditService;

    @InjectMocks
    private UserService userService;

    private User superAdminUser;
    private User adminUser;
    private Role superAdminRole;
    private Role adminRole;
    private Role staffRole;

    @BeforeEach
    void setUp() {
        superAdminRole = new Role(RoleName.ROLE_SUPER_ADMIN, "Super Admin", "Super Admin");
        adminRole = new Role(RoleName.ROLE_ADMIN, "Admin", "Admin");
        staffRole = new Role(RoleName.ROLE_STAFF, "Staff", "Staff");

        superAdminUser = new User("superadmin", "superadmin@enterprise.local", "hashedPassword", "salt123", UserStatus.ACTIVE);
        superAdminUser.addRole(superAdminRole);

        adminUser = new User("admin1", "admin1@enterprise.local", "hashedPassword", "salt456", UserStatus.ACTIVE);
        adminUser.addRole(adminRole);
    }

    @Test
    @DisplayName("Super Admin can successfully create an Admin account")
    void superAdmin_canCreateAdminAccount() {
        CreateUserRequest request = new CreateUserRequest("newadmin", "newadmin@enterprise.local", "Password123!@#", RoleName.ROLE_ADMIN);

        when(userRepository.existsByUsername(anyString())).thenReturn(false);
        when(userRepository.existsByEmail(anyString())).thenReturn(false);
        when(roleRepository.findByCode(RoleName.ROLE_ADMIN)).thenReturn(Optional.of(adminRole));
        when(passwordEncoder.encode(anyString())).thenReturn("hashedNewPassword");
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        UserResponse response = userService.createUser(request, superAdminUser, "127.0.0.1", "Mozilla/5.0");

        assertNotNull(response);
        assertEquals("newadmin", response.username());
        assertTrue(response.roles().contains("ROLE_ADMIN"));
        verify(userRepository, times(1)).save(any(User.class));
    }

    @Test
    @DisplayName("Admin can successfully create a Staff account")
    void admin_canCreateStaffAccount() {
        CreateUserRequest request = new CreateUserRequest("newstaff", "newstaff@enterprise.local", "Password123!@#", RoleName.ROLE_STAFF);

        when(userRepository.existsByUsername(anyString())).thenReturn(false);
        when(userRepository.existsByEmail(anyString())).thenReturn(false);
        when(roleRepository.findByCode(RoleName.ROLE_STAFF)).thenReturn(Optional.of(staffRole));
        when(passwordEncoder.encode(anyString())).thenReturn("hashedNewPassword");
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        UserResponse response = userService.createUser(request, adminUser, "127.0.0.1", "Mozilla/5.0");

        assertNotNull(response);
        assertEquals("newstaff", response.username());
        assertTrue(response.roles().contains("ROLE_STAFF"));
    }

    @Test
    @DisplayName("Admin CANNOT create an Admin account (Security Boundary)")
    void admin_cannotCreateAdminAccount() {
        CreateUserRequest request = new CreateUserRequest("illegaladmin", "illegal@enterprise.local", "Password123!@#", RoleName.ROLE_ADMIN);

        ApiException ex = assertThrows(ApiException.class, () ->
                userService.createUser(request, adminUser, "127.0.0.1", "Mozilla/5.0")
        );

        assertEquals(ErrorCode.FORBIDDEN, ex.getErrorCode());
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("Admin CANNOT create a Super Admin account (Privilege Escalation Prevention)")
    void admin_cannotCreateSuperAdminAccount() {
        CreateUserRequest request = new CreateUserRequest("fakeSuper", "fake@enterprise.local", "Password123!@#", RoleName.ROLE_SUPER_ADMIN);

        ApiException ex = assertThrows(ApiException.class, () ->
                userService.createUser(request, adminUser, "127.0.0.1", "Mozilla/5.0")
        );

        assertEquals(ErrorCode.FORBIDDEN, ex.getErrorCode());
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("Duplicate username is rejected with CONFLICT")
    void duplicateUsername_rejected() {
        CreateUserRequest request = new CreateUserRequest("existinguser", "unique@enterprise.local", "Password123!@#", RoleName.ROLE_STAFF);

        when(userRepository.existsByUsername("existinguser")).thenReturn(true);

        ApiException ex = assertThrows(ApiException.class, () ->
                userService.createUser(request, superAdminUser, "127.0.0.1", "Mozilla/5.0")
        );

        assertEquals(ErrorCode.USERNAME_ALREADY_EXISTS, ex.getErrorCode());
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("Admin CANNOT modify or suspend a Super Admin account")
    void admin_cannotModifySuperAdminStatus() {
        UUID targetSuperAdminId = UUID.randomUUID();
        when(userRepository.findById(targetSuperAdminId)).thenReturn(Optional.of(superAdminUser));

        ApiException ex = assertThrows(ApiException.class, () ->
                userService.updateUserStatus(targetSuperAdminId, UserStatus.SUSPENDED, adminUser, "127.0.0.1", "Mozilla/5.0")
        );

        assertEquals(ErrorCode.FORBIDDEN, ex.getErrorCode());
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("Super Admin cannot deactivate their own account (Self-Lockout Defense)")
    void superAdmin_cannotDeactivateSelf() {
        UUID superAdminId = UUID.randomUUID();
        // Set same ID on user
        User targetSelf = spy(superAdminUser);
        when(targetSelf.getId()).thenReturn(superAdminId);
        when(userRepository.findById(superAdminId)).thenReturn(Optional.of(targetSelf));

        ApiException ex = assertThrows(ApiException.class, () ->
                userService.updateUserStatus(superAdminId, UserStatus.DEACTIVATED, targetSelf, "127.0.0.1", "Mozilla/5.0")
        );

        assertEquals(ErrorCode.VALIDATION_FAILED, ex.getErrorCode());
    }

    @Test
    @DisplayName("Admin CANNOT reset Super Admin or peer Admin password")
    void admin_cannotResetSuperAdminPassword() {
        UUID targetId = UUID.randomUUID();
        when(userRepository.findById(targetId)).thenReturn(Optional.of(superAdminUser));

        com.enterprise.auth.dto.request.AdminResetPasswordRequest request =
                new com.enterprise.auth.dto.request.AdminResetPasswordRequest("NewTempPass123!@#");

        ApiException ex = assertThrows(ApiException.class, () ->
                userService.adminResetPassword(targetId, request, adminUser, "127.0.0.1", "Mozilla/5.0")
        );

        assertEquals(ErrorCode.FORBIDDEN, ex.getErrorCode());
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("Admin can successfully reset Staff password")
    void admin_canResetStaffPassword() {
        UUID staffId = UUID.randomUUID();
        User staffUser = new User("staff1", "staff1@enterprise.local", "oldHash", "salt1", UserStatus.ACTIVE);
        staffUser.addRole(staffRole);

        when(userRepository.findById(staffId)).thenReturn(Optional.of(staffUser));
        when(passwordEncoder.encode("NewTempPass123!@#")).thenReturn("newArgonHash");

        com.enterprise.auth.dto.request.AdminResetPasswordRequest request =
                new com.enterprise.auth.dto.request.AdminResetPasswordRequest("NewTempPass123!@#");

        assertDoesNotThrow(() ->
                userService.adminResetPassword(staffId, request, adminUser, "127.0.0.1", "Mozilla/5.0")
        );

        verify(userRepository, times(1)).save(staffUser);
        verify(auditService, times(1)).recordEvent(eq(adminUser.getId()), eq("ADMIN_PASSWORD_RESET"), any(), any(), any());
    }

    @Test
    @DisplayName("Cannot delete the last remaining Super Admin")
    void cannotDelete_lastSuperAdmin() {
        UUID superAdminId = UUID.randomUUID();
        User targetSuperAdmin = spy(superAdminUser);
        when(targetSuperAdmin.getId()).thenReturn(superAdminId);

        User actor = new User("actorAdmin", "actor@enterprise.local", "hash", "salt", UserStatus.ACTIVE);
        actor.addRole(superAdminRole);

        when(userRepository.findById(superAdminId)).thenReturn(Optional.of(targetSuperAdmin));
        when(userRepository.countByRoleCode(RoleName.ROLE_SUPER_ADMIN)).thenReturn(1L);

        ApiException ex = assertThrows(ApiException.class, () ->
                userService.deleteUser(superAdminId, actor, "127.0.0.1", "Mozilla/5.0")
        );

        assertEquals(ErrorCode.VALIDATION_FAILED, ex.getErrorCode());
        verify(userRepository, never()).delete(any(User.class));
    }

    @Test
    @DisplayName("Admin CANNOT delete Super Admin or Admin accounts")
    void admin_cannotDeleteSuperAdminOrAdmin() {
        UUID targetId = UUID.randomUUID();
        when(userRepository.findById(targetId)).thenReturn(Optional.of(superAdminUser));

        ApiException ex = assertThrows(ApiException.class, () ->
                userService.deleteUser(targetId, adminUser, "127.0.0.1", "Mozilla/5.0")
        );

        assertEquals(ErrorCode.FORBIDDEN, ex.getErrorCode());
        verify(userRepository, never()).delete(any(User.class));
    }
}
