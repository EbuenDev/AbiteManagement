package com.enterprise.auth.dto.request;

import com.enterprise.auth.entity.RoleName;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record CreateUserRequest(
    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 64, message = "Username must be between 3 and 64 characters")
    @Pattern(regexp = "^[a-zA-Z0-9._-]+$", message = "Username may only contain letters, numbers, dots, hyphens, and underscores")
    String username,

    @NotBlank(message = "Email is required")
    @Email(message = "A valid email address is required")
    @Size(max = 255, message = "Email length must not exceed 255 characters")
    String email,

    @NotBlank(message = "Initial password is required")
    @Size(min = 10, max = 128, message = "Password must be at least 10 characters long")
    String initialPassword,

    @NotNull(message = "Role is required")
    RoleName role
) {}
