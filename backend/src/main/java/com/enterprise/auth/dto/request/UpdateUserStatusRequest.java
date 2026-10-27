package com.enterprise.auth.dto.request;

import com.enterprise.auth.entity.UserStatus;
import jakarta.validation.constraints.NotNull;

public record UpdateUserStatusRequest(
    @NotNull(message = "Status cannot be null")
    UserStatus status
) {}
