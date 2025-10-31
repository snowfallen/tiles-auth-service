package com.tiles.auth.model.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/**
 * Login Request DTO
 *
 * Використовується для POST /auth/login
 *
 * Validation:
 * - username: не може бути порожнім
 * - password: не може бути порожнім
 */
@Data
public class LoginRequest {

    @NotBlank(message = "Username is required")
    private String username;

    @NotBlank(message = "Password is required")
    private String password;
}
