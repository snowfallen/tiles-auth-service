package com.tiles.auth.model.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/**
 * Refresh Token Request DTO
 *
 * Використовується для POST /auth/refresh
 *
 * Коли access token expired, client відправляє refresh token
 * для отримання нового access token.
 */
@Data
public class RefreshTokenRequest {

    @NotBlank(message = "Refresh token is required")
    private String refreshToken;
}
