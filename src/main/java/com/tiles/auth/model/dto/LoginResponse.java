package com.tiles.auth.model.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Login Response DTO
 *
 * Відправляється після успішного login або refresh.
 *
 * Містить:
 * - accessToken: JWT для автентифікації (15 хв)
 * - refreshToken: UUID для оновлення access token (7 днів)
 * - tokenType: "Bearer" (OAuth2 standard)
 * - expiresIn: час життя access token в секундах
 * - user: інформація про користувача
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class LoginResponse {

    private String accessToken;

    private String refreshToken;

    @Builder.Default
    private String tokenType = "Bearer";

    private Long expiresIn;  // Seconds

    private UserInfo user;

    /**
     * Nested UserInfo DTO
     *
     * Інформація про користувача що повертається в response.
     * НЕ містить sensitive data (password, тощо)
     */
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class UserInfo {
        private String id;
        private String username;
        private String email;
        private String[] roles;
    }
}
