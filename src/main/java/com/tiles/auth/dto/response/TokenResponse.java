package com.tiles.auth.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Token Response DTO
 *
 * Simplified response для POST /auth/refresh endpoint.
 *
 * DIFFERENCE від LoginResponse:
 * ════════════════════════════
 * LoginResponse:
 * - Access token
 * - Refresh token
 * - Token type
 * - Expires in
 * - User info ✅ (full profile)
 *
 * TokenResponse:
 * - Access token
 * - Refresh token
 * - Token type
 * - Expires in
 * - User info ❌ (not included)
 *
 * WHY NO USER INFO:
 * ════════════════
 * Token refresh scenario:
 * 1. Client already has user info (від login)
 * 2. Access token expired
 * 3. Client refreshes token
 * 4. Only needs new tokens
 * 5. User info unchanged
 *
 * Benefits:
 * ✅ Smaller response (less data)
 * ✅ Faster (no DB query для user)
 * ✅ Efficient (only what's needed)
 *
 * If user info needed:
 * Client can make separate request: GET /api/users/me
 * But typically not needed during refresh.
 *
 * USAGE:
 * ═════
 * POST /auth/refresh
 * {
 *   "refreshToken": "550e8400-..."
 * }
 *
 * Response:
 * {
 *   "accessToken": "eyJhbGciOiJSUzI1NiIs...",
 *   "refreshToken": "723d35b8-...",  // NEW token (rotation)
 *   "tokenType": "Bearer",
 *   "expiresIn": 900
 * }
 *
 * CLIENT FLOW:
 * ═══════════
 * 1. Access token expires
 * 2. Client sends refresh token
 * 3. Server validates refresh token
 * 4. Server generates NEW tokens
 * 5. Server revokes OLD refresh token
 * 6. Server returns TokenResponse
 * 7. Client updates stored tokens
 * 8. Client retries failed request
 *
 * TOKEN ROTATION:
 * ══════════════
 * Both tokens rotated:
 * - OLD access token: expired (ignored)
 * - OLD refresh token: revoked (deleted від Redis)
 * - NEW access token: generated (15 min)
 * - NEW refresh token: generated (7 days)
 *
 * Security benefit:
 * ✅ Refresh tokens одноразові
 * ✅ Stolen token limited lifetime
 * ✅ Reuse detection possible
 *
 * REUSE DETECTION:
 * ═══════════════
 * If OLD token reused:
 * 1. OLD token не існує (already revoked)
 * 2. Validation fails
 * 3. 401 Unauthorized
 * 4. Client must re-login
 *
 * Indicates:
 * - Token stolen (attacker used first)
 * - Race condition (concurrent refresh)
 * - Client bug (didn't update token)
 *
 * LOMBOK ANNOTATIONS:
 * ══════════════════
 * Same як LoginResponse:
 * - @Data: Getters, setters, toString, equals, hashCode
 * - @Builder: Builder pattern
 * - @NoArgsConstructor: Default constructor (Jackson)
 * - @AllArgsConstructor: All fields constructor (Builder)
 *
 * JSON EXAMPLE:
 * ════════════
 * {
 *   "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImF1dGgtc2VydmljZS1rZXktMjAyNCJ9.eyJzdWIiOiI1NTBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDAiLCJ1c2VybmFtZSI6ImFkbWluIiwiZW1haWwiOiJhZG1pbkBleGFtcGxlLmNvbSIsInJvbGVzIjpbIlVTRVIiLCJBRE1JTiJdLCJpc3MiOiJodHRwOi8vYXV0aC1zZXJ2aWNlOjgwODQiLCJpYXQiOjE2OTg3NTg0MDAsImV4cCI6MTY5ODc1OTMwMCwianRpIjoiNzIzZDM1YjgtMzk0NC00YWY3LTk4YzEtYWJjZGVmMTIzNDU2In0.signature...",
 *   "refreshToken": "723d35b8-3944-4af7-98c1-abcdef123456",
 *   "tokenType": "Bearer",
 *   "expiresIn": 900
 * }
 *
 * @author snowfallen
 * @version 1.0.0
 * @since 2024-10-31
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TokenResponse {

    /**
     * Access Token (JWT)
     *
     * NEW JWT access token (15 min lifetime).
     *
     * See LoginResponse.accessToken for detailed documentation.
     *
     * ROTATION:
     * ════════
     * Always new token generated.
     * Old token ignored (already expired).
     *
     * New token contains:
     * - Fresh user data (roles, email)
     * - New expiration (current + 15 min)
     * - New token ID (jti claim)
     */
    private String accessToken;

    /**
     * Refresh Token (UUID)
     *
     * NEW UUID refresh token (7 days lifetime).
     *
     * See LoginResponse.refreshToken for detailed documentation.
     *
     * ROTATION:
     * ════════
     * New token generated.
     * Old token revoked (deleted від Redis).
     *
     * Client must:
     * 1. Store NEW token
     * 2. Discard OLD token
     * 3. Use NEW token для next refresh
     *
     * DO NOT reuse OLD token:
     * - Already revoked
     * - Will fail validation
     * - Indicates security issue
     */
    private String refreshToken;

    /**
     * Token Type
     *
     * Always "Bearer" (OAuth 2.0 standard).
     *
     * See LoginResponse.tokenType for detailed documentation.
     *
     * Default value: "Bearer"
     * Set automatically if not specified.
     */
    @Builder.Default
    private String tokenType = "Bearer";

    /**
     * Expires In (Seconds)
     *
     * Access token lifetime в seconds (900 = 15 min).
     *
     * See LoginResponse.expiresIn for detailed documentation.
     *
     * CLIENT ACTION:
     * ═════════════
     * Update expiration timer:
     *
     * const expiresAt = Date.now() + (expiresIn * 1000);
     * localStorage.setItem('tokenExpiresAt', expiresAt);
     *
     * Set new refresh timer:
     * setTimeout(() => {
     *     refreshToken();
     * }, (expiresIn - 60) * 1000);  // 1 min before expiry
     */
    private Long expiresIn;
}
