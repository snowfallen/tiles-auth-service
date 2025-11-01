package com.tiles.auth.service;

/**
 * Refresh Token Service Interface
 *
 * Defines contract для refresh token operations.
 *
 * RESPONSIBILITIES:
 * ═══════════════
 * - Generate refresh tokens (UUID)
 * - Store tokens в Redis
 * - Validate tokens
 * - Revoke tokens (logout)
 * - Track user sessions
 *
 * REFRESH TOKEN:
 * ═════════════
 * Format: UUID (e.g., "550e8400-e29b-41d4-a716-446655440000")
 * Storage: Redis (key-value store)
 * TTL: 7 days (auto-expiration)
 *
 * Why UUID (not JWT):
 * ✅ Stateful (can revoke instantly)
 * ✅ Shorter (easier для mobile apps)
 * ✅ Single-purpose (only для refresh)
 * ✅ Redis TTL (automatic cleanup)
 *
 * REDIS DATA MODEL:
 * ════════════════
 *
 * 1. Token Data:
 * Key: refresh_token:{uuid}
 * Value: JSON {userId, username, email, issuedAt, expiresAt}
 * TTL: 7 days
 *
 * 2. User Sessions:
 * Key: user_session:{userId}
 * Value: Set of token UUIDs
 * TTL: 7 days
 *
 * SECURITY:
 * ════════
 * - Token rotation (одноразові tokens)
 * - Automatic expiration (Redis TTL)
 * - Instant revocation (delete від Redis)
 * - Session tracking (logout all devices)
 *
 * @author snowfallen
 * @version 1.0.0
 * @since 2024-10-31
 */
public interface RefreshTokenService {

    /**
     * Generate Refresh Token
     *
     * Creates UUID refresh token і stores в Redis.
     *
     * PROCESS:
     * ═══════
     * 1. Generate UUID
     * 2. Create token data (userId, username, email, timestamps)
     * 3. Serialize to JSON
     * 4. Store в Redis з TTL (7 days)
     * 5. Add token ID до user session set
     * 6. Return UUID
     *
     * TOKEN DATA:
     * ══════════
     * {
     *   "userId": "uuid",
     *   "username": "admin",
     *   "email": "admin@example.com",
     *   "issuedAt": 1698758400000,
     *   "expiresAt": 1699363200000
     * }
     *
     * @param userId user UUID
     * @param username username
     * @param email email address
     * @return refresh token UUID string
     */
    String generateRefreshToken(String userId, String username, String email);

    /**
     * Validate Refresh Token
     *
     * Checks if token exists і not expired.
     *
     * VALIDATION:
     * ══════════
     * ✅ Exists в Redis
     * ✅ Not expired (check expiresAt)
     * ✅ Valid format (JSON parsable)
     *
     * Note: Redis TTL автоматично видаляє expired tokens,
     * але ми перевіряємо expiresAt явно для extra safety.
     *
     * @param refreshToken refresh token UUID
     * @return true if valid
     * @throws com.tiles.auth.exception.InvalidTokenException if invalid
     */
    boolean validateRefreshToken(String refreshToken);

    /**
     * Get User ID від Refresh Token
     *
     * Extracts userId від token data в Redis.
     *
     * @param refreshToken refresh token UUID
     * @return userId (UUID string)
     * @throws com.tiles.auth.exception.InvalidTokenException if not found
     */
    String getUserIdFromRefreshToken(String refreshToken);

    /**
     * Get Username від Refresh Token
     *
     * Extracts username від token data в Redis.
     *
     * @param refreshToken refresh token UUID
     * @return username
     * @throws com.tiles.auth.exception.InvalidTokenException if not found
     */
    String getUsernameFromRefreshToken(String refreshToken);

    /**
     * Revoke Refresh Token
     *
     * Instantly invalidates token (delete від Redis).
     *
     * PROCESS:
     * ═══════
     * 1. Get userId від token data
     * 2. Remove token від user session set
     * 3. Delete token від Redis
     *
     * USE CASES:
     * ═════════
     * - Logout (single device)
     * - Token rotation (old token)
     * - Security breach
     *
     * INSTANT REVOCATION:
     * ══════════════════
     * Unlike JWT (cannot revoke without database),
     * refresh tokens instantly revoked (just delete від Redis).
     *
     * @param refreshToken refresh token UUID to revoke
     */
    void revokeRefreshToken(String refreshToken);

    /**
     * Revoke All User Tokens
     *
     * Logout з всіх devices (revoke all tokens).
     *
     * PROCESS:
     * ═══════
     * 1. Find user session set (user_session:{userId})
     * 2. Get all token UUIDs від set
     * 3. Delete each token (refresh_token:{uuid})
     * 4. Delete user session set
     *
     * USE CASES:
     * ═════════
     * - User clicks "Logout all devices"
     * - Password changed
     * - Security breach suspected
     * - Account compromised
     *
     * @param userId user UUID
     */
    void revokeAllUserTokens(String userId);

    /**
     * Get Active Session Count
     *
     * Counts how many devices user logged in.
     *
     * Returns count of active refresh tokens для user.
     * Each token = one device/browser session.
     *
     * USE CASES:
     * ═════════
     * - Show user: "You're logged in on 3 devices"
     * - Security monitoring
     * - Rate limiting (max sessions per user)
     *
     * @param userId user UUID
     * @return count of active tokens
     */
    long getActiveSessionCount(String userId);
}
