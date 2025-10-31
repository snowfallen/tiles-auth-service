package com.tiles.auth.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tiles.auth.exception.InvalidTokenException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * Refresh Token Service
 *
 * Відповідає за:
 * - Refresh token generation
 * - Refresh token storage (Redis)
 * - Refresh token validation
 * - Refresh token rotation (security best practice)
 * - User session management
 *
 * Refresh Token Flow:
 * 1. User login → generate refresh token (UUID)
 * 2. Store in Redis with TTL (7 days)
 * 3. Client stores refresh token (httpOnly cookie or secure storage)
 * 4. Access token expires (15 min) → client sends refresh token
 * 5. Validate refresh token → generate NEW access + refresh tokens
 * 6. Revoke OLD refresh token (rotation)
 * 7. Return new tokens
 *
 * Security:
 * - Rotation (одноразові refresh tokens)
 * - TTL (automatic expiry через 7 днів)
 * - Redis storage (можна revoke instantly)
 * - User sessions tracking (logout all devices)
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenServiceImpl implements RefreshTokenService {

    private final RedisTemplate<String, String> redisTemplate;
    private final ObjectMapper objectMapper;

    @Value("${jwt.refresh-token-expiry}")
    private Long refreshTokenExpiry;  // milliseconds (7 days)

    // Redis key prefixes
    private static final String REFRESH_TOKEN_PREFIX = "refresh_token:";
    private static final String USER_SESSION_PREFIX = "user_session:";

    /**
     * Generate Refresh Token
     *
     * Creates UUID refresh token and stores in Redis.
     * Also tracks user session (для logout all devices).
     *
     * Redis structure:
     * refresh_token:{uuid} → {userId, username, email, issuedAt, expiresAt}
     * user_session:{userId} → Set of refresh_token_ids
     *
     * @param userId user ID
     * @param username username
     * @param email email
     * @return refresh token (UUID string)
     */
    @Override
    public String generateRefreshToken(String userId, String username, String email) {
        // Generate UUID refresh token
        String refreshToken = UUID.randomUUID().toString();

        // Calculate expiry
        long now = System.currentTimeMillis();
        long expiresAt = now + refreshTokenExpiry;

        // Refresh token data (JSON in Redis)
        Map<String, Object> tokenData = new HashMap<>();
        tokenData.put("userId", userId);
        tokenData.put("username", username);
        tokenData.put("email", email);
        tokenData.put("issuedAt", now);
        tokenData.put("expiresAt", expiresAt);

        try {
            String tokenDataJson = objectMapper.writeValueAsString(tokenData);

            // Store in Redis with TTL
            String key = REFRESH_TOKEN_PREFIX + refreshToken;
            redisTemplate.opsForValue().set(
                    key,
                    tokenDataJson,
                    Duration.ofMillis(refreshTokenExpiry)
            );

            // Track user session
            addToUserSession(userId, refreshToken);

            log.debug("Generated refresh token for user: {}", username);
            return refreshToken;

        } catch (Exception e) {
            log.error("Error generating refresh token", e);
            throw new RuntimeException("Failed to generate refresh token", e);
        }
    }

    /**
     * Validate Refresh Token
     *
     * Перевіряє:
     * - Чи існує в Redis
     * - Чи не expired (Redis TTL автоматично видаляє, але перевіряємо явно)
     *
     * @param refreshToken refresh token UUID
     * @return true if valid
     * @throws InvalidTokenException if invalid
     */
    @Override
    public boolean validateRefreshToken(String refreshToken) {
        String key = REFRESH_TOKEN_PREFIX + refreshToken;
        String tokenDataJson = redisTemplate.opsForValue().get(key);

        if (tokenDataJson == null) {
            log.warn("Refresh token not found or expired: {}", refreshToken);
            throw new InvalidTokenException("Invalid or expired refresh token");
        }

        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> tokenData = objectMapper.readValue(tokenDataJson, Map.class);

            // Check expiry (extra safety, Redis TTL should handle this)
            Long expiresAt = ((Number) tokenData.get("expiresAt")).longValue();
            if (System.currentTimeMillis() > expiresAt) {
                log.warn("Refresh token expired: {}", refreshToken);
                revokeRefreshToken(refreshToken);
                throw new InvalidTokenException("Refresh token expired");
            }

            return true;

        } catch (Exception e) {
            log.error("Error validating refresh token", e);
            throw new InvalidTokenException("Invalid refresh token format");
        }
    }

    /**
     * Get User ID from Refresh Token
     *
     * @param refreshToken refresh token UUID
     * @return userId
     */
    @Override
    public String getUserIdFromRefreshToken(String refreshToken) {
        String key = REFRESH_TOKEN_PREFIX + refreshToken;
        String tokenDataJson = redisTemplate.opsForValue().get(key);

        if (tokenDataJson == null) {
            throw new InvalidTokenException("Invalid or expired refresh token");
        }

        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> tokenData = objectMapper.readValue(tokenDataJson, Map.class);
            return (String) tokenData.get("userId");
        } catch (Exception e) {
            log.error("Error extracting userId from refresh token", e);
            throw new InvalidTokenException("Invalid refresh token format");
        }
    }

    /**
     * Get Username from Refresh Token
     *
     * @param refreshToken refresh token UUID
     * @return username
     */
    @Override
    public String getUsernameFromRefreshToken(String refreshToken) {
        String key = REFRESH_TOKEN_PREFIX + refreshToken;
        String tokenDataJson = redisTemplate.opsForValue().get(key);

        if (tokenDataJson == null) {
            throw new InvalidTokenException("Invalid or expired refresh token");
        }

        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> tokenData = objectMapper.readValue(tokenDataJson, Map.class);
            return (String) tokenData.get("username");
        } catch (Exception e) {
            log.error("Error extracting username from refresh token", e);
            throw new InvalidTokenException("Invalid refresh token format");
        }
    }

    /**
     * Revoke Refresh Token
     *
     * Видаляє refresh token з Redis (instant revocation).
     * Використовується при:
     * - Token rotation (старий токен видаляється)
     * - Logout
     * - Security breach
     *
     * @param refreshToken refresh token UUID
     */
    @Override
    public void revokeRefreshToken(String refreshToken) {
        String key = REFRESH_TOKEN_PREFIX + refreshToken;

        // Get userId before deleting (для видалення з user session)
        String tokenDataJson = redisTemplate.opsForValue().get(key);
        if (tokenDataJson != null) {
            try {
                @SuppressWarnings("unchecked")
                Map<String, Object> tokenData = objectMapper.readValue(tokenDataJson, Map.class);
                String userId = (String) tokenData.get("userId");

                // Remove from user session
                removeFromUserSession(userId, refreshToken);
            } catch (Exception e) {
                log.error("Error parsing token data during revocation", e);
            }
        }

        // Delete from Redis
        redisTemplate.delete(key);
        log.debug("Revoked refresh token: {}", refreshToken);
    }

    /**
     * Revoke All User Refresh Tokens
     *
     * Logout з всіх devices.
     * Видаляє всі refresh tokens для user.
     *
     * @param userId user ID
     */
    @Override
    public void revokeAllUserTokens(String userId) {
        String sessionKey = USER_SESSION_PREFIX + userId;

        // Get all refresh tokens для цього user
        Set<String> refreshTokens = redisTemplate.opsForSet().members(sessionKey);

        if (refreshTokens != null && !refreshTokens.isEmpty()) {
            // Delete all refresh tokens
            refreshTokens.forEach(token -> {
                String tokenKey = REFRESH_TOKEN_PREFIX + token;
                redisTemplate.delete(tokenKey);
            });

            // Delete user session set
            redisTemplate.delete(sessionKey);

            log.info("Revoked all tokens for user: {}", userId);
        }
    }

    /**
     * Get active session count для user
     *
     * Кількість active devices/sessions.
     *
     * @param userId user ID
     * @return count of active refresh tokens
     */
    @Override
    public long getActiveSessionCount(String userId) {
        String sessionKey = USER_SESSION_PREFIX + userId;
        Long count = redisTemplate.opsForSet().size(sessionKey);
        return count != null ? count : 0;
    }

    /**
     * Add refresh token to user session
     *
     * Tracks all active refresh tokens для user.
     * Uses Redis Set для зберігання.
     *
     * @param userId user ID
     * @param refreshToken refresh token UUID
     */
    private void addToUserSession(String userId, String refreshToken) {
        String sessionKey = USER_SESSION_PREFIX + userId;
        redisTemplate.opsForSet().add(sessionKey, refreshToken);

        // Set TTL on user session (same as refresh token TTL)
        redisTemplate.expire(sessionKey, refreshTokenExpiry, TimeUnit.MILLISECONDS);
    }

    /**
     * Remove refresh token from user session
     *
     * @param userId user ID
     * @param refreshToken refresh token UUID
     */
    private void removeFromUserSession(String userId, String refreshToken) {
        String sessionKey = USER_SESSION_PREFIX + userId;
        redisTemplate.opsForSet().remove(sessionKey, refreshToken);
    }
}
