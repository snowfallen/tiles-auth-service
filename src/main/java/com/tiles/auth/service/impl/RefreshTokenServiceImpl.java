package com.tiles.auth.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tiles.auth.exception.InvalidTokenException;
import com.tiles.auth.service.RefreshTokenService;
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
 * Refresh Token Service Implementation
 *
 * Manages refresh tokens в Redis storage.
 *
 * RESPONSIBILITIES:
 * ═══════════════
 * - Generate UUID refresh tokens
 * - Store token data в Redis
 * - Validate tokens (check existence + expiration)
 * - Revoke tokens (instant invalidation)
 * - Track user sessions (multiple devices)
 *
 * REDIS DATA MODEL:
 * ════════════════
 *
 * 1. Refresh Token Data:
 * ─────────────────────
 * Key: refresh_token:{uuid}
 * Value: JSON string
 * {
 *   "userId": "user-uuid",
 *   "username": "admin",
 *   "email": "admin@example.com",
 *   "issuedAt": 1698758400000,
 *   "expiresAt": 1699363200000
 * }
 * TTL: 7 days (604800000 milliseconds)
 *
 * 2. User Session Set:
 * ──────────────────
 * Key: user_session:{userId}
 * Value: Redis Set
 * {
 *   "uuid-1",  // Desktop token
 *   "uuid-2",  // Mobile token
 *   "uuid-3"   // Tablet token
 * }
 * TTL: 7 days
 *
 * REFRESH TOKEN FLOW:
 * ══════════════════
 *
 * Login:
 * 1. Generate UUID
 * 2. Store token data в Redis
 * 3. Add UUID до user session set
 * 4. Return UUID до client
 *
 * Refresh:
 * 1. Validate token (check Redis)
 * 2. Extract user info
 * 3. Generate NEW token
 * 4. Revoke OLD token (rotation)
 * 5. Return NEW token
 *
 * Logout:
 * 1. Delete token від Redis
 * 2. Remove від user session set
 *
 * Logout All:
 * 1. Get all tokens від user session set
 * 2. Delete each token
 * 3. Delete session set
 *
 * SECURITY:
 * ════════
 * ✅ Token rotation (одноразові tokens)
 * ✅ Automatic expiration (Redis TTL)
 * ✅ Instant revocation (delete від Redis)
 * ✅ Session tracking (logout all devices)
 * ✅ Auditing (issuedAt, expiresAt timestamps)
 *
 * WHY UUID (not JWT):
 * ══════════════════
 * ✅ Stateful (can revoke instantly)
 * ✅ Shorter length (better для mobile)
 * ✅ Single purpose (only для refresh)
 * ✅ Redis TTL handles expiration
 * ✅ No signature validation needed
 *
 * @author snowfallen
 * @version 1.0.0
 * @since 2024-10-31
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenServiceImpl implements RefreshTokenService {

    /**
     * Redis Template
     *
     * High-level abstraction для Redis operations.
     * Configured з String serializers (keys + values).
     *
     * Operations:
     * - opsForValue(): String operations (GET, SET)
     * - opsForSet(): Set operations (SADD, SMEMBERS)
     * - delete(): Delete keys
     * - expire(): Set TTL
     */
    private final RedisTemplate<String, String> redisTemplate;

    /**
     * Object Mapper
     *
     * Jackson ObjectMapper для JSON serialization.
     * Converts Java objects ↔ JSON strings.
     *
     * Configured з:
     * - JavaTimeModule (LocalDateTime support)
     * - ISO-8601 date format
     * - No pretty printing (compact JSON)
     */
    private final ObjectMapper objectMapper;

    /**
     * Refresh Token Expiry
     *
     * How long refresh token valid (milliseconds).
     *
     * Default: 604800000ms = 7 days
     *
     * Loaded від application.yml:
     * jwt.refresh-token-expiry: 604800000
     *
     * This is:
     * - Redis TTL (automatic deletion)
     * - Expiry timestamp в token data
     */
    @Value("${jwt.refresh-token-expiry}")
    private Long refreshTokenExpiry;

    /**
     * Redis Key Prefixes
     *
     * Namespacing для Redis keys.
     * Prevents collisions з other services.
     *
     * Pattern: prefix:identifier
     * Example: refresh_token:550e8400-e29b-41d4-a716-446655440000
     */
    private static final String REFRESH_TOKEN_PREFIX = "refresh_token:";
    private static final String USER_SESSION_PREFIX = "user_session:";

    /**
     * Generate Refresh Token
     *
     * Creates UUID refresh token і stores в Redis.
     *
     * PROCESS:
     * ═══════
     * 1. Generate random UUID
     * 2. Calculate timestamps (issuedAt, expiresAt)
     * 3. Create token data map
     * 4. Serialize to JSON
     * 5. Store в Redis з TTL
     * 6. Add UUID до user session set
     * 7. Return UUID
     *
     * TOKEN DATA STRUCTURE:
     * ════════════════════
     * Map<String, Object> containing:
     * - userId: User's UUID (primary identifier)
     * - username: User's login name (for convenience)
     * - email: User's email (for convenience)
     * - issuedAt: Token creation timestamp (milliseconds)
     * - expiresAt: Token expiration timestamp (milliseconds)
     *
     * Why store username/email:
     * ✅ Quick user identification (no DB query)
     * ✅ Audit trail (who used token)
     * ✅ Logging/debugging
     *
     * REDIS STORAGE:
     * ═════════════
     * Key: refresh_token:{uuid}
     * Value: {"userId":"...","username":"...","issuedAt":...,"expiresAt":...}
     * TTL: 7 days
     *
     * Redis automatically deletes expired keys.
     * But we also check expiresAt explicitly (defense in depth).
     *
     * USER SESSION TRACKING:
     * ═════════════════════
     * Also adds token UUID до user session set.
     * This enables "logout all devices" functionality.
     *
     * Key: user_session:{userId}
     * Value: Set {uuid1, uuid2, uuid3}
     *
     * @param userId user UUID
     * @param username username
     * @param email email address
     * @return refresh token UUID string
     */
    @Override
    public String generateRefreshToken(String userId, String username, String email) {
        log.debug("Generating refresh token for user: userId={}, username={}",
                userId, username);

        // ════════════════════════════════════════
        // Step 1: Generate UUID
        // ════════════════════════════════════════
        // UUID.randomUUID() generates type 4 UUID (random)
        // Example: 550e8400-e29b-41d4-a716-446655440000
        String refreshToken = UUID.randomUUID().toString();

        log.debug("Generated refresh token UUID: {}", refreshToken);

        // ════════════════════════════════════════
        // Step 2: Calculate Timestamps
        // ════════════════════════════════════════
        // Current time (issued at)
        long now = System.currentTimeMillis();

        // Expiration time (issued at + TTL)
        long expiresAt = now + refreshTokenExpiry;

        log.debug("Token expiry calculated: issuedAt={}, expiresAt={}, ttl={}ms",
                now, expiresAt, refreshTokenExpiry);

        // ════════════════════════════════════════
        // Step 3: Create Token Data
        // ════════════════════════════════════════
        // Map containing all token information
        // Will be serialized to JSON
        Map<String, Object> tokenData = new HashMap<>();
        tokenData.put("userId", userId);
        tokenData.put("username", username);
        tokenData.put("email", email);
        tokenData.put("issuedAt", now);
        tokenData.put("expiresAt", expiresAt);

        try {
            // ════════════════════════════════════════
            // Step 4: Serialize to JSON
            // ════════════════════════════════════════
            // ObjectMapper converts Map → JSON string
            // Example output:
            // {"userId":"123","username":"admin","email":"admin@example.com",...}
            String tokenDataJson = objectMapper.writeValueAsString(tokenData);

            log.debug("Token data serialized to JSON: {} bytes",
                    tokenDataJson.length());

            // ════════════════════════════════════════
            // Step 5: Store в Redis з TTL
            // ════════════════════════════════════════
            // Build Redis key: refresh_token:{uuid}
            String key = REFRESH_TOKEN_PREFIX + refreshToken;

            // Store in Redis з automatic expiration
            // opsForValue() = String operations (GET/SET)
            // Duration.ofMillis() creates TTL duration
            redisTemplate.opsForValue().set(
                    key,                                    // Key
                    tokenDataJson,                          // Value (JSON)
                    Duration.ofMillis(refreshTokenExpiry)   // TTL
            );

            log.debug("Token stored in Redis with TTL: key={}, ttl={}ms",
                    key, refreshTokenExpiry);

            // ════════════════════════════════════════
            // Step 6: Track User Session
            // ════════════════════════════════════════
            // Add token UUID до user's session set
            // Enables "logout all devices" functionality
            addToUserSession(userId, refreshToken);

            log.info("Refresh token generated successfully: userId={}, tokenId={}",
                    userId, refreshToken);

            return refreshToken;

        } catch (Exception e) {
            // JSON serialization error або Redis connection error
            log.error("Failed to generate refresh token: userId={}", userId, e);
            throw new RuntimeException("Failed to generate refresh token", e);
        }
    }

    /**
     * Validate Refresh Token
     *
     * Checks if token exists і not expired.
     *
     * VALIDATION CHECKS:
     * ═════════════════
     * ✅ Token exists в Redis
     * ✅ Token not expired (expiresAt > now)
     * ✅ Token data valid JSON
     *
     * Note: Redis TTL automatically deletes expired tokens,
     * але ми також перевіряємо expiresAt явно (extra safety).
     *
     * PROCESS:
     * ═══════
     * 1. Build Redis key від UUID
     * 2. GET від Redis
     * 3. Check if value exists
     * 4. Parse JSON → Map
     * 5. Extract expiresAt timestamp
     * 6. Compare з current time
     * 7. Return true if valid, throw exception if invalid
     *
     * ERRORS:
     * ══════
     * - Token not found в Redis → InvalidTokenException
     * - Token expired (expiresAt < now) → InvalidTokenException
     * - Invalid JSON format → InvalidTokenException
     *
     * WHY TWO EXPIRATION CHECKS:
     * ═════════════════════════
     * 1. Redis TTL (automatic cleanup)
     * 2. expiresAt check (explicit validation)
     *
     * Defense in depth:
     * - If Redis TTL fails, expiresAt catches it
     * - If time sync issues, explicit check helps
     * - Better logging (know why token invalid)
     *
     * @param refreshToken refresh token UUID
     * @return true if valid
     * @throws InvalidTokenException if invalid
     */
    @Override
    public boolean validateRefreshToken(String refreshToken) {
        log.debug("Validating refresh token: tokenId={}", refreshToken);

        // ════════════════════════════════════════
        // Step 1: Build Redis Key
        // ════════════════════════════════════════
        String key = REFRESH_TOKEN_PREFIX + refreshToken;

        // ════════════════════════════════════════
        // Step 2: Get Token Data від Redis
        // ════════════════════════════════════════
        // opsForValue().get() returns null if key not exists
        String tokenDataJson = redisTemplate.opsForValue().get(key);

        // ════════════════════════════════════════
        // Step 3: Check Existence
        // ════════════════════════════════════════
        if (tokenDataJson == null) {
            log.warn("Refresh token not found in Redis: tokenId={}", refreshToken);
            throw new InvalidTokenException("Invalid or expired refresh token");
        }

        log.debug("Token found in Redis, validating expiration...");

        try {
            // ════════════════════════════════════════
            // Step 4: Parse JSON → Map
            // ════════════════════════════════════════
            // ObjectMapper deserializes JSON → Map<String, Object>
            @SuppressWarnings("unchecked")
            Map<String, Object> tokenData =
                    objectMapper.readValue(tokenDataJson, Map.class);

            // ════════════════════════════════════════
            // Step 5: Extract Expiration Timestamp
            // ════════════════════════════════════════
            // expiresAt stored як Number (Long або Integer)
            // Cast to Number first, then get Long value
            Long expiresAt = ((Number) tokenData.get("expiresAt")).longValue();

            log.debug("Token expiration timestamp: expiresAt={}", expiresAt);

            // ════════════════════════════════════════
            // Step 6: Check Expiration
            // ════════════════════════════════════════
            // Compare expiration timestamp з current time
            long now = System.currentTimeMillis();

            if (now > expiresAt) {
                // Token expired (current time past expiration)
                log.warn("Refresh token expired: tokenId={}, expiresAt={}, now={}",
                        refreshToken, expiresAt, now);

                // Clean up: delete expired token від Redis
                // (Redis TTL should handle this, but explicit cleanup good)
                revokeRefreshToken(refreshToken);

                throw new InvalidTokenException("Refresh token expired");
            }

            log.debug("Refresh token validated successfully: tokenId={}", refreshToken);
            return true;

        } catch (InvalidTokenException e) {
            // Rethrow InvalidTokenException (already formatted)
            throw e;

        } catch (Exception e) {
            // JSON parsing error або other unexpected error
            log.error("Error validating refresh token: tokenId={}", refreshToken, e);
            throw new InvalidTokenException("Invalid refresh token format");
        }
    }

    /**
     * Get User ID від Refresh Token
     *
     * Extracts userId від token data в Redis.
     *
     * PROCESS:
     * ═══════
     * 1. Build Redis key
     * 2. GET token data від Redis
     * 3. Check if exists
     * 4. Parse JSON → Map
     * 5. Extract userId
     * 6. Return userId
     *
     * @param refreshToken refresh token UUID
     * @return userId (UUID string)
     * @throws InvalidTokenException if token not found
     */
    @Override
    public String getUserIdFromRefreshToken(String refreshToken) {
        log.debug("Extracting userId from refresh token: tokenId={}", refreshToken);

        String key = REFRESH_TOKEN_PREFIX + refreshToken;
        String tokenDataJson = redisTemplate.opsForValue().get(key);

        if (tokenDataJson == null) {
            log.warn("Refresh token not found: tokenId={}", refreshToken);
            throw new InvalidTokenException("Invalid or expired refresh token");
        }

        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> tokenData =
                    objectMapper.readValue(tokenDataJson, Map.class);

            String userId = (String) tokenData.get("userId");

            log.debug("Extracted userId from token: userId={}", userId);
            return userId;

        } catch (Exception e) {
            log.error("Error extracting userId from refresh token: tokenId={}",
                    refreshToken, e);
            throw new InvalidTokenException("Invalid refresh token format");
        }
    }

    /**
     * Get Username від Refresh Token
     *
     * Extracts username від token data в Redis.
     *
     * @param refreshToken refresh token UUID
     * @return username
     * @throws InvalidTokenException if token not found
     */
    @Override
    public String getUsernameFromRefreshToken(String refreshToken) {
        log.debug("Extracting username from refresh token: tokenId={}", refreshToken);

        String key = REFRESH_TOKEN_PREFIX + refreshToken;
        String tokenDataJson = redisTemplate.opsForValue().get(key);

        if (tokenDataJson == null) {
            log.warn("Refresh token not found: tokenId={}", refreshToken);
            throw new InvalidTokenException("Invalid or expired refresh token");
        }

        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> tokenData =
                    objectMapper.readValue(tokenDataJson, Map.class);

            String username = (String) tokenData.get("username");

            log.debug("Extracted username from token: username={}", username);
            return username;

        } catch (Exception e) {
            log.error("Error extracting username from refresh token: tokenId={}",
                    refreshToken, e);
            throw new InvalidTokenException("Invalid refresh token format");
        }
    }

    /**
     * Revoke Refresh Token
     *
     * Instantly invalidates token (delete від Redis).
     *
     * PROCESS:
     * ═══════
     * 1. Get token data (для extract userId)
     * 2. Remove token від user session set
     * 3. Delete token від Redis
     *
     * USE CASES:
     * ═════════
     * - Logout (user-initiated)
     * - Token rotation (old token after refresh)
     * - Security breach (forced revocation)
     * - Account disabled (revoke all sessions)
     *
     * INSTANT INVALIDATION:
     * ════════════════════
     * Unlike JWT (cannot revoke без blacklist),
     * refresh tokens instantly revoked.
     *
     * Just delete від Redis → immediately invalid.
     *
     * @param refreshToken refresh token UUID to revoke
     */
    @Override
    public void revokeRefreshToken(String refreshToken) {
        log.info("Revoking refresh token: tokenId={}", refreshToken);

        String key = REFRESH_TOKEN_PREFIX + refreshToken;

        // ════════════════════════════════════════
        // Step 1: Get Token Data (before deleting)
        // ════════════════════════════════════════
        // Need userId to remove від user session set
        String tokenDataJson = redisTemplate.opsForValue().get(key);

        if (tokenDataJson != null) {
            try {
                // Extract userId від token data
                @SuppressWarnings("unchecked")
                Map<String, Object> tokenData =
                        objectMapper.readValue(tokenDataJson, Map.class);
                String userId = (String) tokenData.get("userId");

                log.debug("Removing token from user session: userId={}", userId);

                // ════════════════════════════════════════
                // Step 2: Remove від User Session Set
                // ════════════════════════════════════════
                removeFromUserSession(userId, refreshToken);

            } catch (Exception e) {
                // If parsing fails, just log warning
                // Still proceed with token deletion
                log.warn("Error parsing token data during revocation: tokenId={}",
                        refreshToken, e);
            }
        }

        // ════════════════════════════════════════
        // Step 3: Delete Token від Redis
        // ════════════════════════════════════════
        // This instantly invalidates token
        redisTemplate.delete(key);

        log.info("Refresh token revoked successfully: tokenId={}", refreshToken);
    }

    /**
     * Revoke All User Tokens
     *
     * Logout з всіх devices (revoke all tokens).
     *
     * PROCESS:
     * ═══════
     * 1. Build user session key
     * 2. Get all token UUIDs від session set
     * 3. Delete each token від Redis
     * 4. Delete user session set
     *
     * USE CASES:
     * ═════════
     * - User clicks "Logout from all devices"
     * - Password changed (security measure)
     * - Account compromised
     * - Security breach suspected
     * - Admin forces logout
     *
     * USER SESSION SET:
     * ════════════════
     * Key: user_session:{userId}
     * Value: Set {uuid1, uuid2, uuid3}
     *
     * Each UUID = one device/session.
     *
     * REDIS SET OPERATIONS:
     * ════════════════════
     * SMEMBERS: Get all members від set
     * DEL: Delete individual tokens
     * DEL: Delete session set
     *
     * @param userId user UUID
     */
    @Override
    public void revokeAllUserTokens(String userId) {
        log.info("Revoking all refresh tokens for user: userId={}", userId);

        // ════════════════════════════════════════
        // Step 1: Build Session Key
        // ════════════════════════════════════════
        String sessionKey = USER_SESSION_PREFIX + userId;

        // ════════════════════════════════════════
        // Step 2: Get All Token UUIDs
        // ════════════════════════════════════════
        // opsForSet().members() returns all items від set
        // Returns Set<String> of token UUIDs
        Set<String> refreshTokens = redisTemplate.opsForSet().members(sessionKey);

        if (refreshTokens != null && !refreshTokens.isEmpty()) {
            log.debug("Found {} active tokens for user: userId={}",
                    refreshTokens.size(), userId);

            // ════════════════════════════════════════
            // Step 3: Delete All Tokens
            // ════════════════════════════════════════
            // Iterate through each token UUID
            refreshTokens.forEach(tokenUuid -> {
                // Build token key: refresh_token:{uuid}
                String tokenKey = REFRESH_TOKEN_PREFIX + tokenUuid;

                // Delete token від Redis
                redisTemplate.delete(tokenKey);

                log.debug("Deleted token: tokenId={}", tokenUuid);
            });

            // ════════════════════════════════════════
            // Step 4: Delete Session Set
            // ════════════════════════════════════════
            // Remove user session set itself
            redisTemplate.delete(sessionKey);

            log.info("Revoked all tokens for user: userId={}, count={}",
                    userId, refreshTokens.size());
        } else {
            log.debug("No active tokens found for user: userId={}", userId);
        }
    }

    /**
     * Get Active Session Count
     *
     * Returns count of active refresh tokens для user.
     *
     * Each token = one device/browser session.
     *
     * PROCESS:
     * ═══════
     * 1. Build session key
     * 2. Get set size від Redis
     * 3. Return count
     *
     * REDIS OPERATION:
     * ═══════════════
     * SCARD: Returns cardinality (size) of set
     * Efficient: O(1) operation (no need to fetch all members)
     *
     * USE CASES:
     * ═════════
     * - Show user: "You're logged in on 3 devices"
     * - Security monitoring (unusual activity)
     * - Rate limiting (max sessions per user)
     * - Analytics (concurrent sessions)
     *
     * @param userId user UUID
     * @return count of active tokens
     */
    @Override
    public long getActiveSessionCount(String userId) {
        log.debug("Getting active session count for user: userId={}", userId);

        String sessionKey = USER_SESSION_PREFIX + userId;

        // opsForSet().size() returns count of set members
        // Returns null if set doesn't exist
        Long count = redisTemplate.opsForSet().size(sessionKey);

        long sessionCount = count != null ? count : 0;

        log.debug("Active session count: userId={}, count={}", userId, sessionCount);

        return sessionCount;
    }

    /**
     * Add Token to User Session
     *
     * Tracks token в user session set (для logout all).
     *
     * PROCESS:
     * ═══════
     * 1. Build session key
     * 2. Add token UUID до set
     * 3. Set TTL on session set
     *
     * REDIS OPERATIONS:
     * ════════════════
     * SADD: Add member до set
     * EXPIRE: Set TTL on key
     *
     * TTL:
     * Same як refresh token TTL (7 days).
     * Session set automatically deleted when last token expires.
     *
     * @param userId user UUID
     * @param refreshToken refresh token UUID
     */
    private void addToUserSession(String userId, String refreshToken) {
        log.debug("Adding token to user session: userId={}, tokenId={}",
                userId, refreshToken);

        String sessionKey = USER_SESSION_PREFIX + userId;

        // Add token UUID до set
        // opsForSet().add() = SADD command
        redisTemplate.opsForSet().add(sessionKey, refreshToken);

        // Set TTL on session set (same як token TTL)
        // This ensures session set automatically deleted
        redisTemplate.expire(sessionKey, refreshTokenExpiry, TimeUnit.MILLISECONDS);

        log.debug("Token added to user session: sessionKey={}", sessionKey);
    }

    /**
     * Remove Token від User Session
     *
     * Removes token UUID від user session set.
     *
     * Called when:
     * - Token revoked (logout)
     * - Token rotated (refresh)
     *
     * REDIS OPERATION:
     * ═══════════════
     * SREM: Remove member від set
     *
     * @param userId user UUID
     * @param refreshToken refresh token UUID
     */
    private void removeFromUserSession(String userId, String refreshToken) {
        log.debug("Removing token from user session: userId={}, tokenId={}",
                userId, refreshToken);

        String sessionKey = USER_SESSION_PREFIX + userId;

        // Remove token UUID від set
        // opsForSet().remove() = SREM command
        redisTemplate.opsForSet().remove(sessionKey, refreshToken);

        log.debug("Token removed from user session: sessionKey={}", sessionKey);
    }
}
