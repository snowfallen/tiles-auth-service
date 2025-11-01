package com.tiles.auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/**
 * Refresh Token Request DTO
 *
 * Data Transfer Object для endpoints:
 * - POST /auth/refresh (refresh tokens)
 * - POST /auth/logout (logout single device)
 * - POST /auth/logout-all (logout all devices)
 *
 * REFRESH TOKEN FLOW:
 * ══════════════════
 * Token Refresh:
 * 1. Access token expires (15 min)
 * 2. Client sends refresh token (this DTO)
 * 3. Server validates refresh token (Redis)
 * 4. If valid → generate NEW tokens
 * 5. Revoke OLD refresh token (rotation)
 * 6. Return new tokens
 *
 * Logout:
 * 1. Client sends refresh token
 * 2. Server revokes token (delete від Redis)
 * 3. Return success message
 *
 * Logout All:
 * 1. Client sends refresh token (identify user)
 * 2. Server finds all user's tokens
 * 3. Revokes all tokens
 * 4. Return success message
 *
 * SINGLE FIELD:
 * ════════════
 * Only one field needed: refresh token UUID.
 *
 * Simple DTO - just UUID string.
 * Could use @RequestParam, але DTO cleaner:
 * ✅ Consistent API (all POSTs use body)
 * ✅ JSON format (same як other requests)
 * ✅ Validation (@Valid)
 * ✅ Future-proof (can add fields)
 *
 * REFRESH TOKEN FORMAT:
 * ════════════════════
 * UUID (type 4 - random):
 * Example: "550e8400-e29b-41d4-a716-446655440000"
 *
 * Format: 8-4-4-4-12 hexadecimal digits
 * Length: 36 characters (32 hex + 4 hyphens)
 *
 * WHY UUID (not JWT):
 * ══════════════════
 * Refresh tokens = Stateful (Redis storage)
 * Access tokens = Stateless (JWT, no storage)
 *
 * UUID benefits для refresh:
 * ✅ Can revoke instantly (delete від Redis)
 * ✅ Shorter (vs JWT ~200+ chars)
 * ✅ Simpler (no signature validation)
 * ✅ Redis TTL (automatic expiration)
 *
 * JWT drawbacks для refresh:
 * ❌ Cannot revoke (stateless)
 * ❌ Longer (header + payload + signature)
 * ❌ Signature overhead
 * ❌ Need blacklist (defeats stateless)
 *
 * VALIDATION:
 * ══════════
 * @NotBlank:
 * - Required field
 * - Cannot be empty
 * - Cannot be whitespace
 *
 * Error message:
 * "Refresh token is required"
 *
 * NO FORMAT VALIDATION:
 * ════════════════════
 * We don't validate UUID format here.
 *
 * Why:
 * - Redis lookup will fail if invalid
 * - InvalidTokenException thrown
 * - Same error message (security)
 *
 * Don't distinguish:
 * - Invalid format
 * - Valid format but не існує
 * - Valid але expired
 *
 * Generic message: "Invalid or expired refresh token"
 * Prevents token enumeration attacks.
 *
 * SECURITY:
 * ════════
 * Refresh token = sensitive credential.
 * Similar security як password.
 *
 * Best practices:
 * ⚠️  HTTPS only (TLS encryption)
 * ⚠️  HttpOnly cookie (XSS protection) - future
 * ⚠️  SameSite cookie (CSRF protection) - future
 * ⚠️  Secure cookie flag (HTTPS only) - future
 * ⚠️  Token rotation (one-time use)
 * ⚠️  Rate limiting (prevent abuse)
 *
 * Current: Sent в JSON body
 * Future: Consider HttpOnly cookie
 *
 * HTTPONLY COOKIE (future):
 * ════════════════════════
 * Instead of JSON body:
 *
 * Cookie: refreshToken=550e8400-e29b-41d4-a716-446655440000; HttpOnly; Secure; SameSite=Strict
 *
 * Benefits:
 * ✅ XSS protection (JS cannot access)
 * ✅ CSRF protection (SameSite)
 * ✅ Automatic sending (browser handles)
 *
 * Trade-offs:
 * ⚠️  CORS complexity
 * ⚠️  Mobile apps harder (cookie management)
 * ⚠️  Testing harder (Postman, curl)
 *
 * TOKEN ROTATION:
 * ══════════════
 * Security best practice: refresh tokens одноразові.
 *
 * Each refresh:
 * 1. Validate OLD token
 * 2. Generate NEW tokens (access + refresh)
 * 3. Revoke OLD refresh token
 * 4. Store NEW refresh token
 * 5. Return NEW tokens
 *
 * Benefits:
 * ✅ Limits stolen token lifetime
 * ✅ Detects token theft (reuse fails)
 * ✅ Reduces attack window
 *
 * REUSE DETECTION:
 * ═══════════════
 * If OLD token reused:
 * 1. Token не існує в Redis (already revoked)
 * 2. Validation fails
 * 3. InvalidTokenException
 * 4. Client must re-login
 *
 * Possible scenarios:
 * - Token stolen (attacker uses it first)
 * - Race condition (concurrent requests)
 * - Client bug (didn't update token)
 *
 * @author snowfallen
 * @version 1.0.0
 * @since 2024-10-31
 */
@Data
public class RefreshTokenRequest {

    /**
     * Refresh Token (UUID)
     *
     * UUID refresh token для token operations.
     *
     * USAGE:
     * ═════
     * Token Refresh:
     * POST /auth/refresh
     * {
     *   "refreshToken": "550e8400-e29b-41d4-a716-446655440000"
     * }
     *
     * Logout:
     * POST /auth/logout
     * {
     *   "refreshToken": "550e8400-e29b-41d4-a716-446655440000"
     * }
     *
     * Logout All:
     * POST /auth/logout-all
     * {
     *   "refreshToken": "550e8400-e29b-41d4-a716-446655440000"
     * }
     *
     * VALIDATION:
     * ══════════
     * @NotBlank:
     * - Required field
     * - Cannot be null, empty, або whitespace
     *
     * Error:
     * {
     *   "timestamp": "2024-10-31T12:30:00",
     *   "status": 400,
     *   "error": "Bad Request",
     *   "message": "Validation failed",
     *   "validationErrors": {
     *     "refreshToken": "Refresh token is required"
     *   }
     * }
     *
     * REDIS LOOKUP:
     * ════════════
     * Token used as Redis key:
     * Key: refresh_token:550e8400-e29b-41d4-a716-446655440000
     * Value: {"userId":"...","username":"...","issuedAt":...,"expiresAt":...}
     *
     * Validation process:
     * 1. GET від Redis
     * 2. If null → token не існує (invalid)
     * 3. If exists → parse JSON
     * 4. Check expiresAt (extra safety)
     * 5. If valid → proceed
     *
     * TOKEN LIFETIME:
     * ══════════════
     * TTL: 7 days (604800000 milliseconds)
     *
     * Redis automatically deletes після TTL.
     * But we also check expiresAt explicitly.
     *
     * SECURITY:
     * ════════
     * ⚠️  Treat як sensitive credential
     * ⚠️  Never log full token
     * ⚠️  HTTPS only
     * ⚠️  Token rotation (one-time use)
     *
     * Logging (safe):
     * log.debug("Token refresh: tokenId={}", token.substring(0, 8) + "...");
     *
     * Output: "Token refresh: tokenId=550e8400..."
     *
     * STORAGE (client-side):
     * ═════════════════════
     * Where to store refresh token:
     *
     * Web (browser):
     * - HttpOnly cookie (best) - future
     * - LocalStorage (XSS risk) - current
     * - SessionStorage (lost on tab close)
     * - Memory only (lost on refresh)
     *
     * Mobile:
     * - Secure storage (Keychain, KeyStore)
     * - Encrypted SharedPreferences
     * - Not в plain files
     *
     * Desktop:
     * - OS credential manager
     * - Encrypted config file
     * - Memory (session only)
     *
     * RECOMMENDED:
     * ═══════════
     * HttpOnly cookie (future implementation):
     * ✅ XSS protection
     * ✅ CSRF protection (SameSite)
     * ✅ Browser handles security
     *
     * Current (LocalStorage):
     * ⚠️  XSS vulnerability
     * ⚠️  Manual CSRF protection needed
     * ⚠️  Client manages security
     */
    @NotBlank(message = "Refresh token is required")
    private String refreshToken;
}
