package com.tiles.auth.exception;

/**
 * Invalid Token Exception
 *
 * Thrown when refresh token validation fails.
 *
 * USE CASES:
 * ═════════
 * Token validation failures:
 * - Refresh token не існує (not в Redis)
 * - Refresh token expired
 * - Refresh token invalid format
 * - Token already revoked (logout)
 * - Token reused (rotation violation)
 *
 * WHEN THROWN:
 * ═══════════
 * RefreshTokenServiceImpl:
 * - validateRefreshToken() → token not found
 * - validateRefreshToken() → token expired
 * - getUserIdFromRefreshToken() → token not found
 * - getUsernameFromRefreshToken() → token not found
 *
 * AuthServiceImpl:
 * - refreshToken() → validation failed
 * - logout() → validation failed
 * - logoutAll() → validation failed
 *
 * HANDLING:
 * ════════
 * GlobalExceptionHandler catches this exception.
 *
 * Handler method:
 * @ExceptionHandler(InvalidTokenException.class)
 *
 * Response:
 * - HTTP 401 Unauthorized
 * - Generic error message
 *
 * ERROR RESPONSE:
 * ══════════════
 * {
 *   "timestamp": "2024-10-31T12:30:00",
 *   "status": 401,
 *   "error": "Unauthorized",
 *   "message": "Invalid or expired refresh token"
 * }
 *
 * WHY GENERIC MESSAGE:
 * ═══════════════════
 * Security: Don't reveal token details.
 *
 * Bad (reveals info):
 * - "Token not found" → Token format valid, не існує
 * - "Token expired" → Token existed, now expired
 * - "Token revoked" → Token valid, manually revoked
 *
 * Attacker can:
 * - Enumerate valid tokens
 * - Learn token lifecycle
 * - Gather system information
 *
 * Good (generic):
 * - "Invalid or expired refresh token" → No details
 *
 * Cannot distinguish:
 * - Token not found
 * - Token expired
 * - Token revoked
 * - Token invalid format
 *
 * HTTP STATUS CODE:
 * ════════════════
 * 401 Unauthorized:
 * - Token invalid
 * - Cannot refresh tokens
 * - Client should re-login
 *
 * Why 401 (not 403):
 * - 401: Authentication failed (who are you?)
 * - 403: Authorization failed (you can't do this)
 *
 * Token validation = authentication.
 *
 * CLIENT ACTION:
 * ═════════════
 * On 401 від /auth/refresh:
 * 1. Refresh failed
 * 2. Clear stored tokens
 * 3. Redirect to login
 * 4. Show message: "Session expired, please login"
 *
 * EXCEPTION HIERARCHY:
 * ═══════════════════
 * RuntimeException
 *   ↓
 * InvalidTokenException
 *
 * Unchecked exception:
 * - No throws declaration needed
 * - Clean service methods
 * - Caught by GlobalExceptionHandler
 *
 * CONSTRUCTOR:
 * ═══════════
 * Single constructor з message parameter.
 *
 * Usage:
 * throw new InvalidTokenException("Invalid or expired refresh token");
 *
 * Message should always be generic:
 * ✅ "Invalid or expired refresh token"
 * ✅ "Invalid refresh token"
 *
 * Never specific:
 * ❌ "Token not found"
 * ❌ "Token expired"
 * ❌ "Token revoked"
 *
 * USAGE EXAMPLES:
 * ══════════════
 *
 * Example 1: Token not found
 * String tokenData = redisTemplate.opsForValue().get(key);
 * if (tokenData == null) {
 *     throw new InvalidTokenException("Invalid or expired refresh token");
 * }
 *
 * Example 2: Token expired
 * long now = System.currentTimeMillis();
 * if (now > expiresAt) {
 *     revokeRefreshToken(refreshToken);
 *     throw new InvalidTokenException("Refresh token expired");
 * }
 *
 * Example 3: Invalid format
 * try {
 *     Map<String, Object> tokenData = objectMapper.readValue(json, Map.class);
 * } catch (Exception e) {
 *     throw new InvalidTokenException("Invalid refresh token format");
 * }
 *
 * TOKEN LIFECYCLE:
 * ═══════════════
 * Valid states:
 * 1. Active (stored в Redis, not expired)
 * 2. Expired (expiresAt < now, or Redis TTL expired)
 * 3. Revoked (deleted від Redis, logout)
 *
 * Transitions:
 * - Issue → Active
 * - Active → Expired (time passes)
 * - Active → Revoked (logout)
 * - Expired → Deleted (Redis TTL)
 *
 * CAUSES:
 * ══════
 *
 * Token не існує:
 * - Never issued (fake token)
 * - Already revoked (logout)
 * - Expired і cleaned up (Redis TTL)
 *
 * Token expired:
 * - Issued > 7 days ago
 * - Redis TTL expired (automatic deletion)
 * - Explicit expiry check (expiresAt < now)
 *
 * Token rotation:
 * - OLD token used після refresh
 * - Already revoked (one-time use)
 * - NEW token should be used
 *
 * SECURITY IMPLICATIONS:
 * ═════════════════════
 * Token reuse detection:
 * - Indicates stolen token
 * - Attacker і victim both use token
 * - First use succeeds, revokes token
 * - Second use fails (token gone)
 *
 * Response:
 * - Force re-authentication
 * - Monitor для suspicious activity
 * - Consider revoking all user tokens
 * - Alert user (email)
 *
 * TOKEN VALIDATION:
 * ════════════════
 * Two-layer validation:
 *
 * Layer 1: Redis existence
 * - GET від Redis
 * - If null → не існує
 *
 * Layer 2: Expiry check
 * - Parse expiresAt від token data
 * - Compare з current time
 * - If expired → invalid
 *
 * Why two layers:
 * ✅ Redis TTL (automatic cleanup)
 * ✅ Explicit check (defense in depth)
 * ✅ Different failure modes
 *
 * LOGGING:
 * ═══════
 * Exception logged в:
 * - GlobalExceptionHandler (WARN level)
 * - RefreshTokenService (DEBUG level)
 *
 * Logged data:
 * ✅ Exception message
 * ✅ Token ID (first 8 chars only)
 * ✅ User ID (if extractable)
 * ✅ Timestamp
 * ❌ Full token (security risk)
 *
 * Safe logging:
 * log.warn("Invalid token: tokenId={}",
 *     token.substring(0, 8) + "...");
 *
 * CLIENT HANDLING:
 * ═══════════════
 * JavaScript example:
 *
 * async function refreshToken() {
 *   const refreshToken = localStorage.getItem('refreshToken');
 *
 *   try {
 *     const response = await fetch('/auth/refresh', {
 *       method: 'POST',
 *       headers: { 'Content-Type': 'application/json' },
 *       body: JSON.stringify({ refreshToken })
 *     });
 *
 *     if (response.ok) {
 *       const data = await response.json();
 *       // Update tokens
 *       localStorage.setItem('accessToken', data.accessToken);
 *       localStorage.setItem('refreshToken', data.refreshToken);
 *       return data.accessToken;
 *     } else if (response.status === 401) {
 *       // Refresh failed → re-login
 *       handleSessionExpired();
 *     }
 *   } catch (error) {
 *     handleSessionExpired();
 *   }
 * }
 *
 * function handleSessionExpired() {
 *   // Clear tokens
 *   localStorage.removeItem('accessToken');
 *   localStorage.removeItem('refreshToken');
 *
 *   // Show message
 *   showMessage('Session expired. Please login again.');
 *
 *   // Redirect to login
 *   window.location.href = '/login';
 * }
 *
 * TESTING:
 * ═══════
 * Unit test:
 *
 * @Test
 * void testInvalidTokenException() {
 *     // Given
 *     String message = "Invalid or expired refresh token";
 *
 *     // When
 *     InvalidTokenException ex = new InvalidTokenException(message);
 *
 *     // Then
 *     assertEquals(message, ex.getMessage());
 *     assertTrue(ex instanceof RuntimeException);
 * }
 *
 * Integration test:
 *
 * @Test
 * void testRefreshWithInvalidToken() {
 *     // Given
 *     RefreshTokenRequest request = new RefreshTokenRequest();
 *     request.setRefreshToken("invalid-token-12345");
 *
 *     // When
 *     ResponseEntity<?> response = authController.refresh(request);
 *
 *     // Then
 *     assertEquals(401, response.getStatusCodeValue());
 *
 *     Map<String, Object> body = (Map<String, Object>) response.getBody();
 *     assertTrue(body.get("message").toString()
 *         .contains("Invalid or expired"));
 * }
 *
 * MONITORING:
 * ══════════
 * Track metrics:
 * - Invalid token rate (failures / attempts)
 * - Token reuse attempts (security indicator)
 * - Expiration patterns (lifecycle analysis)
 *
 * Alert on:
 * - High invalid token rate (> 10%)
 * - Token reuse detected (potential theft)
 * - Unusual patterns (mass expiration)
 *
 * ALTERNATIVES:
 * ════════════
 * Could use different exceptions:
 * - TokenNotFoundException
 * - TokenExpiredException
 * - TokenRevokedException
 *
 * Why single exception:
 * ✅ Simpler error handling
 * ✅ Generic message (security)
 * ✅ Single HTTP status (401)
 * ✅ Client action same (re-login)
 *
 * RELATED SCENARIOS:
 * ═════════════════
 *
 * Concurrent refresh:
 * - Two requests refresh simultaneously
 * - First succeeds, revokes OLD token
 * - Second fails (OLD token gone)
 * → InvalidTokenException
 *
 * Logout during refresh:
 * - User clicks logout
 * - Token revoked
 * - Background refresh attempts
 * → InvalidTokenException (expected)
 *
 * Key rotation:
 * - NOT this exception (access tokens)
 * - Refresh tokens = UUID (no keys)
 * - Key rotation affects JWT validation (Gateway)
 *
 * @author snowfallen
 * @version 1.0.0
 * @since 2024-10-31
 */
public class InvalidTokenException extends RuntimeException {

    /**
     * Constructor
     *
     * Creates exception з generic message.
     *
     * MESSAGE GUIDELINES:
     * ══════════════════
     * Always use generic messages:
     * ✅ "Invalid or expired refresh token"
     * ✅ "Invalid refresh token"
     *
     * Never reveal specifics:
     * ❌ "Token not found"
     * ❌ "Token expired at 2024-10-31T12:30:00"
     * ❌ "Token revoked"
     *
     * Why generic:
     * - Security (no info leakage)
     * - Simplicity (single message)
     * - Standard practice (OAuth2)
     *
     * Internal logging:
     * - Can be specific (not shown to client)
     * - Include details (debugging)
     * - Log token ID prefix only
     *
     * USAGE:
     * ═════
     * throw new InvalidTokenException("Invalid or expired refresh token");
     *
     * Message available via:
     * - ex.getMessage()
     * - Used в GlobalExceptionHandler
     * - Returned в error response
     *
     * @param message error message (generic recommended)
     */
    public InvalidTokenException(String message) {
        // Pass message to parent RuntimeException
        // Available via getMessage()
        super(message);
    }
}