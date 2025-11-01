package com.tiles.auth.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Login Response DTO
 *
 * Response для successful authentication endpoints:
 * - POST /auth/login
 * - POST /auth/register (auto-login)
 *
 * RESPONSE STRUCTURE:
 * ══════════════════
 * Complete authentication response containing:
 * - Access token (JWT, 15 min)
 * - Refresh token (UUID, 7 days)
 * - Token metadata (type, expiry)
 * - User information (profile data)
 *
 * CLIENT FLOW:
 * ═══════════
 * 1. Client receives LoginResponse
 * 2. Extracts accessToken
 * 3. Stores accessToken (memory або localStorage)
 * 4. Extracts refreshToken
 * 5. Stores refreshToken (secure storage)
 * 6. Extracts user info
 * 7. Updates UI (welcome message, profile)
 * 8. Uses accessToken для API requests:
 *    Authorization: Bearer <accessToken>
 *
 * TOKEN USAGE:
 * ═══════════
 * Access Token:
 * - Short-lived (15 minutes)
 * - Used для API requests
 * - Sent в Authorization header
 * - Cannot be revoked (stateless JWT)
 *
 * Refresh Token:
 * - Long-lived (7 days)
 * - Used to get new access token
 * - Sent when access token expires
 * - Can be revoked (Redis storage)
 *
 * WHY BOTH TOKENS:
 * ═══════════════
 * Security trade-off:
 *
 * Short-lived access token:
 * ✅ Limits stolen token damage (15 min max)
 * ✅ Stateless (no DB lookup)
 * ✅ Fast validation (signature check)
 * ❌ Cannot revoke immediately
 *
 * Long-lived refresh token:
 * ✅ Better UX (less frequent login)
 * ✅ Can revoke (logout works)
 * ✅ Tracked sessions (logout all)
 * ❌ More sensitive (longer lifetime)
 * ❌ Requires storage (Redis)
 *
 * LOMBOK ANNOTATIONS:
 * ══════════════════
 * @Data: Generates getters, setters, toString, equals, hashCode
 * @Builder: Builder pattern для clean construction
 * @NoArgsConstructor: Default constructor (required для Jackson)
 * @AllArgsConstructor: Constructor з all fields (for Builder)
 *
 * Builder usage:
 * LoginResponse response = LoginResponse.builder()
 *     .accessToken(token)
 *     .refreshToken(refresh)
 *     .tokenType("Bearer")
 *     .expiresIn(900L)
 *     .user(userResponse)
 *     .build();
 *
 * JSON SERIALIZATION:
 * ══════════════════
 * Jackson automatically serializes to JSON:
 * - Fields → JSON properties
 * - camelCase → camelCase (default)
 * - null fields → omitted (optional)
 *
 * @author snowfallen
 * @version 1.0.0
 * @since 2024-10-31
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LoginResponse {

    /**
     * Access Token (JWT)
     *
     * JWT access token для API authentication.
     *
     * FORMAT:
     * ══════
     * JWT = header.payload.signature
     *
     * Example (shortened):
     * eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImF1dGgtc2VydmljZS1rZXktMjAyNCJ9.
     * eyJzdWIiOiI1NTBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDAiLCJ1c2VybmFtZSI6ImFkbWluIiwiZW1haWwiOiJhZG1pbkBleGFtcGxlLmNvbSIsInJvbGVzIjpbIlVTRVIiLCJBRE1JTiJdLCJpc3MiOiJodHRwOi8vYXV0aC1zZXJ2aWNlOjgwODQiLCJpYXQiOjE2OTg3NTg0MDAsImV4cCI6MTY5ODc1OTMwMCwianRpIjoiNzIzZDM1YjgtMzk0NC00YWY3LTk4YzEtYWJjZGVmMTIzNDU2In0.
     * [signature...]
     *
     * Length: ~200-300 characters (depends on claims)
     *
     * PAYLOAD (decoded):
     * {
     *   "sub": "550e8400-e29b-41d4-a716-446655440000",  // userId
     *   "username": "admin",
     *   "email": "admin@example.com",
     *   "roles": ["USER", "ADMIN"],
     *   "iss": "http://auth-service:8084",
     *   "iat": 1698758400,  // Issued at
     *   "exp": 1698759300,  // Expires (15 min later)
     *   "jti": "723d35b8-3944-4af7-98c1-abcdef123456"  // Token ID
     * }
     *
     * CLIENT USAGE:
     * ════════════
     * Send в Authorization header:
     *
     * GET /api/users/profile
     * Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
     *
     * Gateway validates token:
     * 1. Extract від header
     * 2. Verify signature (public key від JWKS)
     * 3. Check expiration
     * 4. Extract claims (userId, roles)
     * 5. Forward request з user context
     *
     * LIFETIME:
     * ════════
     * 15 minutes (900 seconds)
     *
     * Why short:
     * ✅ Security (limited damage if stolen)
     * ✅ Logout effective (expires soon)
     * ✅ Claims stay fresh (roles up-to-date)
     *
     * When expires:
     * 1. Client gets 401 Unauthorized
     * 2. Client uses refresh token
     * 3. Gets new access token
     * 4. Retries request
     *
     * STORAGE (client):
     * ════════════════
     * Where to store:
     *
     * Best: Memory only
     * ✅ Most secure (lost on page refresh)
     * ✅ XSS-proof
     * ❌ Poor UX (re-login often)
     *
     * Good: SessionStorage
     * ✅ Lost on tab close
     * ✅ Isolated per tab
     * ⚠️  XSS vulnerable
     *
     * Acceptable: LocalStorage
     * ⚠️  Persists across sessions
     * ⚠️  XSS vulnerable
     * ⚠️  Shared across tabs
     *
     * Bad: Cookies (для JWT)
     * ❌ CSRF vulnerable (if not HttpOnly)
     * ❌ Sent automatically (can't control)
     * ❌ Size limits (4KB)
     *
     * Recommended:
     * - Access token: Memory або SessionStorage
     * - Refresh token: HttpOnly cookie (secure)
     *
     * SECURITY:
     * ════════
     * ⚠️  Never log full token
     * ⚠️  HTTPS only
     * ⚠️  Short lifetime
     * ⚠️  Signature validation required
     * ⚠️  Check expiration
     *
     * Safe logging:
     * log.debug("Token issued: jti={}", jti);
     */
    private String accessToken;

    /**
     * Refresh Token (UUID)
     *
     * UUID refresh token для obtaining new access tokens.
     *
     * FORMAT:
     * ══════
     * UUID (type 4 - random)
     * Example: 550e8400-e29b-41d4-a716-446655440000
     *
     * Length: 36 characters (32 hex + 4 hyphens)
     * Much shorter than JWT (~200+ chars)
     *
     * REDIS STORAGE:
     * ═════════════
     * Stored в Redis:
     * Key: refresh_token:550e8400-e29b-41d4-a716-446655440000
     * Value: {"userId":"...","username":"...","issuedAt":...,"expiresAt":...}
     * TTL: 7 days (automatic expiration)
     *
     * CLIENT USAGE:
     * ════════════
     * When access token expires:
     *
     * POST /auth/refresh
     * {
     *   "refreshToken": "550e8400-e29b-41d4-a716-446655440000"
     * }
     *
     * Response: TokenResponse з new tokens
     *
     * LIFETIME:
     * ════════
     * 7 days (604800 seconds)
     *
     * Why longer:
     * ✅ Better UX (less frequent login)
     * ✅ Still secure (can revoke)
     * ✅ Tracked sessions
     *
     * REVOCATION:
     * ══════════
     * Can be revoked instantly:
     * - Logout (single device)
     * - Logout all (all devices)
     * - Security breach (admin action)
     * - Password change (all tokens)
     *
     * Process:
     * 1. Delete від Redis
     * 2. Token immediately invalid
     * 3. Next use fails
     * 4. Client must re-login
     *
     * TOKEN ROTATION:
     * ══════════════
     * Security best practice: One-time use
     *
     * Each refresh:
     * 1. Validate OLD token
     * 2. Generate NEW tokens
     * 3. Revoke OLD token
     * 4. Return NEW tokens
     *
     * Benefits:
     * ✅ Limits stolen token lifetime
     * ✅ Detects token theft
     * ✅ Reduces attack window
     *
     * STORAGE (client):
     * ════════════════
     * Most secure: HttpOnly cookie
     * ✅ JavaScript cannot access (XSS protection)
     * ✅ SameSite (CSRF protection)
     * ✅ Secure flag (HTTPS only)
     * ✅ Automatic management
     *
     * Alternative: Secure storage
     * - Mobile: Keychain (iOS), KeyStore (Android)
     * - Desktop: OS credential manager
     * - Web: LocalStorage (⚠️  XSS risk)
     *
     * SECURITY:
     * ════════
     * ⚠️  Most sensitive token (long lifetime)
     * ⚠️  Treat як password
     * ⚠️  HTTPS only
     * ⚠️  Secure storage
     * ⚠️  Token rotation
     * ⚠️  Rate limiting
     */
    private String refreshToken;

    /**
     * Token Type
     *
     * OAuth 2.0 token type indicator.
     *
     * VALUE:
     * ═════
     * Always "Bearer"
     *
     * OAUTH 2.0 STANDARD:
     * ══════════════════
     * RFC 6750 - Bearer Token Usage
     *
     * "Bearer" means:
     * - Whoever has token = authorized
     * - No additional proof required
     * - Similar to cash (bearer instrument)
     *
     * Other token types (not used):
     * - "MAC" (Message Authentication Code)
     * - "Basic" (Basic Authentication)
     * - Custom types
     *
     * USAGE:
     * ═════
     * Client constructs Authorization header:
     *
     * tokenType + " " + accessToken
     * → "Bearer eyJhbGciOiJSUzI1NiIs..."
     *
     * Full header:
     * Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
     *
     * WHY INCLUDE:
     * ═══════════
     * Standard OAuth 2.0 response format.
     * Client knows how to use token.
     *
     * Alternative (without tokenType):
     * Client would assume "Bearer" anyway.
     * But explicit = better (standards compliance).
     *
     * BUILDER DEFAULT:
     * ═══════════════
     * @Builder.Default annotation sets default value.
     * If not specified during build, uses "Bearer".
     *
     * Example:
     * LoginResponse.builder()
     *     .accessToken(token)
     *     // tokenType automatically "Bearer"
     *     .build();
     */
    @Builder.Default
    private String tokenType = "Bearer";

    /**
     * Expires In (Seconds)
     *
     * Access token lifetime в seconds.
     *
     * VALUE:
     * ═════
     * 900 seconds = 15 minutes
     *
     * WHY SECONDS:
     * ═══════════
     * OAuth 2.0 standard format.
     *
     * Alternative units:
     * - Milliseconds (1000x larger numbers)
     * - Minutes (less precise)
     * - Timestamp (absolute time, timezone issues)
     *
     * Seconds = good balance:
     * ✅ Precise enough
     * ✅ Readable (900 = 15 min)
     * ✅ Standard (OAuth 2.0)
     *
     * CLIENT USAGE:
     * ════════════
     * Calculate expiration time:
     *
     * const expiresAt = Date.now() + (expiresIn * 1000);
     * // Current time + 900 seconds
     *
     * Set timer для refresh:
     * setTimeout(() => {
     *     refreshToken();
     * }, (expiresIn - 60) * 1000);  // Refresh 1 min before expiry
     *
     * REFRESH STRATEGY:
     * ════════════════
     *
     * Lazy refresh (wait до expiry):
     * 1. Request fails з 401
     * 2. Refresh token
     * 3. Retry request
     * ✅ Simple
     * ❌ Failed request (bad UX)
     *
     * Proactive refresh (before expiry):
     * 1. Timer до expiry - 60s
     * 2. Refresh token proactively
     * 3. Update stored token
     * 4. Continue без interruption
     * ✅ Seamless UX
     * ❌ More complex
     *
     * Recommended: Proactive refresh
     *
     * NOTE:
     * ════
     * This is access token expiry ONLY.
     * Refresh token expiry NOT included.
     *
     * Refresh token lifetime:
     * - 7 days (hardcoded)
     * - Client should track separately
     * - Or handle 401 на refresh attempt
     */
    private Long expiresIn;

    /**
     * User Information
     *
     * Authenticated user's profile data.
     *
     * STRUCTURE:
     * ═════════
     * UserResponse DTO containing:
     * - id: User UUID
     * - username: Login name
     * - email: Email address
     * - roles: Set of role names ["USER", "ADMIN"]
     * - enabled: Account status
     *
     * WHY INCLUDE:
     * ═══════════
     * Convenience - client needs user info immediately.
     *
     * Without user info:
     * 1. Login succeeds
     * 2. Get tokens
     * 3. Make separate request: GET /api/users/me
     * 4. Get user info
     * 5. Update UI
     *
     * With user info:
     * 1. Login succeeds
     * 2. Get tokens + user info
     * 3. Update UI immediately
     * ✅ One less request
     * ✅ Faster UI update
     * ✅ Better UX
     *
     * CLIENT USAGE:
     * ════════════
     * Display welcome message:
     * "Welcome back, {user.username}!"
     *
     * Show profile:
     * - Username
     * - Email
     * - Roles (admin badge if ADMIN)
     *
     * Authorization:
     * if (user.roles.includes("ADMIN")) {
     *     showAdminPanel();
     * }
     *
     * PRIVACY:
     * ═══════
     * User info = own profile data only.
     * No sensitive information included:
     * ❌ Password hash
     * ❌ Other users' data
     * ❌ System information
     *
     * Safe to include:
     * ✅ Own username
     * ✅ Own email
     * ✅ Own roles
     *
     * JWT REDUNDANCY:
     * ══════════════
     * User info also в JWT claims:
     * - Access token contains: userId, username, email, roles
     * - UserResponse contains: same data
     *
     * Why duplicate:
     * ✅ Convenience (don't need decode JWT)
     * ✅ Client-friendly (ready to use)
     * ✅ Type-safe (structured object)
     *
     * JWT for:
     * - Gateway validation
     * - API authorization
     * - Stateless authentication
     *
     * UserResponse for:
     * - UI display
     * - Client-side logic
     * - User profile
     *
     * FUTURE FIELDS:
     * ═════════════
     * Consider adding:
     * - avatarUrl: Profile picture
     * - displayName: Full name
     * - preferences: User settings
     * - lastLogin: Last login timestamp
     * - activeDevices: Device count
     *
     * Keep minimal for now (YAGNI principle).
     */
    private UserResponse user;
}
