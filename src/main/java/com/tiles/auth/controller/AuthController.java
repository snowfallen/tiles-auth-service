package com.tiles.auth.controller;

import com.tiles.auth.dto.request.LoginRequest;
import com.tiles.auth.dto.request.RefreshTokenRequest;
import com.tiles.auth.dto.request.RegisterRequest;
import com.tiles.auth.dto.response.LoginResponse;
import com.tiles.auth.dto.response.MessageResponse;
import com.tiles.auth.dto.response.TokenResponse;
import com.tiles.auth.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Authentication Controller
 *
 * REST API endpoints для authentication і authorization.
 *
 * BASE PATH:
 * ═════════
 * /auth
 *
 * All endpoints prefixed з /auth:
 * - POST /auth/login
 * - POST /auth/register
 * - POST /auth/refresh
 * - POST /auth/logout
 * - POST /auth/logout-all
 *
 * REST PRINCIPLES:
 * ═══════════════
 * ✅ Resource-based URLs (/auth/...)
 * ✅ HTTP verbs (POST для actions)
 * ✅ Status codes (200, 201, 400, 401)
 * ✅ JSON request/response
 * ✅ Stateless (JWT tokens)
 *
 * VALIDATION:
 * ══════════
 * @Valid annotation triggers Bean Validation.
 *
 * Process:
 * 1. Client sends JSON request
 * 2. Jackson deserializes → DTO
 * 3. @Valid triggers validation
 * 4. If invalid → MethodArgumentNotValidException
 * 5. GlobalExceptionHandler catches → 400 Bad Request
 * 6. If valid → proceed to method
 *
 * EXCEPTION HANDLING:
 * ══════════════════
 * All exceptions handled by GlobalExceptionHandler:
 * - InvalidCredentialsException → 401
 * - UserAlreadyExistsException → 409
 * - InvalidTokenException → 401
 * - MethodArgumentNotValidException → 400
 * - General exceptions → 500
 *
 * No try-catch в controller (clean code).
 *
 * RESPONSE ENTITY:
 * ═══════════════
 * ResponseEntity = HTTP response wrapper.
 *
 * Contains:
 * - Status code (200, 201, 400, тощо)
 * - Headers (Content-Type, тощо)
 * - Body (JSON response)
 *
 * Benefits:
 * ✅ Full control (status, headers, body)
 * ✅ Type-safe (generic type)
 * ✅ Fluent API (ok(), created(), badRequest())
 *
 * Example:
 * return ResponseEntity.ok(response);
 * → HTTP 200 OK + JSON body
 *
 * return ResponseEntity.status(HttpStatus.CREATED).body(response);
 * → HTTP 201 Created + JSON body
 *
 * LOGGING:
 * ═══════
 * @Slf4j provides logger.
 *
 * Log levels:
 * - log.info(): Important events (login success)
 * - log.warn(): Warnings (login failed)
 * - log.debug(): Detailed info (development)
 * - log.error(): Errors (exceptions)
 *
 * Security considerations:
 * ⚠️  Never log passwords (even hashed)
 * ⚠️  Never log full tokens
 * ⚠️  Mask sensitive data
 * ✅ Log usernames (audit trail)
 * ✅ Log IPs (security monitoring)
 * ✅ Log actions (login, logout, register)
 *
 * CORS:
 * ════
 * @CrossOrigin handles CORS (Cross-Origin Resource Sharing).
 *
 * Configuration:
 * - origins: Allowed origins (frontend URLs)
 * - methods: Allowed HTTP methods
 * - allowedHeaders: Allowed headers
 * - allowCredentials: Cookie support
 *
 * Current: Configured globally (SecurityConfig).
 * @CrossOrigin може override global config.
 *
 * SECURITY:
 * ════════
 * Public endpoints (no authentication):
 * - POST /auth/login
 * - POST /auth/register
 *
 * Protected endpoints (need token):
 * - POST /auth/refresh (needs refresh token)
 * - POST /auth/logout (needs refresh token)
 * - POST /auth/logout-all (needs refresh token)
 *
 * Note: Protection at service level (token validation).
 * Spring Security config allows all /auth/** (public).
 *
 * @author snowfallen
 * @version 1.0.0
 * @since 2024-10-31
 */
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    /**
     * Authentication Service
     *
     * Business logic для authentication operations.
     *
     * Injected via constructor (RequiredArgsConstructor):
     * - Immutable (final field)
     * - Required dependency (cannot be null)
     * - Testable (can mock)
     */
    private final AuthService authService;

    /**
     * Login Endpoint
     *
     * Authenticates user і returns access + refresh tokens.
     *
     * ENDPOINT:
     * ════════
     * POST /auth/login
     *
     * REQUEST:
     * ═══════
     * Content-Type: application/json
     *
     * {
     *   "username": "admin",  // or email
     *   "password": "password123"
     * }
     *
     * RESPONSE (success):
     * ══════════════════
     * HTTP 200 OK
     * Content-Type: application/json
     *
     * {
     *   "accessToken": "eyJhbGciOiJSUzI1NiIs...",
     *   "refreshToken": "550e8400-e29b-41d4-a716-446655440000",
     *   "tokenType": "Bearer",
     *   "expiresIn": 900,
     *   "user": {
     *     "id": "550e8400-...",
     *     "username": "admin",
     *     "email": "admin@example.com",
     *     "roles": ["USER", "ADMIN"],
     *     "enabled": true
     *   }
     * }
     *
     * RESPONSE (failure):
     * ══════════════════
     * HTTP 401 Unauthorized
     *
     * {
     *   "timestamp": "2024-10-31T12:30:00",
     *   "status": 401,
     *   "error": "Unauthorized",
     *   "message": "Invalid username or password"
     * }
     *
     * Or HTTP 400 Bad Request (validation error):
     * {
     *   "timestamp": "2024-10-31T12:30:00",
     *   "status": 400,
     *   "error": "Bad Request",
     *   "message": "Validation failed",
     *   "validationErrors": {
     *     "username": "Username is required",
     *     "password": "Password is required"
     *   }
     * }
     *
     * AUTHENTICATION FLOW:
     * ═══════════════════
     * 1. Client sends credentials
     * 2. @Valid validates request
     * 3. AuthService.login() called
     * 4. Spring Security authenticates (UserDetailsService)
     * 5. If success:
     *    - Generate JWT access token (15 min)
     *    - Generate UUID refresh token (7 days)
     *    - Store refresh token в Redis
     *    - Return LoginResponse
     * 6. If failure:
     *    - InvalidCredentialsException thrown
     *    - GlobalExceptionHandler → 401
     *
     * FLEXIBLE USERNAME:
     * ═════════════════
     * Field called "username", але accepts:
     * - Username: "admin"
     * - Email: "admin@example.com"
     *
     * UserDetailsService tries both.
     *
     * SECURITY:
     * ════════
     * ⚠️  HTTPS only (TLS encryption)
     * ⚠️  Rate limiting (prevent brute-force)
     * ⚠️  Account lockout (too many failures)
     * ⚠️  Generic error messages (no username hints)
     *
     * LOGGING:
     * ═══════
     * Success: log.info()
     * Failure: log.warn() (в exception handler)
     *
     * Logged data:
     * ✅ Username (audit trail)
     * ✅ IP address (security monitoring)
     * ✅ Timestamp (when)
     * ❌ Password (never log)
     * ❌ Full token (only token ID)
     *
     * CLIENT USAGE:
     * ════════════
     * JavaScript example:
     *
     * const response = await fetch('/auth/login', {
     *   method: 'POST',
     *   headers: { 'Content-Type': 'application/json' },
     *   body: JSON.stringify({
     *     username: 'admin',
     *     password: 'password123'
     *   })
     * });
     *
     * if (response.ok) {
     *   const data = await response.json();
     *   localStorage.setItem('accessToken', data.accessToken);
     *   localStorage.setItem('refreshToken', data.refreshToken);
     *   // Update UI з user info
     * } else {
     *   // Show error message
     * }
     *
     * TESTING:
     * ═══════
     * curl example:
     *
     * curl -X POST http://localhost:8084/auth/login \
     *   -H "Content-Type: application/json" \
     *   -d '{"username":"admin","password":"admin123"}'
     *
     * @param request login credentials (username, password)
     * @return LoginResponse з tokens і user info
     */
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
        log.info("Login attempt: username={}", request.getUsername());

        // Delegate to service layer
        // Service handles:
        // - Authentication (Spring Security)
        // - Token generation (JWT, UUID)
        // - Token storage (Redis)
        // - User info retrieval
        LoginResponse response = authService.login(request);

        log.info("Login successful: username={}", request.getUsername());

        // Return 200 OK з response body
        return ResponseEntity.ok(response);
    }

    /**
     * Register Endpoint
     *
     * Creates new user account і auto-login.
     *
     * ENDPOINT:
     * ════════
     * POST /auth/register
     *
     * REQUEST:
     * ═══════
     * Content-Type: application/json
     *
     * {
     *   "username": "newuser",
     *   "email": "newuser@example.com",
     *   "password": "password123"
     * }
     *
     * VALIDATION:
     * ══════════
     * RegisterRequest fields validated:
     * - username: @NotBlank, @Size(min=3, max=50)
     * - email: @NotBlank, @Email
     * - password: @NotBlank, @Size(min=8)
     *
     * RESPONSE (success):
     * ══════════════════
     * HTTP 201 Created
     *
     * {
     *   "accessToken": "eyJhbGciOiJSUzI1NiIs...",
     *   "refreshToken": "723d35b8-3944-4af7-98c1-abcdef123456",
     *   "tokenType": "Bearer",
     *   "expiresIn": 900,
     *   "user": {
     *     "id": "723d35b8-...",
     *     "username": "newuser",
     *     "email": "newuser@example.com",
     *     "roles": ["USER"],
     *     "enabled": true
     *   }
     * }
     *
     * RESPONSE (failure - duplicate username):
     * ═══════════════════════════════════════
     * HTTP 409 Conflict
     *
     * {
     *   "timestamp": "2024-10-31T12:30:00",
     *   "status": 409,
     *   "error": "Conflict",
     *   "message": "Username already exists: newuser"
     * }
     *
     * RESPONSE (failure - duplicate email):
     * ════════════════════════════════════
     * HTTP 409 Conflict
     *
     * {
     *   "timestamp": "2024-10-31T12:30:00",
     *   "status": 409,
     *   "error": "Conflict",
     *   "message": "Email already exists: newuser@example.com"
     * }
     *
     * RESPONSE (failure - validation):
     * ═══════════════════════════════
     * HTTP 400 Bad Request
     *
     * {
     *   "timestamp": "2024-10-31T12:30:00",
     *   "status": 400,
     *   "error": "Bad Request",
     *   "message": "Validation failed",
     *   "validationErrors": {
     *     "username": "Username must be between 3 and 50 characters",
     *     "password": "Password must be at least 8 characters"
     *   }
     * }
     *
     * REGISTRATION FLOW:
     * ═════════════════
     * 1. Client sends registration data
     * 2. @Valid validates format
     * 3. AuthService.register() called
     * 4. Check username uniqueness
     * 5. Check email uniqueness
     * 6. Hash password (BCrypt)
     * 7. Create User entity
     * 8. Assign USER role (default)
     * 9. Save to database
     * 10. Auto-login (generate tokens)
     * 11. Return LoginResponse
     *
     * AUTO-LOGIN:
     * ══════════
     * After registration, user automatically logged in:
     * - Generates tokens (access + refresh)
     * - Returns LoginResponse (same як /login)
     * - User can immediately use API
     *
     * Benefits:
     * ✅ Better UX (no separate login)
     * ✅ Seamless flow (register → app)
     * ✅ One request (not two)
     *
     * DEFAULT ROLE:
     * ════════════
     * All new users get USER role automatically.
     *
     * ADMIN role:
     * - Assigned manually (database)
     * - Never during registration (security)
     *
     * PASSWORD HASHING:
     * ════════════════
     * Plain password hashed before storage:
     * - BCrypt з 10 rounds
     * - Unique salt per password
     * - One-way function
     * - ~100ms per hash
     *
     * ACCOUNT STATUS:
     * ══════════════
     * New account defaults:
     * - enabled: true (active)
     * - accountNonExpired: true
     * - accountNonLocked: true
     * - credentialsNonExpired: true
     *
     * Email verification (future):
     * - enabled: false (pending verification)
     * - Send confirmation email
     * - Click link → enabled: true
     *
     * SECURITY:
     * ════════
     * ⚠️  HTTPS only
     * ⚠️  Rate limiting (prevent spam accounts)
     * ⚠️  Email verification (future)
     * ⚠️  CAPTCHA (prevent bots) - future
     * ⚠️  Password strength validation
     *
     * LOGGING:
     * ═══════
     * Success: log.info()
     * Failure: log.warn() (в exception handler)
     *
     * Logged data:
     * ✅ Username, email (audit trail)
     * ✅ IP address (security)
     * ❌ Password (never log)
     *
     * CLIENT USAGE:
     * ════════════
     * JavaScript example:
     *
     * const response = await fetch('/auth/register', {
     *   method: 'POST',
     *   headers: { 'Content-Type': 'application/json' },
     *   body: JSON.stringify({
     *     username: 'newuser',
     *     email: 'newuser@example.com',
     *     password: 'password123'
     *   })
     * });
     *
     * if (response.ok) {
     *   const data = await response.json();
     *   // Automatically logged in
     *   localStorage.setItem('accessToken', data.accessToken);
     *   localStorage.setItem('refreshToken', data.refreshToken);
     *   // Redirect to app
     * } else if (response.status === 409) {
     *   // Username або email already exists
     * } else if (response.status === 400) {
     *   // Validation errors
     * }
     *
     * TESTING:
     * ═══════
     * curl example:
     *
     * curl -X POST http://localhost:8084/auth/register \
     *   -H "Content-Type: application/json" \
     *   -d '{
     *     "username":"newuser",
     *     "email":"newuser@example.com",
     *     "password":"password123"
     *   }'
     *
     * @param request registration data (username, email, password)
     * @return LoginResponse з tokens і user info (201 Created)
     */
    @PostMapping("/register")
    public ResponseEntity<LoginResponse> register(@Valid @RequestBody RegisterRequest request) {
        log.info("Registration attempt: username={}, email={}",
                request.getUsername(),
                request.getEmail());

        // Delegate to service layer
        // Service handles:
        // - Validation (uniqueness)
        // - Password hashing
        // - User creation
        // - Role assignment
        // - Auto-login (token generation)
        LoginResponse response = authService.register(request);

        log.info("Registration successful: username={}, userId={}",
                request.getUsername(),
                response.getUser().getId());

        // Return 201 Created з response body
        // Created = resource created successfully
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * Refresh Token Endpoint
     *
     * Exchanges refresh token для new access + refresh tokens.
     *
     * ENDPOINT:
     * ════════
     * POST /auth/refresh
     *
     * REQUEST:
     * ═══════
     * Content-Type: application/json
     *
     * {
     *   "refreshToken": "550e8400-e29b-41d4-a716-446655440000"
     * }
     *
     * RESPONSE (success):
     * ══════════════════
     * HTTP 200 OK
     *
     * {
     *   "accessToken": "eyJhbGciOiJSUzI1NiIs...",  // NEW token
     *   "refreshToken": "723d35b8-3944-4af7-98c1-abcdef123456",  // NEW token
     *   "tokenType": "Bearer",
     *   "expiresIn": 900
     * }
     *
     * Note: No user info (client already has it).
     *
     * RESPONSE (failure):
     * ══════════════════
     * HTTP 401 Unauthorized
     *
     * {
     *   "timestamp": "2024-10-31T12:30:00",
     *   "status": 401,
     *   "error": "Unauthorized",
     *   "message": "Invalid or expired refresh token"
     * }
     *
     * REFRESH FLOW:
     * ════════════
     * 1. Access token expires (15 min)
     * 2. Client sends refresh token
     * 3. AuthService.refreshToken() called
     * 4. Validate refresh token (Redis)
     * 5. If valid:
     *    - Generate NEW access token (15 min)
     *    - Generate NEW refresh token (7 days)
     *    - Revoke OLD refresh token (delete від Redis)
     *    - Store NEW refresh token (Redis)
     *    - Return TokenResponse
     * 6. If invalid:
     *    - InvalidTokenException thrown
     *    - GlobalExceptionHandler → 401
     *
     * TOKEN ROTATION:
     * ══════════════
     * Security best practice: One-time use tokens.
     *
     * Each refresh:
     * - OLD tokens invalidated
     * - NEW tokens generated
     * - Cannot reuse OLD tokens
     *
     * Benefits:
     * ✅ Limits stolen token lifetime
     * ✅ Detects token theft (reuse fails)
     * ✅ Reduces attack window
     *
     * WHEN TO REFRESH:
     * ═══════════════
     *
     * Strategy 1: Lazy refresh (wait до 401)
     * 1. API request з expired token
     * 2. Gateway returns 401
     * 3. Client refreshes token
     * 4. Client retries request
     * ✅ Simple
     * ❌ Failed request (bad UX)
     *
     * Strategy 2: Proactive refresh (before expiry)
     * 1. Timer до expiry - 60s
     * 2. Refresh token proactively
     * 3. Update stored token
     * 4. Continue without interruption
     * ✅ Seamless UX
     * ❌ More complex
     *
     * Recommended: Proactive refresh
     *
     * CONCURRENT REQUESTS:
     * ═══════════════════
     * Possible race condition:
     * 1. Request A: Refresh token (OLD)
     * 2. Request B: Refresh token (OLD) - concurrent
     * 3. Request A succeeds → OLD revoked
     * 4. Request B fails → OLD already revoked
     *
     * Solution:
     * - Client ensures single refresh at time
     * - Queue requests during refresh
     * - Retry on failure
     *
     * SECURITY:
     * ════════
     * ⚠️  HTTPS only
     * ⚠️  Token rotation (one-time use)
     * ⚠️  Short access token lifetime
     * ⚠️  Revocation support
     * ⚠️  Rate limiting
     *
     * LOGGING:
     * ═══════
     * Success: log.info()
     * Failure: log.warn()
     *
     * Logged data:
     * ✅ User ID (від token data)
     * ✅ Token ID (first 8 chars)
     * ❌ Full token (security risk)
     *
     * CLIENT USAGE:
     * ════════════
     * JavaScript example:
     *
     * async function refreshToken() {
     *   const refreshToken = localStorage.getItem('refreshToken');
     *
     *   const response = await fetch('/auth/refresh', {
     *     method: 'POST',
     *     headers: { 'Content-Type': 'application/json' },
     *     body: JSON.stringify({ refreshToken })
     *   });
     *
     *   if (response.ok) {
     *     const data = await response.json();
     *     localStorage.setItem('accessToken', data.accessToken);
     *     localStorage.setItem('refreshToken', data.refreshToken);  // NEW token!
     *     return data.accessToken;
     *   } else {
     *     // Refresh failed → re-login
     *     redirectToLogin();
     *   }
     * }
     *
     * // Proactive refresh (before expiry)
     * setInterval(refreshToken, 14 * 60 * 1000);  // Every 14 min (1 min before expiry)
     *
     * TESTING:
     * ═══════
     * curl example:
     *
     * curl -X POST http://localhost:8084/auth/refresh \
     *   -H "Content-Type: application/json" \
     *   -d '{"refreshToken":"550e8400-e29b-41d4-a716-446655440000"}'
     *
     * @param request refresh token (UUID)
     * @return TokenResponse з new tokens
     */
    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(@Valid @RequestBody RefreshTokenRequest request) {
        log.debug("Token refresh attempt: tokenId={}",
                request.getRefreshToken().substring(0, 8) + "...");

        // Delegate to service layer
        // Service handles:
        // - Token validation (Redis)
        // - Token rotation (revoke old, generate new)
        // - Token storage (Redis)
        TokenResponse response = authService.refresh(request);

        log.debug("Token refresh successful: tokenId={}",
                request.getRefreshToken().substring(0, 8) + "...");

        // Return 200 OK з response body
        return ResponseEntity.ok(response);
    }

    /**
     * Logout Endpoint
     *
     * Revokes refresh token (logout від single device).
     *
     * ENDPOINT:
     * ════════
     * POST /auth/logout
     *
     * REQUEST:
     * ═══════
     * Content-Type: application/json
     *
     * {
     *   "refreshToken": "550e8400-e29b-41d4-a716-446655440000"
     * }
     *
     * RESPONSE (success):
     * ══════════════════
     * HTTP 200 OK
     *
     * {
     *   "message": "Logged out successfully"
     * }
     *
     * RESPONSE (failure):
     * ══════════════════
     * HTTP 401 Unauthorized (token invalid)
     *
     * {
     *   "timestamp": "2024-10-31T12:30:00",
     *   "status": 401,
     *   "error": "Unauthorized",
     *   "message": "Invalid or expired refresh token"
     * }
     *
     * LOGOUT FLOW:
     * ═══════════
     * 1. Client sends refresh token
     * 2. AuthService.logout() called
     * 3. Validate token (exists в Redis)
     * 4. Extract user ID від token
     * 5. Revoke token:
     *    - Delete від Redis (instant invalidation)
     *    - Remove від user session set
     * 6. Return success message
     *
     * ACCESS TOKEN:
     * ════════════
     * Access token NOT revoked (stateless JWT).
     *
     * Access token remains valid до expiry (max 15 min).
     * After 15 min, token expires naturally.
     *
     * If need immediate logout:
     * - Client discards access token
     * - Gateway still accepts token (до expiry)
     * - Trade-off: Simplicity vs immediate revocation
     *
     * For critical security:
     * - Use short access token lifetime (5 min)
     * - Or implement JWT blacklist (adds complexity)
     *
     * SINGLE DEVICE:
     * ═════════════
     * Logs out від current device only.
     * Other devices remain logged in.
     *
     * Scenario:
     * - Desktop: Logged in (token A)
     * - Mobile: Logged in (token B)
     * - Logout Desktop (revoke token A)
     * - Mobile: Still logged in (token B valid)
     *
     * For logout all devices: POST /auth/logout-all
     *
     * CLIENT CLEANUP:
     * ══════════════
     * After logout, client should:
     * 1. Delete access token (localStorage)
     * 2. Delete refresh token (localStorage)
     * 3. Clear user info
     * 4. Redirect to login page
     * 5. Clear any cached data
     *
     * SECURITY:
     * ════════
     * ⚠️  HTTPS only
     * ⚠️  Rate limiting (prevent abuse)
     * ⚠️  Token validation (ensure token exists)
     *
     * LOGGING:
     * ═══════
     * Success: log.info()
     *
     * Logged data:
     * ✅ User ID (audit trail)
     * ✅ Token ID (identification)
     * ✅ Timestamp (when)
     *
     * CLIENT USAGE:
     * ════════════
     * JavaScript example:
     *
     * async function logout() {
     *   const refreshToken = localStorage.getItem('refreshToken');
     *
     *   const response = await fetch('/auth/logout', {
     *     method: 'POST',
     *     headers: { 'Content-Type': 'application/json' },
     *     body: JSON.stringify({ refreshToken })
     *   });
     *
     *   // Clear tokens (even if request failed)
     *   localStorage.removeItem('accessToken');
     *   localStorage.removeItem('refreshToken');
     *
     *   // Redirect to login
     *   window.location.href = '/login';
     * }
     *
     * TESTING:
     * ═══════
     * curl example:
     *
     * curl -X POST http://localhost:8084/auth/logout \
     *   -H "Content-Type: application/json" \
     *   -d '{"refreshToken":"550e8400-e29b-41d4-a716-446655440000"}'
     *
     * @param request refresh token to revoke
     * @return MessageResponse з success message
     */
    @PostMapping("/logout")
    public ResponseEntity<MessageResponse> logout(@Valid @RequestBody RefreshTokenRequest request) {
        log.info("Logout attempt: tokenId={}",
                request.getRefreshToken().substring(0, 8) + "...");

        // Delegate to service layer
        // Service handles:
        // - Token validation
        // - Token revocation (delete від Redis)
        // - User session cleanup
        authService.logout(request);

        log.info("Logout successful: tokenId={}",
                request.getRefreshToken().substring(0, 8) + "...");

        // Return 200 OK з success message
        return ResponseEntity.ok(new MessageResponse("Logged out successfully"));
    }

    /**
     * Logout All Endpoint
     *
     * Revokes all user's refresh tokens (logout від all devices).
     *
     * ENDPOINT:
     * ════════
     * POST /auth/logout-all
     *
     * REQUEST:
     * ═══════
     * Content-Type: application/json
     *
     * {
     *   "refreshToken": "550e8400-e29b-41d4-a716-446655440000"
     * }
     *
     * Note: Token used to identify user, then ALL user's tokens revoked.
     *
     * RESPONSE (success):
     * ══════════════════
     * HTTP 200 OK
     *
     * {
     *   "message": "Logged out from all devices"
     * }
     *
     * RESPONSE (failure):
     * ══════════════════
     * HTTP 401 Unauthorized
     *
     * {
     *   "timestamp": "2024-10-31T12:30:00",
     *   "status": 401,
     *   "error": "Unauthorized",
     *   "message": "Invalid or expired refresh token"
     * }
     *
     * LOGOUT ALL FLOW:
     * ═══════════════
     * 1. Client sends refresh token
     * 2. AuthService.logoutAll() called
     * 3. Validate token (exists в Redis)
     * 4. Extract user ID від token
     * 5. Find all user's tokens:
     *    - Get від user session set (Redis)
     * 6. Revoke ALL tokens:
     *    - Delete each token від Redis
     *    - Delete user session set
     * 7. Return success message
     *
     * ALL DEVICES:
     * ═══════════
     * Logs out від all devices simultaneously.
     *
     * Scenario:
     * - Desktop: Logged in (token A)
     * - Mobile: Logged in (token B)
     * - Tablet: Logged in (token C)
     * - Logout all (від any device)
     * - All devices logged out (tokens A, B, C revoked)
     *
     * USE CASES:
     * ═════════
     * - "Logout from all devices" button
     * - Password changed (security measure)
     * - Account compromised (security response)
     * - Lost device (remote logout)
     * - Suspicious activity detected
     *
     * USER SESSION TRACKING:
     * ═════════════════════
     * Redis stores user session set:
     * Key: user_session:{userId}
     * Value: Set {token1, token2, token3}
     *
     * Each token = one device/browser session.
     *
     * SECURITY:
     * ════════
     * Important security feature:
     * ✅ Respond to account compromise
     * ✅ Force re-authentication
     * ✅ Revoke stolen tokens
     * ✅ Control active sessions
     *
     * LOGGING:
     * ═══════
     * Success: log.info()
     *
     * Logged data:
     * ✅ User ID (whose sessions)
     * ✅ Token count (how many revoked)
     * ✅ Timestamp (when)
     *
     * CLIENT USAGE:
     * ════════════
     * JavaScript example:
     *
     * async function logoutAll() {
     *   const refreshToken = localStorage.getItem('refreshToken');
     *
     *   const response = await fetch('/auth/logout-all', {
     *     method: 'POST',
     *     headers: { 'Content-Type': 'application/json' },
     *     body: JSON.stringify({ refreshToken })
     *   });
     *
     *   if (response.ok) {
     *     // Clear local tokens
     *     localStorage.removeItem('accessToken');
     *     localStorage.removeItem('refreshToken');
     *
     *     // Show confirmation
     *     alert('Logged out from all devices');
     *
     *     // Redirect to login
     *     window.location.href = '/login';
     *   }
     * }
     *
     * UI PLACEMENT:
     * ════════════
     * Account settings page:
     *
     * [Active Sessions]
     * • Desktop (Windows) - Current session
     * • Mobile (iPhone) - Last active: 2 hours ago
     * • Laptop (MacBook) - Last active: 1 day ago
     *
     * [Logout from all devices] ← Button
     *
     * PASSWORD CHANGE:
     * ═══════════════
     * Automatically logout all after password change:
     *
     * @PostMapping("/change-password")
     * public void changePassword(...) {
     *     userService.changePassword(userId, newPassword);
     *     authService.logoutAllForUser(userId);  // Force re-login
     * }
     *
     * TESTING:
     * ═══════
     * curl example:
     *
     * curl -X POST http://localhost:8084/auth/logout-all \
     *   -H "Content-Type: application/json" \
     *   -d '{"refreshToken":"550e8400-e29b-41d4-a716-446655440000"}'
     *
     * @param request refresh token (identifies user)
     * @return MessageResponse з success message
     */
    @PostMapping("/logout-all")
    public ResponseEntity<MessageResponse> logoutAll(@Valid @RequestBody RefreshTokenRequest request) {
        log.info("Logout all attempt: tokenId={}",
                request.getRefreshToken().substring(0, 8) + "...");

        // Delegate to service layer
        // Service handles:
        // - Token validation
        // - User identification
        // - All tokens revocation
        // - Session cleanup
        authService.logoutAll(request);

        log.info("Logout all successful: tokenId={}",
                request.getRefreshToken().substring(0, 8) + "...");

        // Return 200 OK з success message
        return ResponseEntity.ok(new MessageResponse("Logged out from all devices"));
    }
}
