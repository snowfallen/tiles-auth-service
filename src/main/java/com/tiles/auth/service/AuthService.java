package com.tiles.auth.service;

import com.tiles.auth.dto.request.LoginRequest;
import com.tiles.auth.dto.request.RefreshTokenRequest;
import com.tiles.auth.dto.request.RegisterRequest;
import com.tiles.auth.dto.response.LoginResponse;
import com.tiles.auth.dto.response.TokenResponse;
import org.springframework.transaction.annotation.Transactional;

/**
 * Auth Service Interface
 *
 * Defines contract для authentication operations.
 *
 * RESPONSIBILITIES:
 * ═══════════════
 * - User login (username/password → tokens)
 * - User registration (create account + auto-login)
 * - Token refresh (old refresh token → new tokens)
 * - Logout (revoke single refresh token)
 * - Logout all (revoke all user's tokens)
 *
 * TRANSACTIONAL:
 * ═════════════
 * All methods @Transactional для ensure:
 * - Database consistency
 * - Rollback on errors
 * - Atomic operations
 *
 * WHY INTERFACE:
 * ═════════════
 * ✅ Separation of contract від implementation
 * ✅ Easy mocking для tests
 * ✅ Multiple implementations possible
 * ✅ Dependency Inversion Principle
 *
 * @author snowfallen
 * @version 1.0.0
 * @since 2024-10-31
 */
public interface AuthService {

    /**
     * User Login
     *
     * Authenticates user і generates tokens.
     *
     * PROCESS:
     * ═══════
     * 1. Validate credentials (username + password)
     * 2. Generate JWT access token (15 min TTL)
     * 3. Generate refresh token (7 days TTL)
     * 4. Store refresh token в Redis
     * 5. Return tokens + user info
     *
     * ERRORS:
     * ══════
     * - BadCredentialsException: invalid username/password
     * - InvalidCredentialsException: account disabled
     * - UsernameNotFoundException: user not found
     *
     * @param request login credentials (username, password)
     * @return LoginResponse з tokens і user info
     * @throws org.springframework.security.authentication.BadCredentialsException if invalid
     */
    @Transactional
    LoginResponse login(LoginRequest request);

    /**
     * User Registration
     *
     * Creates new user account і auto-login.
     *
     * PROCESS:
     * ═══════
     * 1. Validate registration data
     * 2. Check username/email uniqueness
     * 3. Hash password (BCrypt)
     * 4. Create user в database
     * 5. Assign default USER role
     * 6. Auto-login: generate tokens
     * 7. Return tokens + user info
     *
     * ERRORS:
     * ══════
     * - UserAlreadyExistsException: username/email exists
     * - ValidationException: invalid data
     *
     * @param request registration data (username, email, password)
     * @return LoginResponse з tokens і user info (auto-login)
     * @throws com.tiles.auth.exception.UserAlreadyExistsException if exists
     */
    @Transactional
    LoginResponse register(RegisterRequest request);

    /**
     * Refresh Tokens
     *
     * Generates new tokens using refresh token.
     * Implements token rotation (old token revoked).
     *
     * PROCESS:
     * ═══════
     * 1. Validate refresh token (check Redis)
     * 2. Extract user info від token
     * 3. Load user від database (fresh data)
     * 4. Generate NEW access token
     * 5. Generate NEW refresh token
     * 6. Revoke OLD refresh token (rotation)
     * 7. Store NEW refresh token в Redis
     * 8. Return new tokens
     *
     * TOKEN ROTATION:
     * ══════════════
     * Security best practice - refresh tokens одноразові.
     * Each use generates new token і revokes old.
     *
     * Benefits:
     * ✅ Limits stolen token lifetime
     * ✅ Detects token theft (reuse attempt)
     * ✅ Reduces attack window
     *
     * ERRORS:
     * ══════
     * - InvalidTokenException: token invalid/expired
     * - UsernameNotFoundException: user not found
     *
     * @param request refresh token request
     * @return TokenResponse з new tokens
     * @throws com.tiles.auth.exception.InvalidTokenException if invalid
     */
    @Transactional
    TokenResponse refresh(RefreshTokenRequest request);

    /**
     * Logout
     *
     * Revokes single refresh token (current device).
     *
     * PROCESS:
     * ═══════
     * 1. Validate refresh token
     * 2. Delete token від Redis
     * 3. Remove від user session set
     *
     * NOTE:
     * ════
     * Access token залишається valid до expiry (15 min).
     * This is OK - short TTL limits risk.
     * Cannot invalidate JWT without database lookup
     * (defeats purpose of stateless tokens).
     *
     * @param request refresh token до revoke
     */
    @Transactional
    void logout(RefreshTokenRequest request);

    /**
     * Logout All Devices
     *
     * Revokes всі refresh tokens для user (all devices).
     *
     * PROCESS:
     * ═══════
     * 1. Validate refresh token (identify user)
     * 2. Get userId від token
     * 3. Find all user's refresh tokens (Redis set)
     * 4. Delete all tokens
     * 5. Delete user session set
     *
     * USE CASES:
     * ═════════
     * - Security breach suspected
     * - User wants logout everywhere
     * - Password changed
     * - Account compromised
     *
     * @param request refresh token (для identify user)
     */
    @Transactional
    void logoutAll(RefreshTokenRequest request);
}
