package com.tiles.auth.service.impl;

import com.tiles.auth.dto.request.LoginRequest;
import com.tiles.auth.dto.request.RefreshTokenRequest;
import com.tiles.auth.dto.request.RegisterRequest;
import com.tiles.auth.dto.response.LoginResponse;
import com.tiles.auth.dto.response.TokenResponse;
import com.tiles.auth.entity.User;
import com.tiles.auth.mapper.AuthMapper;
import com.tiles.auth.mapper.UserMapper;
import com.tiles.auth.security.CustomUserDetails;
import com.tiles.auth.service.AuthService;
import com.tiles.auth.service.RefreshTokenService;
import com.tiles.auth.service.TokenService;
import com.tiles.auth.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Auth Service Implementation
 *
 * Містить всю бізнес-логіку authentication operations.
 *
 * ARCHITECTURE:
 * ════════════
 * Service layer = бізнес-логіка (NO HTTP details)
 * Controller → Service → Repository/External services
 *
 * DEPENDENCIES:
 * ════════════
 * - AuthenticationManager: Spring Security authentication
 * - UserService: User management (load, create)
 * - TokenService: JWT operations (generate, validate)
 * - RefreshTokenService: Refresh token operations (Redis)
 * - UserMapper: Entity → DTO conversion
 * - AuthMapper: Response building
 *
 * TRANSACTIONAL:
 * ═════════════
 * All methods @Transactional для ensure:
 * - Database consistency (commit/rollback)
 * - Atomic operations (all-or-nothing)
 * - Connection management (auto close)
 *
 * @author snowfallen
 * @version 1.0.0
 * @since 2024-10-31
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AuthServiceImpl implements AuthService {

    /**
     * Authentication Manager
     *
     * Spring Security component для authentication.
     * Orchestrates authentication process:
     * - Calls UserDetailsService (UserService)
     * - Validates password (BCrypt)
     * - Returns Authentication object
     */
    private final AuthenticationManager authenticationManager;

    /**
     * User Service
     *
     * User management operations:
     * - Load user від database
     * - Create new user (registration)
     * - Check user existence
     */
    private final UserService userService;

    /**
     * Token Service
     *
     * JWT token operations:
     * - Generate access tokens (RS256)
     * - Validate tokens
     * - Parse claims
     */
    private final TokenService tokenService;

    /**
     * Refresh Token Service
     *
     * Refresh token operations (Redis):
     * - Generate UUID tokens
     * - Store в Redis
     * - Validate tokens
     * - Revoke tokens
     */
    private final RefreshTokenService refreshTokenService;

    /**
     * User Mapper
     *
     * Converts User entity → UserResponse DTO.
     * Separates internal model від API response.
     */
    private final UserMapper userMapper;

    /**
     * Auth Mapper
     *
     * Builds authentication responses:
     * - LoginResponse (tokens + user info)
     * - TokenResponse (only tokens)
     */
    private final AuthMapper authMapper;

    /**
     * Login Implementation
     *
     * Authenticates user і generates tokens.
     *
     * PROCESS FLOW:
     * ════════════
     * 1. Create authentication token (username + password)
     * 2. Call AuthenticationManager.authenticate()
     *    → Validates credentials через Spring Security
     *    → Loads user через UserDetailsService
     *    → Checks password через BCrypt
     * 3. Extract authenticated UserDetails
     * 4. Generate JWT access token (15 min TTL)
     * 5. Generate refresh token (7 days TTL, stored в Redis)
     * 6. Build LoginResponse (tokens + user info)
     * 7. Return response
     *
     * AUTHENTICATION MANAGER FLOW:
     * ═══════════════════════════
     * AuthenticationManager receives token:
     * 1. Passes to DaoAuthenticationProvider
     * 2. Provider calls userDetailsService.loadUserByUsername()
     * 3. Provider calls passwordEncoder.matches(raw, hashed)
     * 4. If matches → returns authenticated Authentication
     * 5. If not matches → throws BadCredentialsException
     *
     * ERRORS:
     * ══════
     * - BadCredentialsException: wrong username/password
     * - UsernameNotFoundException: user not found
     * - InvalidCredentialsException: account disabled
     * - DisabledException: account disabled
     * - LockedException: account locked
     *
     * All exceptions handled by GlobalExceptionHandler.
     *
     * TRANSACTION:
     * ═══════════
     * @Transactional ensures:
     * - Database connection opened
     * - User loaded в transaction
     * - Refresh token stored в Redis
     * - Commit on success, rollback on error
     *
     * @param request login credentials (username, password)
     * @return LoginResponse з tokens і user info
     * @throws org.springframework.security.authentication.BadCredentialsException if invalid
     */
    @Transactional
    @Override
    public LoginResponse login(LoginRequest request) {
        log.info("Login attempt: username={}", request.getUsername());

        // ════════════════════════════════════════
        // Step 1: Authenticate User
        // ════════════════════════════════════════
        // Create authentication token з credentials
        // This is INPUT для AuthenticationManager
        UsernamePasswordAuthenticationToken authToken =
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                );

        // Authenticate через Spring Security
        // This triggers:
        // 1. UserDetailsService.loadUserByUsername()
        // 2. PasswordEncoder.matches()
        // 3. Returns authenticated Authentication object
        //
        // Throws exception if authentication fails
        Authentication authentication = authenticationManager.authenticate(authToken);

        // Extract authenticated user details
        // Principal = authenticated user object
        // Cast to CustomUserDetails (our wrapper)
        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();

        log.debug("User authenticated successfully: username={}", userDetails.getUsername());

        // ════════════════════════════════════════
        // Step 2: Generate Access Token (JWT)
        // ════════════════════════════════════════
        // JWT access token з user claims:
        // - sub: userId
        // - username, email, roles
        // - iss: auth service URL
        // - exp: current time + 15 minutes
        // Signed з RSA private key (RS256)
        String accessToken = tokenService.generateAccessToken(userDetails);

        log.debug("Access token generated for user: {}", userDetails.getUsername());

        // ════════════════════════════════════════
        // Step 3: Generate Refresh Token (UUID)
        // ════════════════════════════════════════
        // UUID refresh token stored в Redis:
        // - Token data: userId, username, email, timestamps
        // - TTL: 7 days (automatic expiration)
        // - Also tracked в user session set
        String refreshToken = refreshTokenService.generateRefreshToken(
                userDetails.getUserId(),
                userDetails.getUsername(),
                userDetails.getEmail()
        );

        log.debug("Refresh token generated and stored in Redis");

        // ════════════════════════════════════════
        // Step 4: Build Response
        // ════════════════════════════════════════
        // Convert User entity → UserResponse DTO
        // Build LoginResponse з tokens + user info
        LoginResponse response = authMapper.toLoginResponse(
                accessToken,
                refreshToken,
                userMapper.toResponse(userDetails)
        );

        log.info("Login successful: username={}, userId={}",
                userDetails.getUsername(),
                userDetails.getUserId());

        return response;
    }

    /**
     * Register Implementation
     *
     * Creates new user account і auto-login.
     *
     * PROCESS FLOW:
     * ════════════
     * 1. Call UserService.registerUser()
     *    → Validates uniqueness (username, email)
     *    → Hashes password (BCrypt)
     *    → Creates User entity
     *    → Assigns USER role
     *    → Saves to database
     * 2. Wrap User в CustomUserDetails
     * 3. Generate JWT access token
     * 4. Generate refresh token (store в Redis)
     * 5. Build LoginResponse (auto-login)
     * 6. Return response
     *
     * AUTO-LOGIN:
     * ══════════
     * After successful registration, user automatically logged in.
     * No need to submit credentials again.
     *
     * Benefits:
     * ✅ Better UX (seamless experience)
     * ✅ Fewer steps (no extra login)
     * ✅ Same response format як login
     *
     * PASSWORD SECURITY:
     * ═════════════════
     * Password hashed з BCrypt (10 rounds) before storage.
     * Plain password NEVER stored в database.
     *
     * BCrypt properties:
     * - One-way function (cannot decode)
     * - Unique salt per password
     * - ~100ms per hash (brute-force resistant)
     *
     * ERRORS:
     * ══════
     * - UserAlreadyExistsException: username exists
     * - UserAlreadyExistsException: email exists
     * - ValidationException: invalid data format
     * - RuntimeException: USER role not found
     *
     * @param request registration data (username, email, password)
     * @return LoginResponse з tokens і user info (auto-login)
     * @throws com.tiles.auth.exception.UserAlreadyExistsException if exists
     */
    @Transactional
    @Override
    public LoginResponse register(RegisterRequest request) {
        log.info("Registration attempt: username={}, email={}",
                request.getUsername(),
                request.getEmail());

        // ════════════════════════════════════════
        // Step 1: Create User
        // ════════════════════════════════════════
        // UserService handles:
        // - Uniqueness validation (username, email)
        // - Password hashing (BCrypt)
        // - Role assignment (USER)
        // - Database save
        User user = userService.registerUser(request);

        log.debug("User created successfully: userId={}", user.getId());

        // Wrap User entity в Spring Security UserDetails
        CustomUserDetails userDetails = new CustomUserDetails(user);

        // ════════════════════════════════════════
        // Step 2: Generate Tokens (Auto-Login)
        // ════════════════════════════════════════
        // Generate JWT access token (15 min TTL)
        String accessToken = tokenService.generateAccessToken(userDetails);

        log.debug("Access token generated for new user");

        // Generate refresh token (7 days TTL, Redis)
        String refreshToken = refreshTokenService.generateRefreshToken(
                userDetails.getUserId(),
                userDetails.getUsername(),
                userDetails.getEmail()
        );

        log.debug("Refresh token generated and stored in Redis");

        // ════════════════════════════════════════
        // Step 3: Build Response
        // ════════════════════════════════════════
        LoginResponse response = authMapper.toLoginResponse(
                accessToken,
                refreshToken,
                userMapper.toResponse(userDetails)
        );

        log.info("Registration successful (auto-login): username={}, userId={}",
                user.getUsername(),
                user.getId());

        return response;
    }

    /**
     * Refresh Tokens Implementation
     *
     * Generates new tokens using refresh token.
     * Implements TOKEN ROTATION (security best practice).
     *
     * PROCESS FLOW:
     * ════════════
     * 1. Validate refresh token (check Redis)
     * 2. Extract userId від token data
     * 3. Extract username від token data
     * 4. Load fresh user data від database
     * 5. Generate NEW JWT access token
     * 6. Generate NEW refresh token
     * 7. Revoke OLD refresh token (rotation)
     * 8. Store NEW refresh token в Redis
     * 9. Build TokenResponse
     * 10. Return new tokens
     *
     * TOKEN ROTATION:
     * ══════════════
     * Security best practice - refresh tokens ОДНОРАЗОВІ.
     *
     * Each refresh:
     * ✅ Generates NEW tokens (access + refresh)
     * ✅ Revokes OLD refresh token
     *
     * Benefits:
     * ✅ Limits stolen token lifetime
     * ✅ Detects token theft (reuse attempt fails)
     * ✅ Reduces attack window
     * ✅ Compliance з security standards
     *
     * WHY LOAD FRESH USER DATA:
     * ════════════════════════
     * User data може змінитися з моменту login:
     * - Roles changed (promoted to ADMIN)
     * - Account disabled
     * - Email updated
     *
     * Loading fresh data ensures JWT has current info.
     *
     * ERRORS:
     * ══════
     * - InvalidTokenException: token not found в Redis
     * - InvalidTokenException: token expired
     * - UsernameNotFoundException: user deleted
     *
     * @param request refresh token request
     * @return TokenResponse з new tokens
     * @throws com.tiles.auth.exception.InvalidTokenException if invalid
     */
    @Transactional
    @Override
    public TokenResponse refresh(RefreshTokenRequest request) {
        log.info("Token refresh attempt");

        // ════════════════════════════════════════
        // Step 1: Validate Refresh Token
        // ════════════════════════════════════════
        // Checks:
        // - Token exists в Redis
        // - Not expired (expiresAt check)
        // - Valid JSON format
        //
        // Throws InvalidTokenException if invalid
        refreshTokenService.validateRefreshToken(request.getRefreshToken());

        log.debug("Refresh token validated successfully");

        // ════════════════════════════════════════
        // Step 2: Extract User Info від Token
        // ════════════════════════════════════════
        // Get userId і username від token data в Redis
        String userId = refreshTokenService.getUserIdFromRefreshToken(
                request.getRefreshToken()
        );
        String username = refreshTokenService.getUsernameFromRefreshToken(
                request.getRefreshToken()
        );

        log.debug("Extracted user info from refresh token: userId={}, username={}",
                userId, username);

        // ════════════════════════════════════════
        // Step 3: Load Fresh User Data
        // ════════════════════════════════════════
        // Load user від database для get current data
        // (roles може змінитися, account може бути disabled, тощо)
        User user = userService.findByUsername(username);
        CustomUserDetails userDetails = new CustomUserDetails(user);

        log.debug("Loaded fresh user data from database");

        // ════════════════════════════════════════
        // Step 4: Generate NEW Tokens
        // ════════════════════════════════════════
        // NEW JWT access token з fresh user data
        String newAccessToken = tokenService.generateAccessToken(userDetails);

        log.debug("New access token generated");

        // NEW refresh token (UUID)
        String newRefreshToken = refreshTokenService.generateRefreshToken(
                userDetails.getUserId(),
                userDetails.getUsername(),
                userDetails.getEmail()
        );

        log.debug("New refresh token generated and stored in Redis");

        // ════════════════════════════════════════
        // Step 5: Revoke OLD Refresh Token
        // ════════════════════════════════════════
        // TOKEN ROTATION: old token одноразовий
        // Delete від Redis immediately
        refreshTokenService.revokeRefreshToken(request.getRefreshToken());

        log.debug("Old refresh token revoked (rotation)");

        // ════════════════════════════════════════
        // Step 6: Build Response
        // ════════════════════════════════════════
        TokenResponse response = authMapper.toTokenResponse(
                newAccessToken,
                newRefreshToken
        );

        log.info("Token refresh successful: username={}, userId={}",
                username, userId);

        return response;
    }

    /**
     * Logout Implementation
     *
     * Revokes single refresh token (current device).
     *
     * PROCESS FLOW:
     * ════════════
     * 1. Validate refresh token (optional, for logging)
     * 2. Delete token від Redis
     * 3. Remove від user session set
     *
     * ACCESS TOKEN:
     * ════════════
     * Access token залишається valid до expiry (15 min).
     *
     * Why not invalidate immediately:
     * - JWT stateless (no database lookup)
     * - Would require token blacklist (defeats purpose)
     * - 15 min short enough (acceptable risk)
     *
     * If need immediate invalidation:
     * - Use token blacklist (Redis)
     * - Gateway checks blacklist
     * - Trade-off: extra database lookup per request
     *
     * SINGLE DEVICE:
     * ═════════════
     * This revokes only current device's token.
     * Other devices залишаються logged in.
     *
     * For logout all devices: use logoutAll()
     *
     * @param request refresh token до revoke
     */
    @Transactional
    @Override
    public void logout(RefreshTokenRequest request) {
        log.info("Logout attempt");

        // Revoke refresh token (delete від Redis)
        // This makes token immediately invalid
        refreshTokenService.revokeRefreshToken(request.getRefreshToken());

        log.info("Logout successful - refresh token revoked");
    }

    /**
     * Logout All Devices Implementation
     *
     * Revokes всі refresh tokens для user (all sessions).
     *
     * PROCESS FLOW:
     * ════════════
     * 1. Validate refresh token (identify user)
     * 2. Extract userId від token
     * 3. Find all user's tokens (Redis set)
     * 4. Delete all tokens від Redis
     * 5. Delete user session set
     *
     * USE CASES:
     * ═════════
     * - User clicks "Logout from all devices"
     * - Password changed (security)
     * - Account compromised (security)
     * - Security breach suspected
     * - Admin forces logout
     *
     * USER SESSION SET:
     * ════════════════
     * Redis key: user_session:{userId}
     * Value: Set of refresh token UUIDs
     *
     * Example:
     * user_session:123 → {
     *   "uuid-1",  // Desktop browser
     *   "uuid-2",  // Mobile app
     *   "uuid-3"   // Tablet
     * }
     *
     * All these tokens будуть revoked.
     *
     * @param request refresh token (для identify user)
     */
    @Transactional
    @Override
    public void logoutAll(RefreshTokenRequest request) {
        log.info("Logout all devices attempt");

        // ════════════════════════════════════════
        // Step 1: Validate Token & Extract User ID
        // ════════════════════════════════════════
        // Validate token (ensure it's valid)
        refreshTokenService.validateRefreshToken(request.getRefreshToken());

        // Get userId від token data
        String userId = refreshTokenService.getUserIdFromRefreshToken(
                request.getRefreshToken()
        );

        log.debug("Identified user for logout all: userId={}", userId);

        // ════════════════════════════════════════
        // Step 2: Revoke All User Tokens
        // ════════════════════════════════════════
        // RefreshTokenService handles:
        // - Find user session set
        // - Get all token UUIDs
        // - Delete each token
        // - Delete session set
        refreshTokenService.revokeAllUserTokens(userId);

        log.info("Logout all devices successful: userId={} - all tokens revoked", userId);
    }
}