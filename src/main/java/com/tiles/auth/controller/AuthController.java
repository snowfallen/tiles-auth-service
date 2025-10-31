package com.tiles.auth.controller;

import com.tiles.auth.model.dto.*;
import com.tiles.auth.model.entity.User;
import com.tiles.auth.model.security.CustomUserDetails;
import com.tiles.auth.service.RefreshTokenService;
import com.tiles.auth.service.TokenService;
import com.tiles.auth.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

/**
 * Auth Controller
 *
 * REST endpoints для authentication:
 * - POST /auth/login - User login
 * - POST /auth/register - User registration
 * - POST /auth/refresh - Refresh access token
 * - POST /auth/logout - Logout (revoke refresh token)
 * - POST /auth/logout-all - Logout from all devices
 *
 * All endpoints return consistent JSON responses.
 */
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final UserService userService;
    private final TokenService tokenService;
    private final RefreshTokenService refreshTokenService;

    /**
     * Login Endpoint
     *
     * POST /auth/login
     *
     * Flow:
     * 1. Authenticate username/password через Spring Security
     * 2. Generate JWT access token
     * 3. Generate refresh token (UUID, store in Redis)
     * 4. Return tokens + user info
     *
     * Request:
     * {
     *   "username": "admin",
     *   "password": "password123"
     * }
     *
     * Response:
     * {
     *   "accessToken": "eyJhbGc...",
     *   "refreshToken": "550e8400...",
     *   "tokenType": "Bearer",
     *   "expiresIn": 900,
     *   "user": {
     *     "id": "123e4567...",
     *     "username": "admin",
     *     "email": "admin@tiles.local",
     *     "roles": ["USER", "ADMIN"]
     *   }
     * }
     */
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
        log.info("Login attempt for user: {}", request.getUsername());

        // 1. Authenticate with Spring Security
        // AuthenticationManager викликає UserService.loadUserByUsername()
        // і перевіряє password через PasswordEncoder
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );

        // 2. Extract authenticated user
        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();

        // 3. Generate JWT access token
        String accessToken = tokenService.generateAccessToken(userDetails);

        // 4. Generate refresh token (UUID, stored in Redis)
        String refreshToken = refreshTokenService.generateRefreshToken(
                userDetails.getUserId(),
                userDetails.getUsername(),
                userDetails.getEmail()
        );

        // 5. Build response
        LoginResponse response = LoginResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(900L)  // 15 minutes in seconds
                .user(LoginResponse.UserInfo.builder()
                        .id(userDetails.getUserId())
                        .username(userDetails.getUsername())
                        .email(userDetails.getEmail())
                        .roles(userDetails.getRoleNames())
                        .build())
                .build();

        log.info("Login successful for user: {}", request.getUsername());
        return ResponseEntity.ok(response);
    }

    /**
     * Register Endpoint
     *
     * POST /auth/register
     *
     * Flow:
     * 1. Validate request (username, email, password)
     * 2. Check if username/email already exists
     * 3. Create user with hashed password
     * 4. Assign default USER role
     * 5. Save to database
     * 6. Auto-login (generate tokens)
     * 7. Return tokens + user info
     *
     * Request:
     * {
     *   "username": "john_doe",
     *   "email": "john@example.com",
     *   "password": "securepass123"
     * }
     *
     * Response: Same as login
     */
    @PostMapping("/register")
    public ResponseEntity<LoginResponse> register(@Valid @RequestBody RegisterRequest request) {
        log.info("Registration attempt for username: {}", request.getUsername());

        // 1. Register user (creates user with hashed password)
        User user = userService.registerUser(request);

        // 2. Create UserDetails for token generation
        CustomUserDetails userDetails = new CustomUserDetails(user);

        // 3. Generate tokens (auto-login after registration)
        String accessToken = tokenService.generateAccessToken(userDetails);
        String refreshToken = refreshTokenService.generateRefreshToken(
                userDetails.getUserId(),
                userDetails.getUsername(),
                userDetails.getEmail()
        );

        // 4. Build response
        LoginResponse response = LoginResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(900L)
                .user(LoginResponse.UserInfo.builder()
                        .id(userDetails.getUserId())
                        .username(userDetails.getUsername())
                        .email(userDetails.getEmail())
                        .roles(userDetails.getRoleNames())
                        .build())
                .build();

        log.info("Registration successful for user: {}", request.getUsername());
        return ResponseEntity.ok(response);
    }

    /**
     * Refresh Token Endpoint
     *
     * POST /auth/refresh
     *
     * Flow:
     * 1. Validate refresh token (check Redis)
     * 2. Extract userId from refresh token
     * 3. Load user from database
     * 4. Generate NEW access token
     * 5. Generate NEW refresh token (rotation!)
     * 6. Revoke OLD refresh token
     * 7. Return new tokens
     *
     * Request:
     * {
     *   "refreshToken": "550e8400-e29b-41d4-a716-446655440000"
     * }
     *
     * Response:
     * {
     *   "accessToken": "eyJhbGc...",
     *   "refreshToken": "660e8400-e29b-41d4-a716-446655440001",
     *   "tokenType": "Bearer",
     *   "expiresIn": 900
     * }
     */
    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(@Valid @RequestBody RefreshTokenRequest request) {
        log.info("Token refresh attempt");

        // 1. Validate refresh token
        refreshTokenService.validateRefreshToken(request.getRefreshToken());

        // 2. Extract user info from refresh token
        String userId = refreshTokenService.getUserIdFromRefreshToken(request.getRefreshToken());
        String username = refreshTokenService.getUsernameFromRefreshToken(request.getRefreshToken());

        // 3. Load user from database (get fresh data + roles)
        User user = userService.findByUsername(username);
        CustomUserDetails userDetails = new CustomUserDetails(user);

        // 4. Generate NEW access token
        String newAccessToken = tokenService.generateAccessToken(userDetails);

        // 5. Generate NEW refresh token
        String newRefreshToken = refreshTokenService.generateRefreshToken(
                userDetails.getUserId(),
                userDetails.getUsername(),
                userDetails.getEmail()
        );

        // 6. Revoke OLD refresh token (rotation для security)
        refreshTokenService.revokeRefreshToken(request.getRefreshToken());

        // 7. Build response
        TokenResponse response = TokenResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken)
                .tokenType("Bearer")
                .expiresIn(900L)
                .build();

        log.info("Token refresh successful for user: {}", username);
        return ResponseEntity.ok(response);
    }

    /**
     * Logout Endpoint
     *
     * POST /auth/logout
     *
     * Flow:
     * 1. Validate refresh token
     * 2. Revoke refresh token (delete from Redis)
     * 3. Client should discard access token
     *
     * Note: Access token залишається valid до expiry (15 min),
     * але це OK бо короткий TTL.
     *
     * Request:
     * {
     *   "refreshToken": "550e8400-e29b-41d4-a716-446655440000"
     * }
     *
     * Response:
     * {
     *   "message": "Logged out successfully"
     * }
     */
    @PostMapping("/logout")
    public ResponseEntity<?> logout(@Valid @RequestBody RefreshTokenRequest request) {
        log.info("Logout attempt");

        // Revoke refresh token
        refreshTokenService.revokeRefreshToken(request.getRefreshToken());

        log.info("Logout successful");
        return ResponseEntity.ok(new MessageResponse("Logged out successfully"));
    }

    /**
     * Logout All Devices Endpoint
     *
     * POST /auth/logout-all
     *
     * Flow:
     * 1. Validate refresh token (identify user)
     * 2. Get userId from refresh token
     * 3. Revoke ALL refresh tokens для цього user
     * 4. User logged out з всіх devices
     *
     * Use case:
     * - Security breach suspected
     * - User wants to logout from all devices
     * - Password change
     *
     * Request:
     * {
     *   "refreshToken": "550e8400-e29b-41d4-a716-446655440000"
     * }
     *
     * Response:
     * {
     *   "message": "Logged out from all devices successfully"
     * }
     */
    @PostMapping("/logout-all")
    public ResponseEntity<?> logoutAll(@Valid @RequestBody RefreshTokenRequest request) {
        log.info("Logout all devices attempt");

        // 1. Validate refresh token
        refreshTokenService.validateRefreshToken(request.getRefreshToken());

        // 2. Get userId
        String userId = refreshTokenService.getUserIdFromRefreshToken(request.getRefreshToken());

        // 3. Revoke all tokens для user
        refreshTokenService.revokeAllUserTokens(userId);

        log.info("Logout all devices successful for user: {}", userId);
        return ResponseEntity.ok(new MessageResponse("Logged out from all devices successfully"));
    }

    /**
     * Simple message response DTO
     */
    private record MessageResponse(String message) {}
}
