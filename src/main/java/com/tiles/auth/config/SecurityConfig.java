package com.tiles.auth.config;

import com.tiles.auth.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Security Configuration
 *
 * Налаштування Spring Security для Auth Service.
 *
 * Key components:
 * - PasswordEncoder: BCrypt для hashing passwords
 * - AuthenticationManager: Handles authentication
 * - SecurityFilterChain: HTTP security rules
 *
 * Note: Auth Service НЕ потребує JWT validation filter,
 * бо він СТВОРЮЄ JWT, а не валідує їх.
 * JWT validation робить Gateway.
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final UserService userService;

    /**
     * Password Encoder Bean
     *
     * BCrypt - industry standard для password hashing.
     *
     * Properties:
     * - Strength: 10 rounds (2^10 = 1024 iterations)
     * - Salt: automatic (random, unique per password)
     * - One-way: неможливо decode
     * - Adaptive: можна збільшити rounds для stronger security
     *
     * BCrypt rounds benchmark (approximate):
     * - 10 rounds: ~100ms per hash (recommended for login)
     * - 12 rounds: ~400ms per hash
     * - 14 rounds: ~1.6s per hash
     *
     * More rounds = slower = more secure against brute force
     * But too slow = poor UX
     * 10 rounds = good balance
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(10);  // 10 rounds
    }

    /**
     * Authentication Manager Bean
     *
     * Central component для authentication в Spring Security.
     *
     * Usage:
     * AuthController викликає:
     * authenticationManager.authenticate(
     *     new UsernamePasswordAuthenticationToken(username, password)
     * )
     *
     * AuthenticationManager uses:
     * - DaoAuthenticationProvider (configured below)
     * - UserDetailsService (UserService)
     * - PasswordEncoder (BCrypt)
     *
     * Flow:
     * 1. Receive username + password
     * 2. Load user через UserDetailsService
     * 3. Compare passwords через PasswordEncoder
     * 4. Return Authentication object if success
     * 5. Throw exception if failure
     */
    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    /**
     * DAO Authentication Provider
     *
     * Provider для database-backed authentication.
     *
     * "DAO" = Data Access Object pattern
     * Означає що user data береться з database через UserDetailsService.
     *
     * Components:
     * - UserDetailsService: loads user from DB (UserService)
     * - PasswordEncoder: validates password (BCrypt)
     */
    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();

        // Set UserDetailsService (our UserService implements this)
        authProvider.setUserDetailsService(userService);

        // Set PasswordEncoder (BCrypt)
        authProvider.setPasswordEncoder(passwordEncoder());

        return authProvider;
    }

    /**
     * Security Filter Chain
     *
     * Defines HTTP security rules для Auth Service.
     *
     * Rules:
     * 1. Public endpoints (no authentication required):
     *    - POST /auth/login
     *    - POST /auth/register
     *    - GET /.well-known/** (JWKS endpoints)
     *    - GET /actuator/health
     *
     * 2. Protected endpoints (authentication required):
     *    - POST /auth/logout
     *    - POST /auth/logout-all
     *    - All other endpoints
     *
     * Session management:
     * - STATELESS (no server-side sessions)
     * - Spring Security не створює HttpSession
     * - Authentication через JWT (managed by us, not Spring Security)
     *
     * CSRF:
     * - Disabled (not needed для stateless API)
     * - CSRF захист потрібен для session-based auth
     * - З JWT tokens CSRF не relevan
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // Disable CSRF (not needed для stateless API)
                .csrf(csrf -> csrf.disable())

                // Configure authorization rules
                .authorizeHttpRequests(auth -> auth
                        // Public endpoints - anyone can access
                        .requestMatchers(
                                "/auth/login",
                                "/auth/register",
                                "/.well-known/**",       // JWKS endpoints
                                "/actuator/health",      // Health check
                                "/actuator/info"         // Info endpoint
                        ).permitAll()

                        // All other endpoints require authentication
                        .anyRequest().authenticated()
                )

                // Session management - STATELESS
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                // Set authentication provider
                .authenticationProvider(authenticationProvider());

        return http.build();
    }
}
