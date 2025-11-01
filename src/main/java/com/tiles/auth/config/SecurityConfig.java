package com.tiles.auth.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Security Configuration
 *
 * Налаштування Spring Security для Auth Service.
 *
 * RESPONSIBILITIES:
 * ═══════════════
 * - Password hashing (BCrypt)
 * - Authentication mechanism (DAO-based)
 * - HTTP security rules (public/protected endpoints)
 * - Session management (stateless)
 *
 * ARCHITECTURE:
 * ════════════
 * Auth Service НЕ валідує JWT tokens - він їх СТВОРЮЄ!
 * JWT validation робить Gateway.
 *
 * Тому тут:
 * ✅ Password-based authentication (username/password)
 * ✅ BCrypt password hashing
 * ❌ NO JWT filters (не потрібні)
 * ❌ NO JWT validation (робить Gateway)
 *
 * AUTHENTICATION FLOW:
 * ═══════════════════
 * 1. User sends POST /auth/login {username, password}
 * 2. AuthController викликає AuthenticationManager.authenticate()
 * 3. AuthenticationManager використовує DaoAuthenticationProvider
 * 4. DaoAuthenticationProvider:
 *    - Loads user через UserDetailsService (UserServiceImpl)
 *    - Compares passwords через PasswordEncoder (BCrypt)
 *    - Returns Authentication object if success
 * 5. AuthService generates JWT tokens
 * 6. Returns tokens до client
 *
 * SECURITY FEATURES:
 * ═════════════════
 * - BCrypt password hashing (10 rounds)
 * - Stateless sessions (no HttpSession)
 * - CSRF disabled (not needed для stateless API)
 * - Public endpoints (login, register, JWKS)
 * - Protected endpoints (logout, logout-all)
 *
 * PUBLIC ENDPOINTS:
 * ════════════════
 * - POST /auth/login - authentication
 * - POST /auth/register - registration
 * - GET /.well-known/** - JWKS endpoints
 * - GET /actuator/health - health checks
 * - GET /actuator/info - application info
 *
 * PROTECTED ENDPOINTS:
 * ═══════════════════
 * - POST /auth/logout - requires refresh token
 * - POST /auth/logout-all - requires refresh token
 * - All other endpoints
 *
 * WHY STATELESS:
 * ═════════════
 * Microservice architecture → no server-side sessions
 * JWT tokens carry all needed information
 * Benefits:
 * ✅ Horizontal scaling (no session affinity)
 * ✅ Load balancing (any instance can handle request)
 * ✅ Cloud-native (stateless containers)
 *
 * @author snowfallen
 * @version 1.0.0
 * @since 2024-10-31
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    /**
     * UserDetailsService для loading users
     *
     * UserServiceImpl implements UserDetailsService interface.
     * Spring Security використовує це для authentication.
     *
     * Injected через constructor (RequiredArgsConstructor).
     */
    private final UserDetailsService userDetailsService;

    /**
     * Password Encoder Bean
     *
     * BCrypt password hashing algorithm.
     *
     * BCRYPT PROPERTIES:
     * ═════════════════
     * Algorithm: Blowfish-based password hashing
     * Strength: 10 rounds (2^10 = 1024 iterations)
     * Salt: Automatic (random, unique per password)
     * Output: 60-character string ($2a$10$...)
     *
     * Format: $2a$[rounds]$[salt][hash]
     * Example: $2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy
     *
     * SECURITY:
     * ════════
     * ✅ One-way function (cannot decode)
     * ✅ Rainbow table resistant (unique salt)
     * ✅ Brute-force resistant (slow by design)
     * ✅ Adaptive (can increase rounds for stronger security)
     *
     * ROUNDS BENCHMARK (approximate):
     * ══════════════════════════════
     * - 10 rounds: ~100ms per hash ✅ Recommended для login
     * - 12 rounds: ~400ms per hash (stronger, slower)
     * - 14 rounds: ~1.6s per hash (very strong, too slow)
     * - 16 rounds: ~6.4s per hash (impractical)
     *
     * WHY 10 ROUNDS:
     * ═════════════
     * Good balance між security і UX.
     * - Fast enough для login (user не чекає довго)
     * - Slow enough для brute-force protection
     * - Industry standard (OWASP recommendation)
     *
     * USAGE:
     * ═════
     * Hash password:
     * String hash = passwordEncoder.encode("password123");
     *
     * Verify password:
     * boolean matches = passwordEncoder.matches("password123", hash);
     *
     * @return BCryptPasswordEncoder з 10 rounds
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(10);
    }

    /**
     * Authentication Manager Bean
     *
     * Central component для authentication в Spring Security.
     *
     * RESPONSIBILITIES:
     * ═══════════════
     * - Orchestrates authentication process
     * - Delegates до AuthenticationProvider(s)
     * - Returns Authentication object if success
     * - Throws AuthenticationException if failure
     *
     * USAGE IN OUR CODE:
     * ═════════════════
     * AuthService викликає:
     * ```java
     * Authentication auth = authenticationManager.authenticate(
     *     new UsernamePasswordAuthenticationToken(username, password)
     * );
     * ```
     *
     * AUTHENTICATION PROCESS:
     * ══════════════════════
     * 1. Receives Authentication request (username + password)
     * 2. Passes до DaoAuthenticationProvider
     * 3. Provider loads user через UserDetailsService
     * 4. Provider checks password через PasswordEncoder
     * 5. Returns fully authenticated Authentication object
     * 6. OR throws BadCredentialsException if invalid
     *
     * PROVIDERS:
     * ═════════
     * AuthenticationManager can have multiple providers:
     * - DaoAuthenticationProvider (database authentication) ✅ We use
     * - LdapAuthenticationProvider (LDAP authentication)
     * - OAuth2LoginAuthenticationProvider (OAuth2)
     * - RememberMeAuthenticationProvider (remember-me)
     *
     * Each provider attempts authentication in order.
     * First successful provider wins.
     *
     * @param authConfig Spring Security's authentication configuration
     * @return configured AuthenticationManager
     * @throws Exception if configuration fails
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
     * Означає що user credentials зберігаються в database
     * і accessed через DAO (repository).
     *
     * COMPONENTS:
     * ══════════
     * 1. UserDetailsService: loads user від database
     * 2. PasswordEncoder: validates password hash
     *
     * AUTHENTICATION FLOW:
     * ═══════════════════
     * 1. User sends username + password
     * 2. Provider calls userDetailsService.loadUserByUsername(username)
     * 3. UserDetailsService queries database → returns UserDetails
     * 4. Provider calls passwordEncoder.matches(rawPassword, encodedPassword)
     * 5. If matches → authentication SUCCESS ✅
     * 6. If not matches → authentication FAILURE ❌
     *
     * WHY SEPARATE BEAN:
     * ═════════════════
     * Explicitly configured provider → clear dependencies:
     * - Which UserDetailsService to use
     * - Which PasswordEncoder to use
     * - Easy to test (can mock dependencies)
     * - Easy to customize (can add additional checks)
     *
     * ALTERNATIVE:
     * ═══════════
     * Spring Boot auto-configuration can create provider,
     * але explicit configuration clearer і more maintainable.
     *
     * @return configured DaoAuthenticationProvider
     */
    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();

        // Set UserDetailsService
        // Our UserServiceImpl implements UserDetailsService interface
        // Loads users від PostgreSQL database
        authProvider.setUserDetailsService(userDetailsService);

        // Set PasswordEncoder
        // BCrypt для hashing і validation passwords
        authProvider.setPasswordEncoder(passwordEncoder());

        return authProvider;
    }

    /**
     * Security Filter Chain
     *
     * Defines HTTP security rules для Auth Service.
     * Modern approach (Spring Security 5.7+) using lambda DSL.
     *
     * FILTER CHAIN:
     * ════════════
     * Spring Security uses chain of filters для process requests:
     * 1. SecurityContextPersistenceFilter
     * 2. LogoutFilter
     * 3. UsernamePasswordAuthenticationFilter
     * 4. FilterSecurityInterceptor
     * ... багато інших
     *
     * This configuration customizes filter chain behavior.
     *
     * CONFIGURATION:
     * ═════════════
     *
     * 1. CSRF Protection:
     * ─────────────────
     * DISABLED (not needed для stateless API)
     *
     * CSRF (Cross-Site Request Forgery):
     * - Attack: malicious site tricks user's browser
     * - Protection: CSRF token в forms/cookies
     * - When needed: session-based authentication
     * - Why disabled: JWT tokens не в cookies, stateless
     *
     * 2. Authorization Rules:
     * ─────────────────────
     * Public endpoints (permitAll):
     * - /auth/login - authentication
     * - /auth/register - user registration
     * - /.well-known/** - JWKS endpoints (public key)
     * - /actuator/health - health checks
     * - /actuator/info - application metadata
     *
     * Protected endpoints (authenticated):
     * - /auth/logout - requires valid refresh token
     * - /auth/logout-all - requires valid refresh token
     * - All other endpoints - requires authentication
     *
     * 3. Session Management:
     * ────────────────────
     * STATELESS - no server-side sessions
     *
     * SessionCreationPolicy.STATELESS:
     * - Spring Security не створює HttpSession
     * - No session cookies (JSESSIONID)
     * - No session affinity required
     * - Perfect для JWT-based authentication
     *
     * Benefits:
     * ✅ Horizontal scaling (no session replication)
     * ✅ Microservices-friendly
     * ✅ Cloud-native
     * ✅ Reduces memory usage
     *
     * 4. Authentication Provider:
     * ─────────────────────────
     * Uses our DaoAuthenticationProvider
     *
     * SECURITY NOTES:
     * ══════════════
     * ⚠️  Public endpoints MUST be carefully chosen
     * ⚠️  Never expose sensitive operations без auth
     * ⚠️  Always validate input (даже на public endpoints)
     * ⚠️  Monitor for abuse (rate limiting recommended)
     *
     * @param http HttpSecurity configuration object
     * @return configured SecurityFilterChain
     * @throws Exception if configuration fails
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // ════════════════════════════════════════
                // 1. CSRF Configuration
                // ════════════════════════════════════════
                // Disable CSRF protection
                // Not needed для stateless API з JWT tokens
                .csrf(csrf -> csrf.disable())

                // ════════════════════════════════════════
                // 2. Authorization Rules
                // ════════════════════════════════════════
                .authorizeHttpRequests(auth -> auth
                        // Public endpoints - anyone can access
                        // No authentication required
                        .requestMatchers(
                                "/auth/login",           // User login
                                "/auth/register",        // User registration
                                "/.well-known/**",       // JWKS endpoints (public key)
                                "/actuator/health",      // Health check (monitoring)
                                "/actuator/info"         // Application info
                        ).permitAll()

                        // All other endpoints require authentication
                        // This includes:
                        // - /auth/logout (needs refresh token)
                        // - /auth/logout-all (needs refresh token)
                        // - Any future endpoints
                        .anyRequest().authenticated()
                )

                // ════════════════════════════════════════
                // 3. Session Management
                // ════════════════════════════════════════
                // STATELESS - no server-side sessions
                // Perfect для JWT-based authentication
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                // ════════════════════════════════════════
                // 4. Authentication Provider
                // ════════════════════════════════════════
                // Use our custom DaoAuthenticationProvider
                // Configured з UserDetailsService + PasswordEncoder
                .authenticationProvider(authenticationProvider());

        // Build and return configured SecurityFilterChain
        return http.build();
    }
}
