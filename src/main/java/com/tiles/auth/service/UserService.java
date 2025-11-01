package com.tiles.auth.service;

import com.tiles.auth.dto.request.RegisterRequest;
import com.tiles.auth.entity.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.transaction.annotation.Transactional;

/**
 * User Service Interface
 *
 * Defines contract для user management operations.
 * Extends UserDetailsService для Spring Security integration.
 *
 * RESPONSIBILITIES:
 * ═══════════════
 * - User registration
 * - Load user для authentication (UserDetailsService)
 * - Find user by username/email
 * - Check username/email existence
 *
 * SPRING SECURITY INTEGRATION:
 * ═══════════════════════════
 * Implements UserDetailsService interface:
 * - loadUserByUsername(String) method required
 * - Called by AuthenticationManager during login
 * - Returns UserDetails (CustomUserDetails wrapper)
 *
 * @author snowfallen
 * @version 1.0.0
 * @since 2024-10-31
 */
public interface UserService extends UserDetailsService {

    /**
     * Register New User
     *
     * Creates new user account з hashed password.
     *
     * PROCESS:
     * ═══════
     * 1. Validate registration data (@Valid)
     * 2. Check username uniqueness
     * 3. Check email uniqueness
     * 4. Hash password (BCrypt, 10 rounds)
     * 5. Create User entity
     * 6. Assign default USER role
     * 7. Save to PostgreSQL database
     * 8. Return created User
     *
     * PASSWORD HASHING:
     * ════════════════
     * Algorithm: BCrypt
     * Strength: 10 rounds
     * Salt: automatic (random, unique)
     * Output: $2a$10$N9qo8uLO...
     *
     * DEFAULT ROLE:
     * ════════════
     * New users automatically get USER role.
     * ADMIN role assigned manually (future: через admin panel).
     *
     * ERRORS:
     * ══════
     * - UserAlreadyExistsException: username exists
     * - UserAlreadyExistsException: email exists
     * - RuntimeException: USER role not found в database
     *
     * @param request registration data (username, email, password)
     * @return created User entity
     * @throws com.tiles.auth.exception.UserAlreadyExistsException if exists
     */
    @Transactional
    User registerUser(RegisterRequest request);

    /**
     * Find User by Username
     *
     * Searches user в database by username.
     *
     * @param username username to search
     * @return User entity
     * @throws org.springframework.security.core.userdetails.UsernameNotFoundException if not found
     */
    @Transactional(readOnly = true)
    User findByUsername(String username);

    /**
     * Find User by Email
     *
     * Searches user в database by email.
     *
     * @param email email to search
     * @return User entity
     * @throws org.springframework.security.core.userdetails.UsernameNotFoundException if not found
     */
    @Transactional(readOnly = true)
    User findByEmail(String email);

    /**
     * Check Username Existence
     *
     * Efficient check without loading full User entity.
     *
     * Uses COUNT query instead of SELECT:
     * SELECT COUNT(*) > 0 FROM users WHERE username = ?
     *
     * Faster than findByUsername().isPresent()
     * (no need to load all user fields).
     *
     * @param username username to check
     * @return true if exists
     */
    boolean existsByUsername(String username);

    /**
     * Check Email Existence
     *
     * Efficient check without loading full User entity.
     *
     * @param email email to check
     * @return true if exists
     */
    boolean existsByEmail(String email);

    /**
     * Load User by Username (UserDetailsService)
     *
     * Required by UserDetailsService interface.
     * Called by Spring Security during authentication.
     *
     * PROCESS:
     * ═══════
     * 1. Try find by username
     * 2. If not found, try find by email
     * 3. If not found, throw UsernameNotFoundException
     * 4. Check if account enabled
     * 5. Wrap User в CustomUserDetails
     * 6. Return UserDetails
     *
     * SPRING SECURITY FLOW:
     * ════════════════════
     * 1. User submits login form
     * 2. UsernamePasswordAuthenticationToken created
     * 3. AuthenticationManager.authenticate() called
     * 4. DaoAuthenticationProvider calls loadUserByUsername()
     * 5. Provider compares passwords
     * 6. Returns Authentication object if success
     *
     * @param username username or email
     * @return UserDetails (CustomUserDetails)
     * @throws org.springframework.security.core.userdetails.UsernameNotFoundException if not found
     */
    @Override
    @Transactional(readOnly = true)
    org.springframework.security.core.userdetails.UserDetails loadUserByUsername(String username);
}
