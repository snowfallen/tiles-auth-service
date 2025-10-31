package com.tiles.auth.service.impl;

import com.tiles.auth.exception.InvalidCredentialsException;
import com.tiles.auth.exception.UserAlreadyExistsException;
import com.tiles.auth.model.dto.RegisterRequest;
import com.tiles.auth.model.entity.Role;
import com.tiles.auth.model.entity.User;
import com.tiles.auth.model.security.CustomUserDetails;
import com.tiles.auth.repository.RoleRepository;
import com.tiles.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * User Service
 *
 * Відповідає за:
 * - User registration
 * - Loading user для authentication
 * - User management
 *
 * Implements UserDetailsService - Spring Security interface
 * для завантаження user during authentication.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class UserServiceImpl implements UserDetailsService, UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    /**
     * Load user by username для Spring Security
     *
     * Цей метод викликається Spring Security під час authentication.
     *
     * Flow:
     * 1. User відправляє username/password
     * 2. Spring Security викликає loadUserByUsername(username)
     * 3. Ми завантажуємо User з DB
     * 4. Spring Security порівнює passwords
     *
     * @param username username or email
     * @return UserDetails (CustomUserDetails wrapper)
     * @throws UsernameNotFoundException if user not found
     */
    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.debug("Loading user by username: {}", username);

        // Try to find by username first, then by email
        User user = userRepository.findByUsername(username)
                .or(() -> userRepository.findByEmail(username))
                .orElseThrow(() -> {
                    log.warn("User not found: {}", username);
                    return new UsernameNotFoundException("User not found: " + username);
                });

        // Check if account is enabled
        if (!user.getEnabled()) {
            log.warn("Account disabled: {}", username);
            throw new InvalidCredentialsException("Account is disabled");
        }

        log.debug("User loaded successfully: {}", username);
        return new CustomUserDetails(user);
    }

    /**
     * Register new user
     *
     * Flow:
     * 1. Check if username/email already exists
     * 2. Hash password (BCrypt)
     * 3. Create User entity
     * 4. Assign default USER role
     * 5. Save to database
     *
     * @param request registration data
     * @return created User
     * @throws UserAlreadyExistsException if username/email exists
     */
    @Transactional
    @Override
    public User registerUser(RegisterRequest request) {
        log.info("Registering new user: {}", request.getUsername());

        // Check if username already exists
        if (userRepository.existsByUsername(request.getUsername())) {
            log.warn("Username already exists: {}", request.getUsername());
            throw new UserAlreadyExistsException("Username already exists: " + request.getUsername());
        }

        // Check if email already exists
        if (userRepository.existsByEmail(request.getEmail())) {
            log.warn("Email already exists: {}", request.getEmail());
            throw new UserAlreadyExistsException("Email already exists: " + request.getEmail());
        }

        // Get USER role (default role for new users)
        Role userRole = roleRepository.findByName(Role.USER)
                .orElseThrow(() -> new RuntimeException("Default USER role not found in database"));

        // Create User entity
        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .passwordHash(passwordEncoder.encode(request.getPassword()))  // Hash password
                .enabled(true)
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .build();

        // Assign USER role
        user.addRole(userRole);

        // Save to database
        User savedUser = userRepository.save(user);

        log.info("User registered successfully: {}", savedUser.getUsername());
        return savedUser;
    }

    /**
     * Find user by username
     *
     * @param username username
     * @return User entity
     */
    @Transactional(readOnly = true)
    @Override
    public User findByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
    }

    /**
     * Find user by email
     *
     * @param email email
     * @return User entity
     */
    @Transactional(readOnly = true)
    @Override
    public User findByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + email));
    }

    /**
     * Check if username exists
     *
     * @param username username to check
     * @return true if exists
     */
    @Override
    public boolean existsByUsername(String username) {
        return userRepository.existsByUsername(username);
    }

    /**
     * Check if email exists
     *
     * @param email email to check
     * @return true if exists
     */
    @Override
    public boolean existsByEmail(String email) {
        return userRepository.existsByEmail(email);
    }
}
