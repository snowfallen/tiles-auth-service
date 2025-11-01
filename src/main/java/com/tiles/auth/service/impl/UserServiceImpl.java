package com.tiles.auth.service.impl;

import com.tiles.auth.dto.request.RegisterRequest;
import com.tiles.auth.entity.Role;
import com.tiles.auth.entity.User;
import com.tiles.auth.exception.InvalidCredentialsException;
import com.tiles.auth.exception.UserAlreadyExistsException;
import com.tiles.auth.repository.RoleRepository;
import com.tiles.auth.repository.UserRepository;
import com.tiles.auth.security.CustomUserDetails;
import com.tiles.auth.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * User Service Implementation
 *
 * Manages user operations і implements Spring Security UserDetailsService.
 *
 * RESPONSIBILITIES:
 * ═══════════════
 * - User registration (create new accounts)
 * - Load user для authentication (Spring Security)
 * - Find users (by username, email)
 * - Check user existence
 *
 * SPRING SECURITY INTEGRATION:
 * ═══════════════════════════
 * Implements UserDetailsService interface.
 *
 * This interface has ONE method:
 * - loadUserByUsername(String username)
 *
 * Spring Security calls this method during authentication:
 * 1. User submits login (username + password)
 * 2. AuthenticationManager needs to load user
 * 3. Calls UserDetailsService.loadUserByUsername()
 * 4. We load user від database
 * 5. Return UserDetails (CustomUserDetails)
 * 6. AuthenticationManager validates password
 *
 * DEPENDENCIES:
 * ════════════
 * - UserRepository: Database access для users
 * - RoleRepository: Database access для roles
 * - PasswordEncoder: BCrypt password hashing
 *
 * TRANSACTIONAL:
 * ═════════════
 * All database operations @Transactional:
 * - Read-only operations: @Transactional(readOnly = true)
 * - Write operations: @Transactional
 *
 * Benefits:
 * ✅ Database consistency
 * ✅ Automatic rollback on errors
 * ✅ Connection management
 * ✅ Lazy loading works (Hibernate session open)
 *
 * @author snowfallen
 * @version 1.0.0
 * @since 2024-10-31
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class UserServiceImpl implements UserService {

    /**
     * User Repository
     *
     * Spring Data JPA repository для User entity.
     *
     * Provides methods:
     * - save(user): Insert/update user
     * - findById(id): Find by primary key
     * - findByUsername(username): Custom query
     * - findByEmail(email): Custom query
     * - existsByUsername(username): Existence check
     * - existsByEmail(email): Existence check
     * - тощо
     */
    private final UserRepository userRepository;

    /**
     * Role Repository
     *
     * Spring Data JPA repository для Role entity.
     *
     * Roles are almost static (USER, ADMIN).
     * Repository used mainly для lookup during registration.
     */
    private final RoleRepository roleRepository;

    /**
     * Password Encoder
     *
     * BCrypt password hashing.
     * Configured в SecurityConfig з 10 rounds.
     *
     * Operations:
     * - encode(raw): Hash plain password
     * - matches(raw, encoded): Verify password
     */
    private final PasswordEncoder passwordEncoder;

    /**
     * Load User by Username (Spring Security)
     *
     * Required by UserDetailsService interface.
     * Called by Spring Security during authentication.
     *
     * AUTHENTICATION FLOW:
     * ═══════════════════
     * 1. User POSTs /auth/login {username, password}
     * 2. AuthController calls authenticationManager.authenticate()
     * 3. AuthenticationManager delegates до DaoAuthenticationProvider
     * 4. Provider calls userDetailsService.loadUserByUsername() ← THIS METHOD
     * 5. We load User від database
     * 6. Check if account enabled
     * 7. Wrap User в CustomUserDetails
     * 8. Return UserDetails до provider
     * 9. Provider validates password (BCrypt.matches())
     * 10. Returns authenticated Authentication object
     *
     * FLEXIBLE USERNAME:
     * ═════════════════
     * Method accepts "username" parameter, але we support both:
     * - Username: "admin"
     * - Email: "admin@example.com"
     *
     * Process:
     * 1. Try find by username
     * 2. If not found, try find by email
     * 3. If still not found, throw UsernameNotFoundException
     *
     * Why support both:
     * ✅ Better UX (users can login з email)
     * ✅ Flexibility (username or email)
     * ✅ Common pattern (many apps support this)
     *
     * ACCOUNT VALIDATION:
     * ══════════════════
     * After loading user, check if account enabled.
     *
     * If disabled:
     * - Throw InvalidCredentialsException
     * - User cannot login (even з correct password)
     *
     * Use cases для disabled accounts:
     * - Account suspended (policy violation)
     * - Account banned (abuse)
     * - Account pending activation (email verification)
     * - Account deleted (soft delete)
     *
     * CUSTOMUSERDETAILS WRAPPER:
     * ═════════════════════════
     * Spring Security expects UserDetails interface.
     * Our User entity doesn't implement it.
     *
     * Solution: CustomUserDetails wrapper
     * - Implements UserDetails
     * - Wraps User entity
     * - Provides Spring Security methods
     * - Adds convenience methods (getUserId, getEmail)
     *
     * ERRORS:
     * ══════
     * - UsernameNotFoundException: User not found
     * - InvalidCredentialsException: Account disabled
     *
     * Note: Don't throw different exceptions для "user not found"
     * vs "wrong password" - security through obscurity.
     * Generic "invalid credentials" message prevents username enumeration.
     *
     * @param username username or email
     * @return UserDetails (CustomUserDetails wrapper)
     * @throws UsernameNotFoundException if user not found
     * @throws InvalidCredentialsException if account disabled
     */
    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.debug("Loading user by username: {}", username);

        // ════════════════════════════════════════
        // Step 1: Try Find by Username
        // ════════════════════════════════════════
        // First attempt: exact username match
        // userRepository.findByUsername() returns Optional<User>
        User user = userRepository.findByUsername(username)
                // ════════════════════════════════════════
                // Step 2: If Not Found, Try Email
                // ════════════════════════════════════════
                // .or() executed only if first Optional empty
                // Lazy evaluation - efficient (single DB query if username found)
                .or(() -> userRepository.findByEmail(username))
                // ════════════════════════════════════════
                // Step 3: If Still Not Found, Throw Exception
                // ════════════════════════════════════════
                // .orElseThrow() if both attempts failed
                .orElseThrow(() -> {
                    log.warn("User not found: {}", username);
                    return new UsernameNotFoundException("User not found: " + username);
                });

        log.debug("User found: username={}, userId={}", user.getUsername(), user.getId());

        // ════════════════════════════════════════
        // Step 4: Check if Account Enabled
        // ════════════════════════════════════════
        // User.enabled field controls account access
        // If false, user cannot login (even з correct password)
        if (!user.getEnabled()) {
            log.warn("Account disabled: username={}", username);
            throw new InvalidCredentialsException("Account is disabled");
        }

        log.debug("Account is enabled, loading complete");

        // ════════════════════════════════════════
        // Step 5: Wrap в CustomUserDetails
        // ════════════════════════════════════════
        // CustomUserDetails implements UserDetails interface
        // Provides Spring Security required methods:
        // - getUsername(), getPassword()
        // - getAuthorities() (roles → GrantedAuthority)
        // - isEnabled(), isAccountNonExpired(), тощо
        //
        // Plus our custom methods:
        // - getUserId(), getEmail()
        // - getRoleNames()
        CustomUserDetails userDetails = new CustomUserDetails(user);

        log.debug("User loaded successfully: username={}, roles={}",
                user.getUsername(),
                userDetails.getRoleNames());

        return userDetails;
    }

    /**
     * Register New User
     *
     * Creates new user account з hashed password.
     *
     * REGISTRATION FLOW:
     * ═════════════════
     * 1. Validate request data (@Valid в controller)
     * 2. Check username uniqueness
     * 3. Check email uniqueness
     * 4. Hash password (BCrypt)
     * 5. Create User entity
     * 6. Assign default USER role
     * 7. Save to database
     * 8. Return created User
     *
     * UNIQUENESS CHECKS:
     * ═════════════════
     * Both username і email must be unique.
     * Database has UNIQUE constraints, але we check first
     * для better error messages.
     *
     * Why check before insert:
     * ✅ Better error messages (know which field duplicate)
     * ✅ Avoid database exception (cleaner code)
     * ✅ Can return specific error (username vs email)
     *
     * existsByUsername() / existsByEmail():
     * - Efficient (COUNT query, not SELECT)
     * - No need to load full User entity
     * - Returns boolean
     *
     * PASSWORD HASHING:
     * ════════════════
     * Plain password NEVER stored в database.
     *
     * Process:
     * 1. User submits: "password123"
     * 2. BCrypt hashes: "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZ..."
     * 3. Store hash в database (passwordHash field)
     *
     * BCrypt properties:
     * - One-way function (cannot decode)
     * - Unique salt per password (rainbow table resistant)
     * - 10 rounds (2^10 = 1024 iterations)
     * - ~100ms per hash (brute-force resistant)
     *
     * Why BCrypt (not SHA256):
     * ✅ Designed для passwords (slow by design)
     * ✅ Automatic salting
     * ✅ Adaptive (can increase rounds)
     * ✅ Industry standard
     *
     * SHA256 NOT suitable:
     * ❌ Too fast (easy to brute-force)
     * ❌ No built-in salting
     * ❌ Not designed для passwords
     *
     * DEFAULT ROLE:
     * ════════════
     * All new users get USER role automatically.
     *
     * Role hierarchy:
     * - USER: Basic permissions (read own data)
     * - ADMIN: Full permissions (manage users, тощо)
     *
     * ADMIN role assigned:
     * - Manually (database update)
     * - By existing admin (future: admin panel)
     * - Never during registration (security)
     *
     * Role lookup:
     * roleRepository.findByName("USER") returns Optional<Role>
     * If not found → RuntimeException (data integrity issue)
     *
     * This should never happen if:
     * ✅ Liquibase migrations ran correctly
     * ✅ Default roles inserted (004-insert-default-roles.yaml)
     *
     * If missing → application cannot start properly.
     *
     * USER ENTITY CREATION:
     * ════════════════════
     * User.builder() creates User з default values:
     * - enabled: true (account active)
     * - accountNonExpired: true (account не expired)
     * - accountNonLocked: true (account не locked)
     * - credentialsNonExpired: true (password не expired)
     *
     * These fields support:
     * - Account suspension (enabled = false)
     * - Account expiry (accountNonExpired = false)
     * - Account locking (accountNonLocked = false)
     * - Password expiry (credentialsNonExpired = false)
     *
     * Timestamps:
     * - createdAt: @CreationTimestamp (automatic)
     * - updatedAt: @UpdateTimestamp (automatic)
     *
     * DATABASE SAVE:
     * ═════════════
     * userRepository.save(user):
     * - JPA persists entity to database
     * - Executes INSERT statement
     * - Generates UUID (if not set)
     * - Saves to "users" table
     * - Also saves relationship (user_roles junction table)
     *
     * @Transactional ensures:
     * - All operations atomic (commit/rollback)
     * - If error, no partial data saved
     * - Database consistency maintained
     *
     * ERRORS:
     * ══════
     * - UserAlreadyExistsException: username exists
     * - UserAlreadyExistsException: email exists
     * - RuntimeException: USER role not found
     *
     * @param request registration data (username, email, password)
     * @return created User entity
     * @throws UserAlreadyExistsException if username/email exists
     */
    @Transactional
    @Override
    public User registerUser(RegisterRequest request) {
        log.info("Registering new user: username={}, email={}",
                request.getUsername(),
                request.getEmail());

        // ════════════════════════════════════════
        // Step 1: Check Username Uniqueness
        // ════════════════════════════════════════
        // existsByUsername() executes:
        // SELECT COUNT(*) > 0 FROM users WHERE username = ?
        if (userRepository.existsByUsername(request.getUsername())) {
            log.warn("Username already exists: {}", request.getUsername());
            throw new UserAlreadyExistsException(
                    "Username already exists: " + request.getUsername()
            );
        }

        log.debug("Username available: {}", request.getUsername());

        // ════════════════════════════════════════
        // Step 2: Check Email Uniqueness
        // ════════════════════════════════════════
        // existsByEmail() executes:
        // SELECT COUNT(*) > 0 FROM users WHERE email = ?
        if (userRepository.existsByEmail(request.getEmail())) {
            log.warn("Email already exists: {}", request.getEmail());
            throw new UserAlreadyExistsException(
                    "Email already exists: " + request.getEmail()
            );
        }

        log.debug("Email available: {}", request.getEmail());

        // ════════════════════════════════════════
        // Step 3: Get Default USER Role
        // ════════════════════════════════════════
        // Load USER role від database
        // Should exist (inserted by Liquibase migration)
        Role userRole = roleRepository.findByName(Role.USER)
                .orElseThrow(() -> {
                    log.error("❌ CRITICAL: Default USER role not found in database!");
                    return new RuntimeException("Default USER role not found in database");
                });

        log.debug("Default USER role loaded: roleId={}", userRole.getId());

        // ════════════════════════════════════════
        // Step 4: Hash Password
        // ════════════════════════════════════════
        // BCrypt hash з 10 rounds
        // Example input: "password123"
        // Example output: "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
        String hashedPassword = passwordEncoder.encode(request.getPassword());

        log.debug("Password hashed successfully");

        // ════════════════════════════════════════
        // Step 5: Create User Entity
        // ════════════════════════════════════════
        // Builder pattern для clean construction
        User user = User.builder()
                // User data від request
                .username(request.getUsername())
                .email(request.getEmail())
                .passwordHash(hashedPassword)  // ← Hashed, not plain!

                // Account status flags (all true = active account)
                .enabled(true)                  // Account active
                .accountNonExpired(true)        // Account не expired
                .accountNonLocked(true)         // Account не locked
                .credentialsNonExpired(true)    // Password не expired

                // Timestamps set automatically:
                // - createdAt: @CreationTimestamp
                // - updatedAt: @UpdateTimestamp
                .build();

        log.debug("User entity created: username={}", user.getUsername());

        // ════════════════════════════════════════
        // Step 6: Assign USER Role
        // ════════════════════════════════════════
        // addRole() helper method:
        // - Adds role до user.roles Set
        // - Maintains bidirectional relationship
        user.addRole(userRole);

        log.debug("USER role assigned to user");

        // ════════════════════════════════════════
        // Step 7: Save to Database
        // ════════════════════════════════════════
        // Persist User entity
        // Also persists role relationship (user_roles table)
        User savedUser = userRepository.save(user);

        log.info("User registered successfully: username={}, userId={}, email={}",
                savedUser.getUsername(),
                savedUser.getId(),
                savedUser.getEmail());

        return savedUser;
    }

    /**
     * Find User by Username
     *
     * Loads user від database by username.
     *
     * USAGE:
     * ═════
     * - Token refresh (get fresh user data)
     * - Profile lookup
     * - Admin operations
     *
     * EAGER LOADING:
     * ═════════════
     * User entity has:
     * @ManyToMany(fetch = FetchType.EAGER)
     * private Set<Role> roles;
     *
     * This means roles loaded immediately з user.
     * Single query з JOIN:
     * SELECT u.*, r.*
     * FROM users u
     * LEFT JOIN user_roles ur ON u.id = ur.user_id
     * LEFT JOIN roles r ON ur.role_id = r.id
     * WHERE u.username = ?
     *
     * Why EAGER (not LAZY):
     * ✅ Always need roles (authentication/authorization)
     * ✅ Avoid N+1 query problem
     * ✅ Simple code (no lazy loading exceptions)
     *
     * Trade-off:
     * ⚠️  Slightly larger query
     * ⚠️  Cannot control when roles loaded
     *
     * For auth service, EAGER є OK:
     * - Small number of roles per user
     * - Always need roles anyway
     *
     * @param username username to search
     * @return User entity з roles
     * @throws UsernameNotFoundException if not found
     */
    @Transactional(readOnly = true)
    @Override
    public User findByUsername(String username) {
        log.debug("Finding user by username: {}", username);

        return userRepository.findByUsername(username)
                .orElseThrow(() -> {
                    log.warn("User not found by username: {}", username);
                    return new UsernameNotFoundException("User not found: " + username);
                });
    }

    /**
     * Find User by Email
     *
     * Loads user від database by email.
     *
     * Similar to findByUsername(), але searches by email.
     *
     * USE CASES:
     * ═════════
     * - Password reset (send email)
     * - Email verification
     * - Admin user lookup
     *
     * @param email email to search
     * @return User entity з roles
     * @throws UsernameNotFoundException if not found
     */
    @Transactional(readOnly = true)
    @Override
    public User findByEmail(String email) {
        log.debug("Finding user by email: {}", email);

        return userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    log.warn("User not found by email: {}", email);
                    return new UsernameNotFoundException("User not found: " + email);
                });
    }

    /**
     * Check Username Existence
     *
     * Efficient existence check without loading User entity.
     *
     * QUERY:
     * ═════
     * SELECT COUNT(*) > 0 FROM users WHERE username = ?
     *
     * Why efficient:
     * ✅ No need to load all user fields
     * ✅ Database can use index
     * ✅ Returns boolean only
     * ✅ Faster than findByUsername().isPresent()
     *
     * USE CASES:
     * ═════════
     * - Registration validation
     * - Username availability check
     * - Form validation (AJAX check)
     *
     * @param username username to check
     * @return true if exists, false if available
     */
    @Override
    public boolean existsByUsername(String username) {
        log.debug("Checking username existence: {}", username);

        boolean exists = userRepository.existsByUsername(username);

        log.debug("Username exists: {} = {}", username, exists);

        return exists;
    }

    /**
     * Check Email Existence
     *
     * Efficient existence check without loading User entity.
     *
     * Similar to existsByUsername().
     *
     * @param email email to check
     * @return true if exists, false if available
     */
    @Override
    public boolean existsByEmail(String email) {
        log.debug("Checking email existence: {}", email);

        boolean exists = userRepository.existsByEmail(email);

        log.debug("Email exists: {} = {}", email, exists);

        return exists;
    }
}
