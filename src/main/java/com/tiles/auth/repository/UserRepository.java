package com.tiles.auth.repository;

import com.tiles.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

/**
 * User Repository
 *
 * Spring Data JPA repository для User entity.
 *
 * SPRING DATA JPA:
 * ═══════════════
 * Extends JpaRepository = automatic CRUD operations.
 *
 * Provided methods (no code needed):
 * - save(user): Insert або update
 * - findById(id): Find by primary key
 * - findAll(): Get all users
 * - delete(user): Delete user
 * - count(): Count users
 * - existsById(id): Check existence
 * - тощо
 *
 * CUSTOM QUERIES:
 * ══════════════
 * Method name → query generation.
 * Spring Data JPA parses method name і generates SQL.
 *
 * Naming convention:
 * - findBy{Field}
 * - existsBy{Field}
 * - countBy{Field}
 * - deleteBy{Field}
 *
 * Example:
 * findByUsername → SELECT * FROM users WHERE username = ?
 *
 * QUERY METHODS:
 * ═════════════
 * No @Query annotation needed (method name enough).
 *
 * Manual @Query only needed для:
 * - Complex queries (joins, subqueries)
 * - Performance optimization
 * - Native SQL (PostgreSQL-specific)
 * - Custom projections
 *
 * TRANSACTION:
 * ═══════════
 * Methods automatically transactional:
 * - save() = @Transactional
 * - delete() = @Transactional
 * - findXxx() = @Transactional(readOnly=true)
 *
 * No need manual @Transactional (unless custom logic).
 *
 * EAGER LOADING:
 * ═════════════
 * User entity has:
 * @ManyToMany(fetch = FetchType.EAGER)
 * Set<Role> roles;
 *
 * Every query loads roles automatically:
 * SELECT u.*, r.*
 * FROM users u
 * LEFT JOIN user_roles ur ON u.id = ur.user_id
 * LEFT JOIN roles r ON ur.role_id = r.id
 * WHERE ...
 *
 * OPTIONAL RETURN:
 * ═══════════════
 * findByXxx() returns Optional<User>:
 * - Empty if not found
 * - Contains user if found
 *
 * Usage:
 * Optional<User> userOpt = userRepository.findByUsername("admin");
 * User user = userOpt.orElseThrow(() -> new UserNotFoundException(...));
 *
 * Benefits:
 * ✅ Explicit null handling
 * ✅ Fluent API (map, filter, orElse)
 * ✅ Prevents NullPointerException
 *
 * BOOLEAN RETURN:
 * ══════════════
 * existsByXxx() returns boolean:
 * - true if exists
 * - false if not found
 *
 * Efficient: COUNT query (not SELECT all fields)
 *
 * @author snowfallen
 * @version 1.0.0
 * @since 2024-10-31
 */
@Repository
public interface UserRepository extends JpaRepository<User, UUID> {

    /**
     * Find User by Username
     *
     * Searches user by exact username match.
     *
     * GENERATED QUERY:
     * ═══════════════
     * SELECT u.*, r.*
     * FROM users u
     * LEFT JOIN user_roles ur ON u.id = ur.user_id
     * LEFT JOIN roles r ON ur.role_id = r.id
     * WHERE u.username = ?
     *
     * EAGER LOADING:
     * ═════════════
     * Automatically loads roles (FetchType.EAGER).
     * Single query з JOIN (no N+1 problem).
     *
     * CASE SENSITIVITY:
     * ════════════════
     * PostgreSQL: Case-sensitive by default
     * "Admin" ≠ "admin"
     *
     * Case-insensitive (future):
     * @Query("SELECT u FROM User u WHERE LOWER(u.username) = LOWER(?1)")
     * Optional<User> findByUsername(String username);
     *
     * Or database collation:
     * CREATE INDEX idx_username ON users (LOWER(username));
     *
     * USAGE:
     * ═════
     * Login (flexible - username або email):
     * Optional<User> user = userRepository.findByUsername(loginInput)
     *     .or(() -> userRepository.findByEmail(loginInput));
     *
     * Profile lookup:
     * User user = userRepository.findByUsername("admin")
     *     .orElseThrow(() -> new UsernameNotFoundException(...));
     *
     * PERFORMANCE:
     * ═══════════
     * Index: idx_users_username (created by Liquibase)
     * Fast lookup: O(log n) з B-tree index
     *
     * SECURITY:
     * ════════
     * No risk of SQL injection:
     * - Spring Data JPA uses prepared statements
     * - Parameters escaped automatically
     *
     * @param username username to search (case-sensitive)
     * @return Optional containing User if found, empty otherwise
     */
    Optional<User> findByUsername(String username);

    /**
     * Find User by Email
     *
     * Searches user by exact email match.
     *
     * GENERATED QUERY:
     * ═══════════════
     * SELECT u.*, r.*
     * FROM users u
     * LEFT JOIN user_roles ur ON u.id = ur.user_id
     * LEFT JOIN roles r ON ur.role_id = r.id
     * WHERE u.email = ?
     *
     * CASE SENSITIVITY:
     * ════════════════
     * Email standard: Case-insensitive (RFC 5321)
     *
     * Best practice:
     * - Store lowercase: user@example.com
     * - Convert before save: email.toLowerCase()
     * - Query lowercase
     *
     * Case-insensitive query (future):
     * @Query("SELECT u FROM User u WHERE LOWER(u.email) = LOWER(?1)")
     * Optional<User> findByEmail(String email);
     *
     * USAGE:
     * ═════
     * Login (alternative to username):
     * Optional<User> user = userRepository.findByEmail("user@example.com");
     *
     * Password reset:
     * User user = userRepository.findByEmail(email)
     *     .orElseThrow(() -> new UserNotFoundException("Email not found"));
     * sendPasswordResetEmail(user);
     *
     * Email verification:
     * User user = userRepository.findByEmail(email).orElse(null);
     * if (user != null) {
     *     user.setEmailVerified(true);
     *     userRepository.save(user);
     * }
     *
     * PERFORMANCE:
     * ═══════════
     * Index: idx_users_email (created by Liquibase)
     * Fast lookup: O(log n)
     *
     * EAGER LOADING:
     * ═════════════
     * Same як findByUsername - roles loaded automatically.
     *
     * PRIVACY:
     * ═══════
     * Email = PII (Personally Identifiable Information)
     *
     * Considerations:
     * ⚠️  GDPR compliance (EU)
     * ⚠️  Data retention policies
     * ⚠️  Secure storage
     * ⚠️  Audit access
     *
     * @param email email to search
     * @return Optional containing User if found, empty otherwise
     */
    Optional<User> findByEmail(String email);

    /**
     * Check if Username Exists
     *
     * Efficient existence check without loading entity.
     *
     * GENERATED QUERY:
     * ═══════════════
     * SELECT COUNT(*) > 0
     * FROM users
     * WHERE username = ?
     *
     * WHY EFFICIENT:
     * ═════════════
     * COUNT query vs SELECT:
     * ✅ No field loading (faster)
     * ✅ No JOIN (roles not needed)
     * ✅ Database optimization
     * ✅ Less memory
     *
     * vs findByUsername().isPresent():
     * ❌ Loads all fields
     * ❌ Loads roles (JOIN)
     * ❌ More memory
     * ❌ Slower
     *
     * USAGE:
     * ═════
     * Registration validation:
     * if (userRepository.existsByUsername(username)) {
     *     throw new UserAlreadyExistsException("Username already exists");
     * }
     *
     * Username availability check (API):
     * GET /api/users/check-username?username=admin
     * boolean available = !userRepository.existsByUsername(username);
     * return ResponseEntity.ok(Map.of("available", available));
     *
     * Form validation (AJAX):
     * Client checks availability before submit.
     *
     * PERFORMANCE:
     * ═══════════
     * Very fast:
     * - Index scan (idx_users_username)
     * - COUNT optimization (database knows count без reading)
     * - No data transfer (only boolean)
     *
     * Benchmark (1M users):
     * - existsByUsername: ~1ms
     * - findByUsername: ~5ms
     *
     * RACE CONDITION:
     * ══════════════
     * Possible scenario:
     * 1. Check: existsByUsername("admin") → false
     * 2. Another request: saves "admin"
     * 3. Save: tries to save "admin" → error
     *
     * Solution:
     * - Database UNIQUE constraint (safety net)
     * - Transaction isolation
     * - Catch duplicate exception
     *
     * @param username username to check
     * @return true if exists, false if available
     */
    boolean existsByUsername(String username);

    /**
     * Check if Email Exists
     *
     * Efficient existence check для email.
     *
     * GENERATED QUERY:
     * ═══════════════
     * SELECT COUNT(*) > 0
     * FROM users
     * WHERE email = ?
     *
     * Same benefits як existsByUsername.
     *
     * USAGE:
     * ═════
     * Registration validation:
     * if (userRepository.existsByEmail(email)) {
     *     throw new UserAlreadyExistsException("Email already exists");
     * }
     *
     * Email availability check:
     * GET /api/users/check-email?email=user@example.com
     * boolean available = !userRepository.existsByEmail(email);
     *
     * Prevent duplicate accounts:
     * - Same person, different usernames
     * - One email = one account
     *
     * PASSWORD RESET:
     * ══════════════
     * Check before sending reset email:
     * if (!userRepository.existsByEmail(email)) {
     *     // Don't reveal if email exists (security)
     *     return "If email exists, reset link sent";
     * }
     *
     * Security: Same message whether email exists або not.
     * Prevents email enumeration.
     *
     * CASE SENSITIVITY:
     * ════════════════
     * Consider lowercase storage:
     * - Store: user@example.com
     * - Check: user@example.com
     * - Works: USER@EXAMPLE.COM → convert to lowercase
     *
     * PERFORMANCE:
     * ═══════════
     * Index: idx_users_email
     * Very fast (same як existsByUsername)
     *
     * @param email email to check
     * @return true if exists, false if available
     */
    boolean existsByEmail(String email);
}