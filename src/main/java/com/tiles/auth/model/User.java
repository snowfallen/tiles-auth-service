package com.tiles.auth.model;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * User Entity
 *
 * Represents authenticated user в системі.
 *
 * DATABASE TABLE:
 * ══════════════
 * Table: users
 * Primary Key: id (UUID)
 * Unique Keys: username, email
 *
 * FIELDS:
 * ══════
 * - id: Unique identifier (UUID, auto-generated)
 * - username: Unique username для login
 * - email: Unique email address
 * - passwordHash: BCrypt hashed password
 * - enabled: Account enabled flag
 * - accountNonExpired: Account expiry flag
 * - accountNonLocked: Account lock flag
 * - credentialsNonExpired: Password expiry flag
 * - createdAt: Creation timestamp (automatic)
 * - updatedAt: Last update timestamp (automatic)
 * - roles: Many-to-many relationship з Role
 *
 * UUID PRIMARY KEY:
 * ════════════════
 * Why UUID (not SERIAL/BIGSERIAL):
 * ✅ Globally unique (no collisions between services)
 * ✅ Non-sequential (security - cannot guess IDs)
 * ✅ Distributed-friendly (no central ID generator)
 * ✅ Merge-friendly (no ID conflicts)
 *
 * Trade-offs:
 * ⚠️  Larger size (16 bytes vs 4/8 bytes)
 * ⚠️  Index performance (random, not sequential)
 * ⚠️  String representation (36 chars)
 *
 * For auth service, benefits outweigh costs.
 *
 * ACCOUNT STATUS FLAGS:
 * ════════════════════
 * Four boolean flags control account access:
 *
 * enabled:
 * - true: Account active (can login)
 * - false: Account disabled (cannot login)
 * - Use: Account suspension, deletion
 *
 * accountNonExpired:
 * - true: Account valid (not expired)
 * - false: Account expired (trial ended, subscription expired)
 * - Use: Temporary accounts, trial periods
 *
 * accountNonLocked:
 * - true: Account accessible (not locked)
 * - false: Account locked (too many failed logins)
 * - Use: Brute-force protection, suspicious activity
 *
 * credentialsNonExpired:
 * - true: Password valid (not expired)
 * - false: Password expired (must change)
 * - Use: Password rotation policies (90 days, тощо)
 *
 * All flags implemented by Spring Security UserDetails.
 *
 * ROLES RELATIONSHIP:
 * ══════════════════
 * Many-to-Many relationship з Role entity.
 *
 * Junction table: user_roles
 * Columns: user_id (FK), role_id (FK)
 *
 * Why Many-to-Many:
 * - User can have multiple roles (USER + ADMIN)
 * - Role can belong to multiple users
 * - Flexible permission system
 *
 * FetchType.EAGER:
 * - Roles loaded immediately з user
 * - Single query з JOIN
 * - No lazy loading issues
 *
 * TIMESTAMPS:
 * ══════════
 * Hibernate annotations для automatic timestamps:
 *
 * @CreationTimestamp:
 * - Set on INSERT (entity first saved)
 * - Never updated
 * - Column: updatable = false
 *
 * @UpdateTimestamp:
 * - Set on INSERT і UPDATE
 * - Automatically updated on entity changes
 * - Column: updatable = true (default)
 *
 * LOMBOK ANNOTATIONS:
 * ══════════════════
 * @Getter/@Setter: Generate getters/setters
 * @NoArgsConstructor: Default constructor (required by JPA)
 * @AllArgsConstructor: Constructor з all fields
 * @Builder: Builder pattern для clean construction
 *
 * Why Builder pattern:
 * ✅ Readable construction (named parameters)
 * ✅ Flexible (optional fields)
 * ✅ Immutable construction
 * ✅ Default values supported
 *
 * Example:
 * User user = User.builder()
 *     .username("admin")
 *     .email("admin@example.com")
 *     .passwordHash("...")
 *     .enabled(true)
 *     .build();
 *
 * @author snowfallen
 * @version 1.0.0
 * @since 2024-10-31
 */
@Entity
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {

    /**
     * Primary Key - UUID
     *
     * Unique identifier для user.
     *
     * GENERATION STRATEGY:
     * ═══════════════════
     * GenerationType.AUTO:
     * - JPA chooses appropriate strategy
     * - For UUID: generates random UUID (type 4)
     * - PostgreSQL: uses gen_random_uuid()
     *
     * UUID FORMAT:
     * ═══════════
     * Example: 550e8400-e29b-41d4-a716-446655440000
     * Format: 8-4-4-4-12 hexadecimal digits
     * Total: 36 characters (32 hex + 4 hyphens)
     *
     * DATABASE:
     * ════════
     * PostgreSQL type: UUID (native support)
     * Storage: 16 bytes (efficient)
     * Index: B-tree (good performance)
     */
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    /**
     * Username
     *
     * Unique login name для user.
     *
     * CONSTRAINTS:
     * ═══════════
     * - unique: true (database UNIQUE constraint)
     * - nullable: false (required field)
     * - length: 255 (reasonable maximum)
     *
     * VALIDATION:
     * ══════════
     * DTO level (@Valid RegisterRequest):
     * - @NotBlank: Cannot be empty
     * - @Size(min=3, max=50): Length validation
     *
     * DATABASE:
     * ════════
     * Column: username VARCHAR(255) UNIQUE NOT NULL
     * Index: idx_users_username (for fast lookup)
     */
    @Column(unique = true, nullable = false, length = 255)
    private String username;

    /**
     * Email
     *
     * Unique email address для user.
     *
     * CONSTRAINTS:
     * ═══════════
     * - unique: true (one email per account)
     * - nullable: false (required field)
     * - length: 255 (RFC 5321 maximum: 254)
     *
     * VALIDATION:
     * ══════════
     * DTO level:
     * - @NotBlank: Cannot be empty
     * - @Email: Valid email format
     *
     * USE CASES:
     * ═════════
     * - Password reset
     * - Email verification
     * - Notifications
     * - Alternative login (instead of username)
     *
     * DATABASE:
     * ════════
     * Column: email VARCHAR(255) UNIQUE NOT NULL
     * Index: idx_users_email (for fast lookup)
     */
    @Column(unique = true, nullable = false, length = 255)
    private String email;

    /**
     * Password Hash
     *
     * BCrypt hashed password.
     * NEVER stores plain password.
     *
     * BCRYPT HASH FORMAT:
     * ══════════════════
     * Format: $2a$[rounds]$[salt][hash]
     * Example: $2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy
     *
     * Components:
     * - $2a: BCrypt version identifier
     * - $10: Cost factor (2^10 = 1024 rounds)
     * - Next 22 chars: Salt (base64 encoded)
     * - Last 31 chars: Hash (base64 encoded)
     *
     * Total length: 60 characters
     * Database length: 255 (future-proof, higher rounds)
     *
     * SECURITY:
     * ════════
     * ✅ One-way function (cannot decode)
     * ✅ Unique salt per password
     * ✅ Slow by design (brute-force resistant)
     * ✅ Adaptive (can increase rounds)
     *
     * VERIFICATION:
     * ════════════
     * passwordEncoder.matches(rawPassword, passwordHash)
     * - Extracts salt від hash
     * - Hashes raw password з same salt
     * - Compares hashes
     * - Returns boolean
     *
     * DATABASE:
     * ════════
     * Column: password_hash VARCHAR(255) NOT NULL
     */
    @Column(name = "password_hash", nullable = false, length = 255)
    private String passwordHash;

    /**
     * Enabled Flag
     *
     * Controls if account active.
     *
     * VALUES:
     * ══════
     * true: Account enabled (can login)
     * false: Account disabled (cannot login)
     *
     * USE CASES:
     * ═════════
     * - Account suspension (policy violation)
     * - Account deletion (soft delete)
     * - Account deactivation (user request)
     * - Account pending (email verification)
     *
     * SPRING SECURITY:
     * ═══════════════
     * UserDetails.isEnabled() returns this value.
     * If false, authentication fails.
     *
     * DEFAULT:
     * ═══════
     * @Builder.Default sets default value.
     * New accounts: enabled = true (active)
     *
     * DATABASE:
     * ════════
     * Column: enabled BOOLEAN NOT NULL DEFAULT true
     * Index: idx_users_enabled (for filtering active users)
     */
    @Column(nullable = false)
    @Builder.Default
    private Boolean enabled = true;

    /**
     * Account Non-Expired Flag
     *
     * Controls if account expired.
     *
     * VALUES:
     * ══════
     * true: Account valid (not expired)
     * false: Account expired
     *
     * USE CASES:
     * ═════════
     * - Trial accounts (30-day trial)
     * - Subscription expiry (annual subscription)
     * - Temporary accounts (guest access)
     * - Time-limited access (project-based)
     *
     * SPRING SECURITY:
     * ═══════════════
     * UserDetails.isAccountNonExpired() returns this value.
     *
     * DEFAULT:
     * ═══════
     * true (account never expires by default)
     *
     * DATABASE:
     * ════════
     * Column: account_non_expired BOOLEAN NOT NULL DEFAULT true
     */
    @Column(name = "account_non_expired", nullable = false)
    @Builder.Default
    private Boolean accountNonExpired = true;

    /**
     * Account Non-Locked Flag
     *
     * Controls if account locked.
     *
     * VALUES:
     * ══════
     * true: Account accessible (not locked)
     * false: Account locked
     *
     * USE CASES:
     * ═════════
     * - Brute-force protection (too many failed logins)
     * - Suspicious activity (unusual login pattern)
     * - Security investigation (freeze account)
     * - Admin lock (pending review)
     *
     * UNLOCK:
     * ══════
     * - Automatic (after time period)
     * - Manual (admin action)
     * - Self-service (email verification)
     *
     * SPRING SECURITY:
     * ═══════════════
     * UserDetails.isAccountNonLocked() returns this value.
     *
     * DEFAULT:
     * ═══════
     * true (account not locked by default)
     *
     * DATABASE:
     * ════════
     * Column: account_non_locked BOOLEAN NOT NULL DEFAULT true
     */
    @Column(name = "account_non_locked", nullable = false)
    @Builder.Default
    private Boolean accountNonLocked = true;

    /**
     * Credentials Non-Expired Flag
     *
     * Controls if password expired.
     *
     * VALUES:
     * ══════
     * true: Password valid (not expired)
     * false: Password expired (must change)
     *
     * USE CASES:
     * ═════════
     * - Password rotation policies (change every 90 days)
     * - Security compliance (force password change)
     * - Breach response (force reset)
     * - Initial password (must change on first login)
     *
     * PASSWORD CHANGE FLOW:
     * ════════════════════
     * 1. Login succeeds
     * 2. Check credentialsNonExpired
     * 3. If false, redirect to password change
     * 4. User changes password
     * 5. Set credentialsNonExpired = true
     * 6. Continue to application
     *
     * SPRING SECURITY:
     * ═══════════════
     * UserDetails.isCredentialsNonExpired() returns this value.
     *
     * DEFAULT:
     * ═══════
     * true (password doesn't expire by default)
     *
     * DATABASE:
     * ════════
     * Column: credentials_non_expired BOOLEAN NOT NULL DEFAULT true
     */
    @Column(name = "credentials_non_expired", nullable = false)
    @Builder.Default
    private Boolean credentialsNonExpired = true;

    /**
     * Creation Timestamp
     *
     * When user account created.
     *
     * AUTOMATIC:
     * ═════════
     * @CreationTimestamp: Hibernate sets on INSERT
     * No manual intervention required
     *
     * TYPE:
     * ════
     * LocalDateTime (Java 8+ date/time API)
     * Example: 2024-10-31T12:30:00
     *
     * IMMUTABLE:
     * ═════════
     * updatable = false: Never updated after creation
     * Value set once, never changes
     *
     * USE CASES:
     * ═════════
     * - Audit trail (when account created)
     * - User analytics (account age)
     * - Compliance (data retention)
     * - Sorting (newest users first)
     *
     * DATABASE:
     * ════════
     * Column: created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
     */
    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    /**
     * Update Timestamp
     *
     * When user account last updated.
     *
     * AUTOMATIC:
     * ═════════
     * @UpdateTimestamp: Hibernate updates on:
     * - INSERT (initial value)
     * - UPDATE (every change)
     *
     * TYPE:
     * ════
     * LocalDateTime (Java 8+ date/time API)
     *
     * USE CASES:
     * ═════════
     * - Audit trail (last modification)
     * - Sync detection (changed since last sync?)
     * - Cache invalidation (data stale?)
     * - Activity tracking (recent activity)
     *
     * DATABASE:
     * ════════
     * Column: updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
     */
    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    /**
     * Roles Relationship
     *
     * Many-to-Many relationship з Role entity.
     *
     * MAPPING:
     * ═══════
     * @ManyToMany: Bidirectional many-to-many
     * @JoinTable: Junction table configuration
     *
     * Junction table: user_roles
     * - user_id: FK to users.id
     * - role_id: FK to roles.id
     * - PK: (user_id, role_id) composite
     *
     * FETCH TYPE:
     * ══════════
     * FetchType.EAGER: Roles loaded immediately
     *
     * Single query з LEFT JOIN:
     * SELECT u.*, r.*
     * FROM users u
     * LEFT JOIN user_roles ur ON u.id = ur.user_id
     * LEFT JOIN roles r ON ur.role_id = r.id
     * WHERE u.id = ?
     *
     * Why EAGER:
     * ✅ Always need roles (authentication)
     * ✅ Avoid N+1 queries
     * ✅ Simple code (no lazy loading issues)
     *
     * DATA STRUCTURE:
     * ══════════════
     * Set<Role> (not List):
     * ✅ No duplicates (same role cannot be added twice)
     * ✅ Unordered (role order doesn't matter)
     * ✅ Efficient contains() check
     *
     * HashSet initialization:
     * @Builder.Default ensures new HashSet() created
     * Prevents NullPointerException
     *
     * OPERATIONS:
     * ══════════
     * See helper methods:
     * - addRole(role): Add role
     * - removeRole(role): Remove role
     * - hasRole(name): Check if user has role
     */
    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    @Builder.Default
    private Set<Role> roles = new HashSet<>();

    /**
     * Add Role
     *
     * Helper method для adding role до user.
     *
     * USAGE:
     * ═════
     * user.addRole(userRole);
     *
     * vs manual:
     * user.getRoles().add(userRole);
     *
     * Benefits:
     * ✅ Cleaner API
     * ✅ Encapsulation (hides Set implementation)
     * ✅ Future-proof (can add validation)
     *
     * @param role Role entity to add
     */
    public void addRole(Role role) {
        this.roles.add(role);
    }

    /**
     * Remove Role
     *
     * Helper method для removing role від user.
     *
     * @param role Role entity to remove
     */
    public void removeRole(Role role) {
        this.roles.remove(role);
    }

    /**
     * Check if User Has Role
     *
     * Convenience method для role checking.
     *
     * USAGE:
     * ═════
     * if (user.hasRole("ADMIN")) {
     *     // Admin operations
     * }
     *
     * vs manual:
     * user.getRoles().stream()
     *     .anyMatch(r -> r.getName().equals("ADMIN"))
     *
     * Benefits:
     * ✅ Readable code
     * ✅ Reusable logic
     * ✅ Less boilerplate
     *
     * @param roleName role name to check (e.g., "USER", "ADMIN")
     * @return true if user has this role
     */
    public boolean hasRole(String roleName) {
        return roles.stream()
                .anyMatch(role -> role.getName().equals(roleName));
    }
}
