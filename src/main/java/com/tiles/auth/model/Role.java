package com.tiles.auth.model;

import jakarta.persistence.*;
import lombok.*;

/**
 * Role Entity
 *
 * Represents user role/permission в системі.
 *
 * DATABASE TABLE:
 * ══════════════
 * Table: roles
 * Primary Key: id (BIGSERIAL)
 * Unique Key: name
 *
 * ROLE-BASED ACCESS CONTROL (RBAC):
 * ═════════════════════════════════
 * Roles = groups of permissions.
 * Users assigned roles → inherit permissions.
 *
 * Example hierarchy:
 * - USER: Basic permissions (read own data)
 * - ADMIN: Full permissions (manage users, system)
 * - MODERATOR: Medium permissions (manage content)
 *
 * PREDEFINED ROLES:
 * ════════════════
 * Roles are ALMOST STATIC - predefined values.
 * Similar to enum, але stored в database.
 *
 * Current roles:
 * - USER: Default role для all users
 * - ADMIN: Administrative access
 *
 * Why database (not Java enum):
 * ✅ Can add roles without code changes
 * ✅ Can query roles (which users have role X?)
 * ✅ Foreign key relationships
 * ✅ Audit trail (role changes)
 *
 * Trade-off:
 * ⚠️  Extra table і joins
 * ⚠️  Slightly slower than enum
 *
 * LIQUIBASE MIGRATION:
 * ═══════════════════
 * Roles inserted by Liquibase:
 * - 004-insert-default-roles.yaml
 *
 * Ensures roles exist before application starts.
 *
 * MANY-TO-MANY:
 * ════════════
 * Relationship з User entity:
 * - User can have multiple roles
 * - Role belongs to multiple users
 * - Junction table: user_roles
 *
 * EQUALS/HASHCODE:
 * ═══════════════
 * @EqualsAndHashCode(of = "name"):
 * - Equals based on name field only
 * - Two roles equal if same name
 * - Ignores id (can be different в tests)
 *
 * Important для Set operations:
 * - user.roles is Set<Role>
 * - Set uses equals() для uniqueness
 * - Prevents duplicate roles
 *
 * CONSTANTS:
 * ═════════
 * Static constants для role names:
 * - Role.USER = "USER"
 * - Role.ADMIN = "ADMIN"
 *
 * Usage:
 * roleRepository.findByName(Role.USER)
 *
 * vs magic strings:
 * roleRepository.findByName("USER")
 *
 * Benefits:
 * ✅ Type safety (compile-time check)
 * ✅ Refactoring-friendly
 * ✅ Autocomplete
 * ✅ Less typos
 *
 * @author snowfallen
 * @version 1.0.0
 * @since 2024-10-31
 */
@Entity
@Table(name = "roles")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@EqualsAndHashCode(of = "name")  // Equals by name only
public class Role {

    /**
     * Primary Key - BIGSERIAL
     *
     * Unique identifier для role.
     *
     * GENERATION STRATEGY:
     * ═══════════════════
     * GenerationType.IDENTITY:
     * - Database auto-increment
     * - PostgreSQL: BIGSERIAL type
     * - Values: 1, 2, 3, ...
     *
     * Why IDENTITY (not AUTO):
     * ✅ Simple і efficient
     * ✅ Database handles generation
     * ✅ Works well для small tables
     *
     * Why not UUID:
     * Roles are:
     * - Small table (few rows)
     * - Static data (rarely changes)
     * - Often referenced (foreign keys)
     *
     * BIGINT more efficient:
     * ✅ Smaller size (8 bytes vs 16)
     * ✅ Sequential (better index performance)
     * ✅ Readable IDs (1, 2 vs UUIDs)
     *
     * DATABASE:
     * ════════
     * PostgreSQL: id BIGSERIAL PRIMARY KEY
     * Automatically creates sequence: roles_id_seq
     */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * Role Name
     *
     * Unique name identifying this role.
     *
     * CONSTRAINTS:
     * ═══════════
     * - unique: true (each role name appears once)
     * - nullable: false (required field)
     * - length: 50 (reasonable maximum)
     *
     * NAMING CONVENTION:
     * ═════════════════
     * Format: UPPERCASE
     * Examples: USER, ADMIN, MODERATOR
     *
     * Why uppercase:
     * - Standard convention (Spring Security)
     * - Easy to distinguish (USER vs user)
     * - Consistency (all roles same format)
     *
     * SPRING SECURITY:
     * ═══════════════
     * Spring Security expects "ROLE_" prefix:
     * - Database: "USER"
     * - Spring Security: "ROLE_USER"
     *
     * Conversion done в CustomUserDetails:
     * getAuthorities() adds "ROLE_" prefix
     *
     * Why separate:
     * ✅ Database cleaner (no prefix clutter)
     * ✅ Flexibility (can change prefix)
     * ✅ Display-friendly ("User" not "ROLE_USER")
     *
     * VALUES:
     * ══════
     * See constants below (Role.USER, Role.ADMIN)
     *
     * DATABASE:
     * ════════
     * Column: name VARCHAR(50) UNIQUE NOT NULL
     * Index: idx_roles_name (for fast lookup)
     *
     * Values:
     * - USER (id=1)
     * - ADMIN (id=2)
     */
    @Column(unique = true, nullable = false, length = 50)
    private String name;

    /**
     * Predefined Role Names (Constants)
     *
     * Static constants для type-safe role references.
     *
     * USER ROLE:
     * ═════════
     * Default role для all registered users.
     *
     * Permissions (typical):
     * - Read own profile
     * - Update own profile
     * - Read public content
     * - Create own content
     *
     * Assigned automatically:
     * - During registration (UserServiceImpl)
     *
     * USAGE:
     * ═════
     * roleRepository.findByName(Role.USER)
     * user.hasRole(Role.USER)
     *
     * DATABASE:
     * ════════
     * Inserted by: 004-insert-default-roles.yaml
     * Value: "USER"
     * ID: Usually 1 (first inserted)
     */
    public static final String USER = "USER";

    /**
     * ADMIN ROLE:
     * ══════════
     * Administrative role з full permissions.
     *
     * Permissions (typical):
     * - All USER permissions
     * - Manage users (create, update, delete)
     * - Manage roles (assign, revoke)
     * - View system logs
     * - Change system settings
     * - Access admin panel
     *
     * Assigned manually:
     * - Database update (SQL)
     * - Admin panel (future feature)
     * - Never during registration (security)
     *
     * SECURITY:
     * ════════
     * ⚠️  Carefully control ADMIN assignment
     * ⚠️  Log all ADMIN actions (audit trail)
     * ⚠️  Require strong authentication (2FA)
     * ⚠️  Regular access review
     *
     * USAGE:
     * ═════
     * roleRepository.findByName(Role.ADMIN)
     * user.hasRole(Role.ADMIN)
     *
     * Authorization check:
     * @PreAuthorize("hasRole('ADMIN')")
     *
     * DATABASE:
     * ════════
     * Inserted by: 004-insert-default-roles.yaml
     * Value: "ADMIN"
     * ID: Usually 2 (second inserted)
     */
    public static final String ADMIN = "ADMIN";

    /**
     * FUTURE ROLES (examples):
     * ════════════════════════
     *
     * MODERATOR:
     * - Moderate content (approve, reject, delete)
     * - Ban users (temporary/permanent)
     * - View reports
     * - No system access
     *
     * EDITOR:
     * - Create content
     * - Edit any content
     * - Publish content
     * - No user management
     *
     * VIEWER:
     * - Read-only access
     * - Cannot create/edit
     * - Cannot delete
     * - Reports only
     *
     * To add new role:
     * 1. Add constant: public static final String MODERATOR = "MODERATOR";
     * 2. Create Liquibase migration: insert into roles (name) values ('MODERATOR');
     * 3. Define permissions (application logic)
     * 4. Assign to users (admin panel або SQL)
     */
}
