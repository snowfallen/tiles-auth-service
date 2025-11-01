package com.tiles.auth.repository;

import com.tiles.auth.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Role Repository
 *
 * Spring Data JPA repository для Role entity.
 *
 * ROLE MANAGEMENT:
 * ═══════════════
 * Roles = almost static data.
 * Predefined: USER, ADMIN
 *
 * Repository usage:
 * - Lookup during registration (assign USER role)
 * - Role queries (admin operations)
 * - Rarely modified (almost read-only)
 *
 * CRUD OPERATIONS:
 * ═══════════════
 * Inherited від JpaRepository:
 * - save(role): Create або update role
 * - findById(id): Find by primary key
 * - findAll(): Get all roles
 * - delete(role): Delete role (⚠️  rarely used)
 * - count(): Count roles (should be ~2)
 *
 * CUSTOM QUERY:
 * ════════════
 * findByName(String name):
 * - Most common operation
 * - Lookup by role name ("USER", "ADMIN")
 * - Used during registration, authorization
 *
 * PRIMARY KEY:
 * ═══════════
 * JpaRepository<Role, Long>:
 * - Entity type: Role
 * - Primary key type: Long (BIGSERIAL)
 *
 * vs User:
 * JpaRepository<User, UUID>
 * - Entity type: User
 * - Primary key type: UUID
 *
 * SMALL TABLE:
 * ═══════════
 * Roles table very small:
 * - Current: 2 rows (USER, ADMIN)
 * - Future: Maybe 5-10 rows (MODERATOR, EDITOR, тощо)
 *
 * Performance considerations:
 * ✅ All queries very fast (small data)
 * ✅ Can cache entire table (rarely changes)
 * ✅ No pagination needed
 *
 * CACHING (future):
 * ════════════════
 * Consider caching roles:
 * @Cacheable("roles")
 * Optional<Role> findByName(String name);
 *
 * Benefits:
 * ✅ No database query (cache hit)
 * ✅ Faster lookup
 * ✅ Reduced DB load
 *
 * Trade-off:
 * ⚠️  Cache invalidation (if roles change)
 * ⚠️  Memory usage (minimal для 2-10 rows)
 *
 * @author snowfallen
 * @version 1.0.0
 * @since 2024-10-31
 */
@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {

    /**
     * Find Role by Name
     *
     * Searches role by exact name match.
     *
     * GENERATED QUERY:
     * ═══════════════
     * SELECT * FROM roles WHERE name = ?
     *
     * USAGE:
     * ═════
     * Registration (assign default USER role):
     * Role userRole = roleRepository.findByName(Role.USER)
     *     .orElseThrow(() -> new RuntimeException("USER role not found"));
     * user.addRole(userRole);
     *
     * Admin assignment (add ADMIN role):
     * Role adminRole = roleRepository.findByName(Role.ADMIN)
     *     .orElseThrow(() -> new RuntimeException("ADMIN role not found"));
     * user.addRole(adminRole);
     *
     * Authorization check (future):
     * boolean hasRole = user.getRoles().stream()
     *     .anyMatch(r -> r.getName().equals(Role.ADMIN));
     *
     * ROLE CONSTANTS:
     * ══════════════
     * Use Role.USER і Role.ADMIN constants:
     * ✅ Type-safe
     * ✅ Refactoring-friendly
     * ✅ No typos
     *
     * vs magic strings:
     * ❌ roleRepository.findByName("USER")  // Typo risk
     * ✅ roleRepository.findByName(Role.USER)  // Safe
     *
     * CASE SENSITIVITY:
     * ════════════════
     * PostgreSQL: Case-sensitive
     * "USER" ≠ "user" ≠ "User"
     *
     * Database: Always uppercase ("USER", "ADMIN")
     * Code: Use constants (Role.USER, Role.ADMIN)
     *
     * PERFORMANCE:
     * ═══════════
     * Index: idx_roles_name (created by Liquibase)
     * Very fast: O(log n), але n=2, so instant
     *
     * Optimization (future):
     * Load all roles once, cache в memory:
     *
     * @PostConstruct
     * void loadRoles() {
     *     rolesCache = roleRepository.findAll().stream()
     *         .collect(Collectors.toMap(Role::getName, r -> r));
     * }
     *
     * Role getRole(String name) {
     *     return rolesCache.get(name);
     * }
     *
     * DATA INTEGRITY:
     * ══════════════
     * Roles should exist (inserted by Liquibase).
     *
     * If not found:
     * - RuntimeException thrown
     * - Application cannot function
     * - Fix: Run Liquibase migrations
     *
     * Verification (startup check):
     * @PostConstruct
     * void verifyRoles() {
     *     if (!roleRepository.existsByName(Role.USER)) {
     *         throw new IllegalStateException("USER role not found!");
     *     }
     *     if (!roleRepository.existsByName(Role.ADMIN)) {
     *         throw new IllegalStateException("ADMIN role not found!");
     *     }
     * }
     *
     * MODIFICATION:
     * ════════════
     * Roles rarely modified:
     * - Create: Liquibase migration (new role)
     * - Update: Rename (very rare, breaking change)
     * - Delete: Never (users reference roles)
     *
     * If need to add role:
     * 1. Create Liquibase migration
     * 2. Add constant: public static final String MODERATOR = "MODERATOR";
     * 3. Deploy
     * 4. Migration runs automatically
     *
     * @param name role name to search ("USER", "ADMIN")
     * @return Optional containing Role if found, empty otherwise
     */
    Optional<Role> findByName(String name);
}
