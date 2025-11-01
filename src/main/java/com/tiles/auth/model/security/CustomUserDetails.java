package com.tiles.auth.model.security;

import com.tiles.auth.model.User;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.stream.Collectors;

/**
 * Custom UserDetails Implementation
 *
 * Wraps User entity для Spring Security.
 *
 * WHY WRAPPER:
 * ═══════════
 * Spring Security uses UserDetails interface.
 * Our User entity doesn't implement it (separation of concerns).
 *
 * Solution: Wrapper pattern
 * - CustomUserDetails implements UserDetails
 * - Wraps User entity
 * - Delegates methods до User fields
 * - Adds custom methods
 *
 * SPRING SECURITY INTERFACE:
 * ═════════════════════════
 * UserDetails defines methods:
 * - getUsername(): User's login name
 * - getPassword(): User's password hash
 * - getAuthorities(): User's permissions (roles)
 * - isEnabled(): Account enabled?
 * - isAccountNonExpired(): Account valid?
 * - isAccountNonLocked(): Account accessible?
 * - isCredentialsNonExpired(): Password valid?
 *
 * AUTHENTICATION FLOW:
 * ═══════════════════
 * 1. UserService.loadUserByUsername() loads User
 * 2. Wraps User в CustomUserDetails
 * 3. Returns UserDetails до Spring Security
 * 4. AuthenticationProvider validates password
 * 5. Creates Authentication object з UserDetails
 * 6. Authentication stored в SecurityContext
 *
 * AUTHORIZATION:
 * ═════════════
 * getAuthorities() converts roles → GrantedAuthority.
 *
 * Spring Security uses authorities для:
 * - @PreAuthorize("hasRole('ADMIN')")
 * - @Secured("ROLE_ADMIN")
 * - HttpSecurity.authorizeRequests()
 *
 * ROLE PREFIX:
 * ═══════════
 * Spring Security expects "ROLE_" prefix.
 *
 * Database: "USER", "ADMIN"
 * Spring Security: "ROLE_USER", "ROLE_ADMIN"
 *
 * Conversion happens в getAuthorities():
 * "USER" → "ROLE_USER"
 *
 * Why prefix:
 * - Spring Security convention
 * - Distinguishes roles від other authorities
 * - Enables hasRole() method (auto-adds prefix)
 *
 * CUSTOM METHODS:
 * ══════════════
 * Beyond UserDetails interface, we add:
 * - getUserId(): Get user UUID
 * - getEmail(): Get user email
 * - getRoleNames(): Get roles without prefix
 *
 * Used by:
 * - Token generation (JWT claims)
 * - API responses (user info)
 * - Business logic
 *
 * IMMUTABILITY:
 * ════════════
 * @Getter (no @Setter):
 * - Read-only wrapper
 * - Cannot modify після creation
 * - Thread-safe
 *
 * Benefits:
 * ✅ Security (cannot tamper з user data)
 * ✅ Predictability (no side effects)
 * ✅ Thread-safe (concurrent access safe)
 *
 * @author snowfallen
 * @version 1.0.0
 * @since 2024-10-31
 */
@Getter
public class CustomUserDetails implements UserDetails {

    /**
     * Wrapped User Entity
     *
     * All UserDetails methods delegate до this User.
     *
     * ENCAPSULATION:
     * ═════════════
     * Private field - not exposed directly.
     * Access через interface methods only.
     *
     * Why private:
     * ✅ Encapsulation (hides implementation)
     * ✅ Flexibility (can change User structure)
     * ✅ Security (controlled access)
     *
     * FINAL:
     * ═════
     * final = cannot reassign після construction.
     * Immutable reference.
     *
     * Note: User object itself mutable,
     * але reference cannot change.
     */
    private final User user;

    /**
     * Constructor
     *
     * Creates CustomUserDetails wrapper від User entity.
     *
     * USAGE:
     * ═════
     * User user = userRepository.findByUsername("admin");
     * CustomUserDetails userDetails = new CustomUserDetails(user);
     *
     * Called by:
     * - UserServiceImpl.loadUserByUsername()
     * - AuthServiceImpl.login()
     * - AuthServiceImpl.register()
     *
     * VALIDATION:
     * ══════════
     * No null check - assume user not null.
     * Caller responsibility (fails fast if null).
     *
     * @param user User entity to wrap
     */
    public CustomUserDetails(User user) {
        this.user = user;
    }

    /**
     * Get Authorities (Roles)
     *
     * Converts User roles → Spring Security GrantedAuthority.
     *
     * SPRING SECURITY REQUIREMENT:
     * ═══════════════════════════
     * UserDetails must return Collection<GrantedAuthority>.
     * Represents user's permissions.
     *
     * ROLE CONVERSION:
     * ═══════════════
     * Process:
     * 1. Get user.roles (Set<Role>)
     * 2. Stream roles
     * 3. Extract role name (e.g., "USER")
     * 4. Add "ROLE_" prefix → "ROLE_USER"
     * 5. Create SimpleGrantedAuthority
     * 6. Collect до List
     *
     * Example:
     * Database roles: ["USER", "ADMIN"]
     * Authorities: ["ROLE_USER", "ROLE_ADMIN"]
     *
     * WHY PREFIX:
     * ══════════
     * Spring Security convention.
     *
     * Benefits:
     * - hasRole("USER") works (auto-adds prefix)
     * - hasAuthority("ROLE_USER") works
     * - Distinguishes roles від permissions
     *
     * Without prefix:
     * - Need hasAuthority("USER")
     * - Inconsistent з Spring Security docs
     * - Cannot use hasRole() shortcut
     *
     * GRANTEDAUTHORITY:
     * ════════════════
     * Interface representing permission.
     *
     * SimpleGrantedAuthority:
     * - Basic implementation
     * - Just holds string (role name)
     * - getAuthority() returns string
     *
     * Other implementations:
     * - Custom authorities (complex permissions)
     * - Hierarchical roles (role inheritance)
     *
     * USAGE BY SPRING SECURITY:
     * ════════════════════════
     * Authorization checks:
     *
     * @PreAuthorize("hasRole('ADMIN')"):
     * - Spring Security calls getAuthorities()
     * - Checks if "ROLE_ADMIN" в collection
     * - Allows/denies access
     *
     * @PreAuthorize("hasAnyRole('USER', 'ADMIN')"):
     * - Checks if "ROLE_USER" або "ROLE_ADMIN" present
     *
     * @Secured("ROLE_ADMIN"):
     * - Similar to @PreAuthorize
     * - Less flexible (no SpEL)
     *
     * @return Collection of GrantedAuthority (roles з ROLE_ prefix)
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return user.getRoles().stream()
                // Map Role entity → role name string
                // Example: Role{id=1, name="USER"} → "USER"
                .map(role -> role.getName())

                // Add ROLE_ prefix
                // Example: "USER" → "ROLE_USER"
                // SimpleGrantedAuthority wraps string
                .map(roleName -> new SimpleGrantedAuthority("ROLE_" + roleName))

                // Collect до List<GrantedAuthority>
                .collect(Collectors.toList());
    }

    /**
     * Get Password (Hash)
     *
     * Returns BCrypt password hash від User entity.
     *
     * SPRING SECURITY USAGE:
     * ═════════════════════
     * During authentication:
     * 1. Get UserDetails (this object)
     * 2. Get password hash (this method)
     * 3. Compare з submitted password:
     *    passwordEncoder.matches(rawPassword, userDetails.getPassword())
     * 4. If matches → authenticated
     *
     * NEVER PLAIN PASSWORD:
     * ════════════════════
     * This returns HASH, not plain password.
     *
     * Example hash:
     * $2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy
     *
     * Safe to expose (within authentication context):
     * ✅ One-way function (cannot decode)
     * ✅ Unique salt (cannot use rainbow tables)
     * ✅ Only compared, never displayed
     *
     * @return BCrypt password hash
     */
    @Override
    public String getPassword() {
        return user.getPasswordHash();
    }

    /**
     * Get Username
     *
     * Returns username від User entity.
     *
     * SPRING SECURITY USAGE:
     * ═════════════════════
     * - Display в logs: "User 'admin' logged in"
     * - Store в SecurityContext
     * - Audit trail
     * - Session identification
     *
     * NOT EMAIL:
     * ════════
     * Returns username, not email.
     * Even if user logged in з email.
     *
     * Why:
     * - Username = primary identifier
     * - Email can change
     * - Username stable
     *
     * @return username (login name)
     */
    @Override
    public String getUsername() {
        return user.getUsername();
    }

    /**
     * Check if Account Non-Expired
     *
     * Returns User.accountNonExpired flag.
     *
     * SPRING SECURITY CHECK:
     * ═════════════════════
     * During authentication:
     * - If false → AccountExpiredException
     * - User cannot login
     * - Message: "Account expired"
     *
     * USE CASES:
     * ═════════
     * - Trial accounts (30 days)
     * - Subscription expired
     * - Temporary access
     *
     * @return true if account valid, false if expired
     */
    @Override
    public boolean isAccountNonExpired() {
        return user.getAccountNonExpired();
    }

    /**
     * Check if Account Non-Locked
     *
     * Returns User.accountNonLocked flag.
     *
     * SPRING SECURITY CHECK:
     * ═════════════════════
     * During authentication:
     * - If false → LockedException
     * - User cannot login
     * - Message: "Account locked"
     *
     * USE CASES:
     * ═════════
     * - Brute-force protection
     * - Suspicious activity
     * - Admin lock
     *
     * @return true if account accessible, false if locked
     */
    @Override
    public boolean isAccountNonLocked() {
        return user.getAccountNonLocked();
    }

    /**
     * Check if Credentials Non-Expired
     *
     * Returns User.credentialsNonExpired flag.
     *
     * SPRING SECURITY CHECK:
     * ═════════════════════
     * During authentication:
     * - If false → CredentialsExpiredException
     * - User must change password
     * - Redirect to password change page
     *
     * USE CASES:
     * ═════════
     * - Password rotation policy (90 days)
     * - Force password change
     * - Security breach response
     *
     * @return true if password valid, false if expired
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return user.getCredentialsNonExpired();
    }

    /**
     * Check if Enabled
     *
     * Returns User.enabled flag.
     *
     * SPRING SECURITY CHECK:
     * ═════════════════════
     * During authentication:
     * - If false → DisabledException
     * - User cannot login
     * - Message: "Account disabled"
     *
     * USE CASES:
     * ═════════
     * - Account suspension
     * - Account deletion (soft)
     * - Email verification pending
     *
     * @return true if account enabled, false if disabled
     */
    @Override
    public boolean isEnabled() {
        return user.getEnabled();
    }

    /**
     * Get User ID (Custom Method)
     *
     * Returns User's UUID як string.
     *
     * NOT PART OF USERDETAILS:
     * ════════════════════════
     * Custom method - beyond Spring Security interface.
     *
     * USAGE:
     * ═════
     * - JWT claims (sub: userId)
     * - Refresh token generation
     * - API responses
     * - Business logic
     *
     * WHY STRING (not UUID):
     * ═════════════════════
     * Convenience - often need string representation.
     *
     * UUID.toString() format:
     * "550e8400-e29b-41d4-a716-446655440000"
     *
     * @return user ID (UUID string)
     */
    public String getUserId() {
        return user.getId().toString();
    }

    /**
     * Get Email (Custom Method)
     *
     * Returns User's email address.
     *
     * NOT PART OF USERDETAILS:
     * ════════════════════════
     * Custom method - convenience accessor.
     *
     * USAGE:
     * ═════
     * - JWT claims (email: user@example.com)
     * - Refresh token generation
     * - API responses (user info)
     * - Email notifications
     *
     * @return email address
     */
    public String getEmail() {
        return user.getEmail();
    }

    /**
     * Get Role Names (Custom Method)
     *
     * Returns array of role names WITHOUT "ROLE_" prefix.
     *
     * NOT PART OF USERDETAILS:
     * ════════════════════════
     * Custom method для clean role names.
     *
     * DIFFERENCE від getAuthorities():
     * ═══════════════════════════════
     * getAuthorities(): ["ROLE_USER", "ROLE_ADMIN"]
     * getRoleNames(): ["USER", "ADMIN"]
     *
     * WHY SEPARATE METHOD:
     * ═══════════════════
     * Different use cases:
     *
     * getAuthorities():
     * - Spring Security authorization
     * - Needs ROLE_ prefix
     * - Returns GrantedAuthority objects
     *
     * getRoleNames():
     * - JWT claims (compact format)
     * - API responses (display names)
     * - Business logic (simple strings)
     * - Returns plain strings
     *
     * USAGE:
     * ═════
     * JWT payload:
     * {
     *   "roles": ["USER", "ADMIN"]  ← This method
     * }
     *
     * vs
     * {
     *   "roles": ["ROLE_USER", "ROLE_ADMIN"]  ← Less clean
     * }
     *
     * ARRAY vs COLLECTION:
     * ═══════════════════
     * Returns String[] (not List):
     * - Simpler в JSON (no collection wrapper)
     * - Common format для JWT claims
     * - Efficient (fixed size)
     *
     * @return array of role names (no ROLE_ prefix)
     */
    public String[] getRoleNames() {
        return user.getRoles().stream()
                // Extract role name only (no prefix)
                .map(role -> role.getName())

                // Convert Stream → Array
                // new String[0] = array type hint
                .toArray(String[]::new);
    }
}
