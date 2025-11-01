package com.tiles.auth.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;

/**
 * User Response DTO
 *
 * User profile data для API responses.
 *
 * USAGE:
 * ═════
 * Included в:
 * - LoginResponse (login, register)
 * - GET /api/users/me (get own profile)
 * - GET /api/users/{id} (get user profile)
 * - User listings (admin panel)
 *
 * FIELDS:
 * ══════
 * Public user information:
 * - id: User UUID (identifier)
 * - username: Login name (display)
 * - email: Email address (contact)
 * - roles: Role names (authorization)
 * - enabled: Account status (active/disabled)
 *
 * NOT included:
 * ❌ passwordHash (security)
 * ❌ accountNonExpired (internal)
 * ❌ accountNonLocked (internal)
 * ❌ credentialsNonExpired (internal)
 * ❌ createdAt (not needed від client)
 * ❌ updatedAt (not needed від client)
 *
 * WHY SEPARATE DTO:
 * ════════════════
 * Don't expose User entity directly:
 *
 * Entity (internal):
 * - All fields (passwordHash, timestamps)
 * - JPA annotations
 * - Relationships (roles entity)
 * - Database structure
 *
 * DTO (external):
 * - Only safe fields
 * - No annotations (clean POJO)
 * - Simple types (Set<String> not Set<Role>)
 * - API contract
 *
 * Benefits:
 * ✅ Security (no sensitive data leak)
 * ✅ Flexibility (change entity без breaking API)
 * ✅ Clean API (only relevant fields)
 * ✅ Versioning (can have v1/v2 DTOs)
 *
 * MAPPING:
 * ═══════
 * UserMapper converts Entity → DTO:
 *
 * User entity → UserResponse DTO
 * - UUID id → String id
 * - Set<Role> roles → Set<String> roleNames
 * - Filter sensitive fields
 *
 * PRIVACY:
 * ═══════
 * Consider privacy levels:
 *
 * Own profile (full access):
 * - id, username, email, roles, enabled
 *
 * Other user's profile (limited):
 * - id, username
 * - Maybe: email (if public)
 * - Not: roles, enabled (privacy)
 *
 * Future: Separate DTOs:
 * - UserProfileResponse (own profile)
 * - PublicUserResponse (other users)
 *
 * LOMBOK ANNOTATIONS:
 * ══════════════════
 * @Data: Generates standard methods
 * @Builder: Builder pattern
 * @NoArgsConstructor: Default constructor
 * @AllArgsConstructor: Full constructor
 *
 * @author snowfallen
 * @version 1.0.0
 * @since 2024-10-31
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserResponse {

    /**
     * User ID (UUID)
     *
     * Unique identifier для user.
     *
     * FORMAT:
     * ══════
     * UUID string representation
     * Example: "550e8400-e29b-41d4-a716-446655440000"
     *
     * WHY STRING (not UUID type):
     * ══════════════════════════
     * DTO simplicity:
     * ✅ JSON serialization automatic
     * ✅ No custom serializer needed
     * ✅ Portable (any language)
     *
     * UUID type would require:
     * - Custom Jackson serializer
     * - Client UUID parsing
     * - More complexity
     *
     * USAGE:
     * ═════
     * Client identification:
     * - Store user ID
     * - API requests: GET /api/users/{id}
     * - Authorization checks
     * - Audit logs
     *
     * NOT for:
     * ❌ Display to user (show username instead)
     * ❌ URL slugs (use username)
     * ❌ Search (not memorable)
     *
     * PRIVACY:
     * ═══════
     * UUID = safe to expose:
     * ✅ Non-sequential (cannot guess)
     * ✅ Random (no pattern)
     * ✅ Unique (no collisions)
     *
     * vs SERIAL ID:
     * ❌ Sequential (can enumerate users)
     * ❌ Predictable (security risk)
     * ❌ Leaks info (user count, growth rate)
     */
    private String id;

    /**
     * Username
     *
     * User's login name.
     *
     * DISPLAY:
     * ═══════
     * Primary display name:
     * - Welcome message: "Welcome, {username}!"
     * - Profile page: "@{username}"
     * - Comments: "Posted by {username}"
     * - Mentions: "@{username}"
     *
     * UNIQUENESS:
     * ══════════
     * Globally unique (database constraint).
     * No two users can have same username.
     *
     * Case sensitivity:
     * - Database: Case-sensitive (PostgreSQL)
     * - "Admin" ≠ "admin"
     * - Display: Preserve original case
     *
     * FORMAT:
     * ══════
     * Validated at registration:
     * - Length: 3-50 characters
     * - Pattern: Letters, numbers, underscore, hyphen
     * - No validation в DTO (already validated)
     *
     * USAGE:
     * ═════
     * Client display:
     * - User profile header
     * - Navigation bar
     * - Comment authors
     * - Search results
     *
     * API requests:
     * - GET /api/users/{username}
     * - Mention search
     *
     * PRIVACY:
     * ═══════
     * Public information:
     * ✅ Safe to display
     * ✅ Can be indexed (search engines)
     * ✅ No sensitive data
     */
    private String username;

    /**
     * Email
     *
     * User's email address.
     *
     * DISPLAY:
     * ═══════
     * Own profile only:
     * - Account settings
     * - Profile page (own)
     * - Contact information
     *
     * PRIVACY:
     * ═══════
     * Potentially sensitive:
     * ⚠️  Consider privacy settings
     * ⚠️  May want to hide від other users
     *
     * Current: Always included в UserResponse
     * Future: Privacy levels:
     * - Public (show to all)
     * - Connections (show to friends)
     * - Private (own profile only)
     *
     * USAGE:
     * ═════
     * Client display:
     * - Own profile: "Email: user@example.com"
     * - Account settings: Editable field
     * - Other profiles: Maybe hide або show based on privacy
     *
     * NOT for:
     * ❌ Public display (without consent)
     * ❌ Email harvesting (spam risk)
     *
     * VALIDATION:
     * ══════════
     * Validated at registration:
     * - Email format (@Email annotation)
     * - Uniqueness (database)
     * - No validation в DTO
     *
     * FUTURE:
     * ══════
     * Email verification:
     * - Add `emailVerified` boolean field
     * - Show verification status
     * - Allow re-send verification
     */
    private String email;

    /**
     * Roles
     *
     * User's role names (без ROLE_ prefix).
     *
     * FORMAT:
     * ══════
     * Set<String> containing role names:
     * - ["USER"]
     * - ["USER", "ADMIN"]
     * - ["USER", "MODERATOR"]
     *
     * WHY SET (not List):
     * ══════════════════
     * ✅ No duplicates (role appears once)
     * ✅ Unordered (role order doesn't matter)
     * ✅ Efficient contains() check
     *
     * JSON serialization:
     * Set → JSON array (order random)
     *
     * ROLE NAMES:
     * ══════════
     * Database: "USER", "ADMIN"
     * DTO: Same (no prefix)
     * Spring Security: "ROLE_USER", "ROLE_ADMIN" (з prefix)
     *
     * Why no prefix в DTO:
     * ✅ Cleaner API
     * ✅ Display-friendly
     * ✅ Compact
     *
     * Prefix added только в CustomUserDetails.getAuthorities()
     * для Spring Security.
     *
     * USAGE:
     * ═════
     * Client authorization:
     *
     * if (user.roles.includes("ADMIN")) {
     *     showAdminPanel();
     * }
     *
     * if (user.roles.includes("MODERATOR")) {
     *     showModeratorTools();
     * }
     *
     * Display:
     * - Show badges: "Admin", "Moderator"
     * - Role indicator на profile
     * - Permission hints
     *
     * SECURITY:
     * ════════
     * Roles = authorization data:
     * ⚠️  Don't trust client-side checks
     * ⚠️  Always validate на server (Gateway)
     * ⚠️  JWT also contains roles (source of truth)
     *
     * Client-side roles for:
     * ✅ UI display (show/hide elements)
     * ✅ UX optimization (disable unavailable features)
     *
     * NOT for:
     * ❌ Security decisions (server validates)
     * ❌ Authorization (Gateway does it)
     *
     * User can modify client-side roles (browser),
     * але Gateway validates JWT roles (cannot fake).
     *
     * COMMON ROLES:
     * ════════════
     * USER:
     * - Default role (all users)
     * - Basic permissions
     *
     * ADMIN:
     * - Full permissions
     * - Manage users, system
     *
     * MODERATOR (future):
     * - Moderate content
     * - Ban users
     *
     * EDITOR (future):
     * - Edit content
     * - Publish articles
     */
    private Set<String> roles;

    /**
     * Enabled Flag
     *
     * Account status (active або disabled).
     *
     * VALUES:
     * ══════
     * true: Account enabled (active)
     * false: Account disabled (cannot login)
     *
     * USAGE:
     * ═════
     * Client display:
     * - Show warning: "Account disabled"
     * - Hide actions (cannot comment, post)
     * - Contact support message
     *
     * Admin panel:
     * - Toggle button: Enable/Disable account
     * - Status indicator: Active/Disabled
     * - Disable reason (future)
     *
     * DISABLED ACCOUNT:
     * ════════════════
     * Cannot:
     * ❌ Login (authentication fails)
     * ❌ Use API (Gateway rejects)
     * ❌ Perform actions
     *
     * Can (maybe):
     * ✅ View public content (read-only)
     * ✅ Contact support (appeal)
     *
     * Reasons для disable:
     * - Terms violation (spam, abuse)
     * - Security concern (compromised)
     * - User request (temporary deactivation)
     * - Payment issue (subscription expired)
     *
     * RE-ENABLE:
     * ═════════
     * Admin action:
     * 1. Review case
     * 2. Enable account (set enabled=true)
     * 3. User can login immediately
     *
     * Self-service (future):
     * 1. User requests reactivation
     * 2. Email verification
     * 3. Automatic enable
     *
     * PRIVACY:
     * ═══════
     * Consider hiding from other users:
     * - Own profile: Show status
     * - Other profiles: Maybe hide (privacy)
     * - Admin panel: Always show
     *
     * Future: Separate field visibility:
     * - PublicUserResponse: No enabled field
     * - UserProfileResponse: Include enabled
     */
    private Boolean enabled;
}
