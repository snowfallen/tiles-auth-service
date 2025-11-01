package com.tiles.auth.mapper;

import com.tiles.auth.dto.response.UserResponse;
import com.tiles.auth.model.User;
import org.springframework.stereotype.Component;

import java.util.stream.Collectors;

/**
 * User Mapper
 *
 * Converts User entity ↔ UserResponse DTO.
 *
 * MAPPER PATTERN:
 * ══════════════
 * Separates domain model від API representation.
 *
 * Entity (domain):
 * - All fields (passwordHash, timestamps)
 * - JPA annotations
 * - Relationships (Set<Role> entities)
 * - Database structure
 *
 * DTO (API):
 * - Only public fields
 * - No annotations
 * - Simple types (Set<String> role names)
 * - API contract
 *
 * Mapper bridges gap:
 * Entity → DTO (toResponse)
 * DTO → Entity (toEntity, not needed here)
 *
 * WHY MANUAL MAPPING:
 * ══════════════════
 * vs MapStruct (annotation processor):
 *
 * Manual:
 * ✅ Full control
 * ✅ No magic (explicit code)
 * ✅ Easy debugging
 * ✅ No additional dependencies
 * ✅ Simple cases (few fields)
 *
 * MapStruct:
 * ✅ Less boilerplate
 * ✅ Generated code (fast)
 * ✅ Complex mappings
 * ⚠️  Build-time generation
 * ⚠️  Learning curve
 *
 * For this simple mapping, manual є cleaner.
 *
 * COMPONENT ANNOTATION:
 * ════════════════════
 * @Component registers as Spring bean.
 * Can be injected into services/controllers.
 *
 * Usage:
 * @RequiredArgsConstructor
 * class SomeService {
 *     private final UserMapper userMapper;
 *
 *     public UserResponse getUser() {
 *         User user = userRepository.findById(id);
 *         return userMapper.toResponse(user);
 *     }
 * }
 *
 * IMMUTABILITY:
 * ════════════
 * Mapper methods:
 * - Don't modify input entity
 * - Create new DTO object
 * - Pure functions (no side effects)
 *
 * Benefits:
 * ✅ Thread-safe
 * ✅ Predictable
 * ✅ Cacheable
 *
 * NULL SAFETY:
 * ═══════════
 * Current implementation:
 * - Assumes user not null
 * - Assumes roles not null
 *
 * Future improvement:
 * - Add null checks
 * - Return Optional<UserResponse>
 * - Handle edge cases
 *
 * @author snowfallen
 * @version 1.0.0
 * @since 2024-10-31
 */
@Component
public class UserMapper {

    /**
     * Convert User Entity → UserResponse DTO
     *
     * Maps domain entity до API DTO.
     *
     * FIELD MAPPING:
     * ═════════════
     * Entity → DTO:
     *
     * user.id (UUID) → response.id (String)
     * - UUID.toString() converts UUID → String
     * - "550e8400-..." format
     *
     * user.username → response.username
     * - Direct copy (String → String)
     *
     * user.email → response.email
     * - Direct copy (String → String)
     *
     * user.roles (Set<Role>) → response.roles (Set<String>)
     * - Stream roles
     * - Extract role.getName() для each
     * - Collect to Set<String>
     * - ["USER", "ADMIN"]
     *
     * user.enabled → response.enabled
     * - Direct copy (Boolean → Boolean)
     *
     * EXCLUDED FIELDS:
     * ═══════════════
     * Not mapped (security/privacy):
     * ❌ passwordHash (sensitive)
     * ❌ accountNonExpired (internal)
     * ❌ accountNonLocked (internal)
     * ❌ credentialsNonExpired (internal)
     * ❌ createdAt (not needed)
     * ❌ updatedAt (not needed)
     *
     * ROLE EXTRACTION:
     * ═══════════════
     * Process:
     * 1. user.getRoles() → Set<Role>
     * 2. .stream() → Stream<Role>
     * 3. .map(Role::getName) → Stream<String>
     * 4. .collect(Collectors.toSet()) → Set<String>
     *
     * Example:
     * Input: Set<Role> {Role(id=1, name="USER"), Role(id=2, name="ADMIN")}
     * Output: Set<String> {"USER", "ADMIN"}
     *
     * WHY SET (not List):
     * - Preserves collection type
     * - No duplicates
     * - Unordered (role order doesn't matter)
     *
     * DTO CONSTRUCTION:
     * ════════════════
     * Builder pattern:
     * - Clean construction
     * - Named parameters
     * - Readable code
     *
     * UserResponse.builder()
     *     .id(...)
     *     .username(...)
     *     .email(...)
     *     .roles(...)
     *     .enabled(...)
     *     .build();
     *
     * USAGE EXAMPLES:
     * ══════════════
     *
     * Single user:
     * User user = userRepository.findById(id);
     * UserResponse response = userMapper.toResponse(user);
     * return ResponseEntity.ok(response);
     *
     * List of users:
     * List<User> users = userRepository.findAll();
     * List<UserResponse> responses = users.stream()
     *     .map(userMapper::toResponse)
     *     .collect(Collectors.toList());
     * return ResponseEntity.ok(responses);
     *
     * Optional user:
     * Optional<User> userOpt = userRepository.findById(id);
     * Optional<UserResponse> responseOpt = userOpt.map(userMapper::toResponse);
     * return ResponseEntity.of(responseOpt);
     *
     * NULL HANDLING:
     * ═════════════
     * Current: Assumes user not null
     *
     * If user is null:
     * - NullPointerException thrown
     * - Caller responsibility (check before calling)
     *
     * Improvement (future):
     * public UserResponse toResponse(User user) {
     *     if (user == null) {
     *         return null;  // or throw exception
     *     }
     *     // ... mapping
     * }
     *
     * Or use Optional:
     * public Optional<UserResponse> toResponse(User user) {
     *     return Optional.ofNullable(user)
     *         .map(u -> UserResponse.builder()...);
     * }
     *
     * PERFORMANCE:
     * ═══════════
     * Lightweight operation:
     * - Simple field copies
     * - Single stream operation (roles)
     * - No database queries
     * - No heavy computation
     *
     * Suitable для:
     * ✅ Single user (fast)
     * ✅ Small lists (<1000)
     * ✅ Real-time requests
     *
     * Large lists (10k+):
     * - Consider pagination
     * - Lazy loading
     * - Streaming response
     *
     * TESTING:
     * ═══════
     * Unit test example:
     *
     * @Test
     * void testToResponse() {
     *     // Given
     *     Role userRole = new Role(1L, "USER");
     *     User user = User.builder()
     *         .id(UUID.randomUUID())
     *         .username("testuser")
     *         .email("test@example.com")
     *         .enabled(true)
     *         .roles(Set.of(userRole))
     *         .build();
     *
     *     // When
     *     UserResponse response = userMapper.toResponse(user);
     *
     *     // Then
     *     assertEquals(user.getId().toString(), response.getId());
     *     assertEquals(user.getUsername(), response.getUsername());
     *     assertEquals(user.getEmail(), response.getEmail());
     *     assertTrue(response.getRoles().contains("USER"));
     *     assertTrue(response.getEnabled());
     * }
     *
     * @param user User entity to convert
     * @return UserResponse DTO
     */
    public UserResponse toResponse(User user) {
        return UserResponse.builder()
                // UUID → String conversion
                // UUID.toString() format: "550e8400-e29b-41d4-a716-446655440000"
                .id(user.getId().toString())

                // Direct string copy
                .username(user.getUsername())

                // Direct string copy
                .email(user.getEmail())

                // Set<Role> → Set<String> conversion
                // Extracts role names: ["USER", "ADMIN"]
                .roles(user.getRoles().stream()
                        .map(role -> role.getName())
                        .collect(Collectors.toSet()))

                // Direct boolean copy
                .enabled(user.getEnabled())

                // Build immutable DTO
                .build();
    }
}
