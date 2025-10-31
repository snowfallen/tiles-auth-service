package com.tiles.auth.model.entity;

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
 * Represents authenticated user in the system.
 * Uses UUID as primary key for better distribution and security.
 * 
 * Fields:
 * - id: Unique identifier (UUID)
 * - username: Unique username for login
 * - email: Unique email address
 * - passwordHash: BCrypt hashed password
 * - enabled: Account enabled flag
 * - accountNonExpired: Account expiry flag
 * - accountNonLocked: Account lock flag
 * - credentialsNonExpired: Password expiry flag
 * - roles: Many-to-many relationship with Role
 */
@Entity
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {
    
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;
    
    @Column(unique = true, nullable = false, length = 255)
    private String username;
    
    @Column(unique = true, nullable = false, length = 255)
    private String email;
    
    @Column(name = "password_hash", nullable = false, length = 255)
    private String passwordHash;
    
    @Column(nullable = false)
    @Builder.Default
    private Boolean enabled = true;
    
    @Column(name = "account_non_expired", nullable = false)
    @Builder.Default
    private Boolean accountNonExpired = true;
    
    @Column(name = "account_non_locked", nullable = false)
    @Builder.Default
    private Boolean accountNonLocked = true;
    
    @Column(name = "credentials_non_expired", nullable = false)
    @Builder.Default
    private Boolean credentialsNonExpired = true;
    
    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;
    
    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
    
    /**
     * Many-to-Many relationship with Role
     * FetchType.EAGER - завантажує roles одразу з user
     * Це OK для auth, бо ролей небагато
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
     * Helper method to add role
     */
    public void addRole(Role role) {
        this.roles.add(role);
    }
    
    /**
     * Helper method to remove role
     */
    public void removeRole(Role role) {
        this.roles.remove(role);
    }
    
    /**
     * Check if user has specific role
     */
    public boolean hasRole(String roleName) {
        return roles.stream()
                .anyMatch(role -> role.getName().equals(roleName));
    }
}