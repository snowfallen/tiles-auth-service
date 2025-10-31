package com.tiles.auth.repository;

import com.tiles.auth.model.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Role Repository
 *
 * Simple repository для Role entity.
 * Roles - це майже enum (статичні значення),
 * тому методів небагато.
 */
@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {

    /**
     * Find role by name
     *
     * Query: SELECT * FROM roles WHERE name = ?
     *
     * @param name role name (USER, ADMIN)
     * @return Optional<Role>
     */
    Optional<Role> findByName(String name);

    /**
     * Check if role exists by name
     *
     * @param name role name
     * @return true if exists
     */
    boolean existsByName(String name);
}
