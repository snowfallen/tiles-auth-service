package com.tiles.auth.repository;

import com.tiles.auth.model.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

/**
 * User Repository
 *
 * Spring Data JPA repository для User entity.
 *
 * Spring Data автоматично генерує implementations для:
 * - save(user)
 * - findById(id)
 * - findAll()
 * - delete(user)
 * - тощо
 *
 * Ми додаємо custom query methods:
 * - findByUsername
 * - findByEmail
 * - existsByUsername
 * - existsByEmail
 */
@Repository
public interface UserRepository extends JpaRepository<User, UUID> {

    /**
     * Find user by username
     *
     * Spring Data автоматично генерує query:
     * SELECT * FROM users WHERE username = ?
     *
     * @param username unique username
     * @return Optional<User> (empty if not found)
     */
    Optional<User> findByUsername(String username);

    /**
     * Find user by email
     *
     * Query: SELECT * FROM users WHERE email = ?
     *
     * @param email unique email
     * @return Optional<User>
     */
    Optional<User> findByEmail(String email);

    /**
     * Check if username exists
     *
     * Query: SELECT COUNT(*) > 0 FROM users WHERE username = ?
     *
     * More efficient than findByUsername().isPresent()
     * бо не завантажує всі поля
     *
     * @param username username to check
     * @return true if exists
     */
    boolean existsByUsername(String username);

    /**
     * Check if email exists
     *
     * Query: SELECT COUNT(*) > 0 FROM users WHERE email = ?
     *
     * @param email email to check
     * @return true if exists
     */
    boolean existsByEmail(String email);

    /**
     * Find user by username with roles (explicit fetch)
     *
     * Хоча ми вже маємо FetchType.EAGER на roles,
     * цей метод може бути корисний для explicit control.
     *
     * @Query annotation дозволяє писати custom JPQL
     */
    @Query("SELECT u FROM User u LEFT JOIN FETCH u.roles WHERE u.username = :username")
    Optional<User> findByUsernameWithRoles(String username);

    /**
     * Find enabled users by role
     *
     * Приклад складнішого query через relationship
     */
    @Query("SELECT DISTINCT u FROM User u JOIN u.roles r WHERE r.name = :roleName AND u.enabled = true")
    java.util.List<User> findEnabledUsersByRole(String roleName);
}
