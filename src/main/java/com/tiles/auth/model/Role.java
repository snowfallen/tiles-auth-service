package com.tiles.auth.model.entity;

import jakarta.persistence.*;
import lombok.*;

/**
 * Role Entity
 *
 * Represents user role/permission (USER, ADMIN, etc.)
 * Simple enum-like table with predefined values.
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

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false, length = 50)
    private String name;

    /**
     * Predefined role names
     */
    public static final String USER = "USER";
    public static final String ADMIN = "ADMIN";
}