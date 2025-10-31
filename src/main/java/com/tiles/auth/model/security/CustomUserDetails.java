package com.tiles.auth.model.security;

import com.tiles.auth.model.entity.User;
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
 * Spring Security використовує UserDetails для authentication/authorization.
 *
 * Зверни увагу:
 * - Roles конвертуються в GrantedAuthority з prefix "ROLE_"
 * - Це Spring Security convention
 */
@Getter
public class CustomUserDetails implements UserDetails {

    private final User user;

    public CustomUserDetails(User user) {
        this.user = user;
    }

    /**
     * Get authorities (roles) for Spring Security
     *
     * Spring Security очікує format: ROLE_XXX
     * Наші roles в БД: USER, ADMIN
     * Тут конвертуємо: ROLE_USER, ROLE_ADMIN
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return user.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.getName()))
                .collect(Collectors.toList());
    }

    @Override
    public String getPassword() {
        return user.getPasswordHash();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return user.getAccountNonExpired();
    }

    @Override
    public boolean isAccountNonLocked() {
        return user.getAccountNonLocked();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return user.getCredentialsNonExpired();
    }

    @Override
    public boolean isEnabled() {
        return user.getEnabled();
    }

    /**
     * Additional helper methods
     */

    public String getUserId() {
        return user.getId().toString();
    }

    public String getEmail() {
        return user.getEmail();
    }

    /**
     * Get role names without ROLE_ prefix
     */
    public String[] getRoleNames() {
        return user.getRoles().stream()
                .map(role -> role.getName())
                .toArray(String[]::new);
    }
}
