package com.tiles.auth.mapper;

import com.tiles.auth.dto.response.LoginResponse;
import com.tiles.auth.dto.response.TokenResponse;
import com.tiles.auth.dto.response.UserResponse;
import com.tiles.auth.config.JwtConfig;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * Auth Mapper
 *
 * Builds authentication responses
 */
@Component
@RequiredArgsConstructor
public class AuthMapper {

    private final JwtConfig jwtConfig;

    /**
     * Build LoginResponse з tokens і user info
     */
    public LoginResponse toLoginResponse(
            String accessToken,
            String refreshToken,
            UserResponse user) {

        return LoginResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(jwtConfig.getAccessTokenExpiryInSeconds())
                .user(user)
                .build();
    }

    /**
     * Build TokenResponse (тільки tokens, без user info)
     */
    public TokenResponse toTokenResponse(
            String accessToken,
            String refreshToken) {

        return TokenResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(jwtConfig.getAccessTokenExpiryInSeconds())
                .build();
    }
}
