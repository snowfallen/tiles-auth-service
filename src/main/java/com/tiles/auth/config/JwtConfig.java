package com.tiles.auth.config;

import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

/**
 * JWT Configuration
 *
 * Централізоване місце для JWT configuration properties.
 *
 * Values завантажуються з:
 * - application.yml
 * - Config Server (auth-service.yml)
 * - Environment variables
 *
 * Usage:
 * @Autowired JwtConfig jwtConfig;
 * String issuer = jwtConfig.getIssuer();
 */
@Configuration
@Getter
public class JwtConfig {

    /**
     * JWT Secret Key
     *
     * Used для signing/validation JWT (HS256).
     *
     * IMPORTANT:
     * - MUST be at least 256 bits (32 bytes) для HS256
     * - Should be random and unpredictable
     * - NEVER commit to Git (use environment variables)
     * - Different per environment (dev/staging/prod)
     *
     * In production:
     * - Store in Kubernetes Secret
     * - Or use Vault/AWS Secrets Manager
     * - Rotate periodically
     *
     * Default value тільки для dev!
     */
    @Value("${jwt.secret}")
    private String secret;

    /**
     * Access Token Expiry
     *
     * How long access token valid (in milliseconds).
     *
     * Default: 900000ms = 15 minutes
     *
     * Considerations:
     * - Too short (< 5 min): poor UX (frequent refreshes)
     * - Too long (> 30 min): security risk
     * - 15 min: good balance
     *
     * Token lifecycle:
     * 1. Login → get access token (15 min TTL)
     * 2. Use for 15 minutes
     * 3. Token expires
     * 4. Refresh → get new access token (15 min TTL)
     * 5. Repeat
     */
    @Value("${jwt.access-token-expiry}")
    private Long accessTokenExpiry;

    /**
     * Refresh Token Expiry
     *
     * How long refresh token valid (in milliseconds).
     *
     * Default: 604800000ms = 7 days
     *
     * Considerations:
     * - Too short (< 1 day): annoying (user forced to relogin often)
     * - Too long (> 30 days): security risk
     * - 7 days: reasonable for most apps
     *
     * Mobile apps often use longer (30+ days)
     * Banking apps use shorter (1 day)
     */
    @Value("${jwt.refresh-token-expiry}")
    private Long refreshTokenExpiry;

    /**
     * JWT Issuer
     *
     * "iss" claim в JWT.
     * Identifies who created the token.
     *
     * Format: URL of Auth Service
     * Example: http://auth-service.tiles-infra.svc.cluster.local:8084
     *
     * Usage:
     * - Resource servers can verify issuer
     * - Multiple auth services → different issuers
     * - Part of JWT validation
     */
    @Value("${jwt.issuer}")
    private String issuer;

    /**
     * Get access token expiry in seconds
     * (for API responses)
     */
    public Long getAccessTokenExpiryInSeconds() {
        return accessTokenExpiry / 1000;
    }

    /**
     * Get refresh token expiry in seconds
     */
    public Long getRefreshTokenExpiryInSeconds() {
        return refreshTokenExpiry / 1000;
    }
}
