package com.tiles.auth.service.impl;

import com.tiles.auth.exception.InvalidTokenException;
import com.tiles.auth.model.security.CustomUserDetails;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Token Service
 *
 * Відповідає за:
 * - JWT generation (access tokens)
 * - JWT validation
 * - JWT parsing (extracting claims)
 *
 * Використовує JJWT library (io.jsonwebtoken).
 *
 * JWT Structure:
 * - Header: algorithm (HS256), type (JWT)
 * - Payload: claims (sub, roles, exp, тощо)
 * - Signature: HMACSHA256(header + payload, secret)
 */
@Service
@Slf4j
public class TokenServiceImpl implements TokenService {

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.access-token-expiry}")
    private Long accessTokenExpiry;  // milliseconds

    @Value("${jwt.issuer}")
    private String issuer;

    /**
     * Generate JWT Access Token
     *
     * Creates JWT with:
     * - Subject (sub): userId
     * - Username: username
     * - Email: email
     * - Roles: array of role names
     * - Issuer (iss): auth-service URL
     * - Issued At (iat): current timestamp
     * - Expiration (exp): current + 15 minutes
     * - JWT ID (jti): unique token ID
     *
     * @param userDetails authenticated user
     * @return JWT string
     */
    @Override
    public String generateAccessToken(CustomUserDetails userDetails) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + accessTokenExpiry);

        // Additional claims (custom data in JWT)
        Map<String, Object> claims = new HashMap<>();
        claims.put("username", userDetails.getUsername());
        claims.put("email", userDetails.getEmail());
        claims.put("roles", userDetails.getRoleNames());

        // Build JWT
        String token = Jwts.builder()
                .setClaims(claims)                          // Custom claims
                .setSubject(userDetails.getUserId())        // Subject = userId
                .setIssuer(issuer)                          // Issuer = auth-service
                .setIssuedAt(now)                           // Issued at
                .setExpiration(expiryDate)                  // Expiration
                .setId(UUID.randomUUID().toString())        // Unique token ID
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)  // Sign with secret
                .compact();

        log.debug("Generated access token for user: {}", userDetails.getUsername());
        return token;
    }

    /**
     * Validate JWT Token
     *
     * Перевіряє:
     * - Signature (чи не підробили токен)
     * - Expiration (чи не expired)
     * - Format (чи валідний JWT)
     *
     * @param token JWT string
     * @return true if valid
     * @throws InvalidTokenException if invalid
     */
    @Override
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (ExpiredJwtException ex) {
            log.warn("Token expired: {}", ex.getMessage());
            throw new InvalidTokenException("Token expired");
        } catch (UnsupportedJwtException ex) {
            log.error("Unsupported JWT: {}", ex.getMessage());
            throw new InvalidTokenException("Unsupported JWT token");
        } catch (MalformedJwtException ex) {
            log.error("Malformed JWT: {}", ex.getMessage());
            throw new InvalidTokenException("Malformed JWT token");
        } catch (SecurityException ex) {
            log.error("Invalid JWT signature: {}", ex.getMessage());
            throw new InvalidTokenException("Invalid JWT signature");
        } catch (IllegalArgumentException ex) {
            log.error("JWT claims empty: {}", ex.getMessage());
            throw new InvalidTokenException("JWT claims string is empty");
        }
    }

    /**
     * Get User ID from JWT
     *
     * Extracts subject (userId) from token.
     *
     * @param token JWT string
     * @return userId (UUID string)
     */
    @Override
    public String getUserIdFromToken(String token) {
        Claims claims = getClaimsFromToken(token);
        return claims.getSubject();
    }

    /**
     * Get Username from JWT
     *
     * @param token JWT string
     * @return username
     */
    @Override
    public String getUsernameFromToken(String token) {
        Claims claims = getClaimsFromToken(token);
        return claims.get("username", String.class);
    }

    /**
     * Get Email from JWT
     *
     * @param token JWT string
     * @return email
     */
    @Override
    public String getEmailFromToken(String token) {
        Claims claims = getClaimsFromToken(token);
        return claims.get("email", String.class);
    }

    /**
     * Get Roles from JWT
     *
     * @param token JWT string
     * @return array of role names
     */
    @Override
    @SuppressWarnings("unchecked")
    public String[] getRolesFromToken(String token) {
        Claims claims = getClaimsFromToken(token);
        // Roles stored as List in JWT, convert to array
        return ((java.util.List<String>) claims.get("roles")).toArray(new String[0]);
    }

    /**
     * Get Expiration Date from JWT
     *
     * @param token JWT string
     * @return expiration date
     */
    @Override
    public Date getExpirationFromToken(String token) {
        Claims claims = getClaimsFromToken(token);
        return claims.getExpiration();
    }

    /**
     * Check if token is expired
     *
     * @param token JWT string
     * @return true if expired
     */
    @Override
    public boolean isTokenExpired(String token) {
        Date expiration = getExpirationFromToken(token);
        return expiration.before(new Date());
    }

    /**
     * Extract all claims from JWT
     *
     * Private helper method.
     *
     * @param token JWT string
     * @return Claims object
     */
    private Claims getClaimsFromToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * Get signing key from secret
     *
     * Converts String secret to SecretKey для HMAC.
     *
     * ВАЖЛИВО: Secret має бути мінімум 256 біт (32 байти) для HS256.
     *
     * @return SecretKey for signing/validation
     */
    private SecretKey getSigningKey() {
        byte[] keyBytes = jwtSecret.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}