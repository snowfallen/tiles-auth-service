package com.tiles.auth.service;

import com.tiles.auth.security.CustomUserDetails;

import java.util.Date;

/**
 * Token Service Interface
 *
 * Defines contract для JWT token operations.
 *
 * RESPONSIBILITIES:
 * ═══════════════
 * - Generate JWT access tokens (RS256)
 * - Validate JWT tokens
 * - Parse JWT claims (extract data)
 * - Check token expiration
 *
 * JWT STRUCTURE:
 * ═════════════
 * JWT = Header.Payload.Signature
 *
 * Header:
 * {
 *   "alg": "RS256",
 *   "typ": "JWT",
 *   "kid": "auth-service-key-2024"
 * }
 *
 * Payload (claims):
 * {
 *   "sub": "user-uuid",
 *   "username": "admin",
 *   "email": "admin@example.com",
 *   "roles": ["USER", "ADMIN"],
 *   "iss": "http://auth-service...",
 *   "iat": 1698758400,
 *   "exp": 1698759300,
 *   "jti": "token-uuid"
 * }
 *
 * Signature:
 * RSA-SHA256(base64(header) + "." + base64(payload), privateKey)
 *
 * RS256 ALGORITHM:
 * ═══════════════
 * - Sign: RSA private key (Auth Service only)
 * - Verify: RSA public key (Gateway, JWKS)
 * - Benefits: public key can be shared
 *
 * @author snowfallen
 * @version 1.0.0
 * @since 2024-10-31
 */
public interface TokenService {

    /**
     * Generate JWT Access Token
     *
     * Creates signed JWT з user claims.
     *
     * TOKEN CONTENTS:
     * ══════════════
     * Standard claims:
     * - sub (subject): userId (UUID)
     * - iss (issuer): auth service URL
     * - iat (issued at): current timestamp
     * - exp (expiration): current + 15 minutes
     * - jti (JWT ID): unique token ID (UUID)
     *
     * Custom claims:
     * - username: user's username
     * - email: user's email
     * - roles: array of role names ["USER", "ADMIN"]
     *
     * SIGNATURE:
     * ═════════
     * Algorithm: RS256 (RSA + SHA-256)
     * Key: RSA private key (2048-bit)
     * Header: includes "kid" для key identification
     *
     * USAGE:
     * ═════
     * Client includes token в requests:
     * Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
     *
     * Gateway validates token using public key.
     *
     * @param userDetails authenticated user details
     * @return JWT access token string
     */
    String generateAccessToken(CustomUserDetails userDetails);

    /**
     * Validate JWT Token
     *
     * Verifies token signature і checks expiration.
     *
     * VALIDATION CHECKS:
     * ═════════════════
     * ✅ Signature valid (using public key)
     * ✅ Not expired (exp claim)
     * ✅ Valid format (proper JWT structure)
     * ✅ Issuer matches (iss claim)
     *
     * ERRORS:
     * ══════
     * - ExpiredJwtException: token expired
     * - SignatureException: invalid signature (tampered)
     * - MalformedJwtException: invalid JWT format
     * - UnsupportedJwtException: unsupported algorithm
     *
     * @param token JWT token string
     * @return true if valid
     * @throws com.tiles.auth.exception.InvalidTokenException if invalid
     */
    boolean validateToken(String token);

    /**
     * Extract User ID від JWT
     *
     * Gets "sub" (subject) claim від token.
     * Subject = primary identifier (userId UUID).
     *
     * @param token JWT token string
     * @return userId (UUID string)
     */
    String getUserIdFromToken(String token);

    /**
     * Extract Username від JWT
     *
     * Gets "username" custom claim від token.
     *
     * @param token JWT token string
     * @return username
     */
    String getUsernameFromToken(String token);

    /**
     * Extract Email від JWT
     *
     * Gets "email" custom claim від token.
     *
     * @param token JWT token string
     * @return email address
     */
    String getEmailFromToken(String token);

    /**
     * Extract Roles від JWT
     *
     * Gets "roles" custom claim від token.
     *
     * Format в JWT: ["USER", "ADMIN"]
     * Returns: String[] {"USER", "ADMIN"}
     *
     * @param token JWT token string
     * @return array of role names
     */
    String[] getRolesFromToken(String token);

    /**
     * Extract Expiration Date від JWT
     *
     * Gets "exp" (expiration) claim від token.
     *
     * @param token JWT token string
     * @return expiration date
     */
    Date getExpirationFromToken(String token);

    /**
     * Check if Token Expired
     *
     * Compares expiration time з current time.
     *
     * @param token JWT token string
     * @return true if expired
     */
    boolean isTokenExpired(String token);
}
