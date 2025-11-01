package com.tiles.auth.service.impl;

import com.tiles.auth.config.JwtConfig;
import com.tiles.auth.exception.InvalidTokenException;
import com.tiles.auth.security.CustomUserDetails;
import com.tiles.auth.service.TokenService;
import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Token Service Implementation - RS256
 *
 * JWT token operations using RSA asymmetric cryptography.
 *
 * ALGORITHM:
 * ═════════
 * RS256 = RSA Signature with SHA-256
 *
 * Process:
 * 1. Create JWT payload (claims)
 * 2. Serialize to JSON
 * 3. Base64Url encode header + payload
 * 4. Sign з RSA private key
 * 5. Append signature
 *
 * Result: header.payload.signature
 *
 * SIGNING:
 * ═══════
 * Private key (Auth Service only):
 * - Signs tokens
 * - MUST be secret
 * - 2048-bit RSA key
 *
 * Public key (shared via JWKS):
 * - Validates signatures
 * - Can be public
 * - Gateway uses для validation
 *
 * JJWT LIBRARY:
 * ════════════
 * io.jsonwebtoken:jjwt (version 0.12.5)
 *
 * Features:
 * ✅ RS256, RS384, RS512 support
 * ✅ JWT claims (standard + custom)
 * ✅ Expiration checking
 * ✅ Signature validation
 * ✅ Type-safe API
 *
 * @author snowfallen
 * @version 1.0.0
 * @since 2024-10-31
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class TokenServiceImpl implements TokenService {

    /**
     * JWT Configuration
     *
     * Provides:
     * - RSA keys (private + public)
     * - Token expiry durations
     * - Issuer URL
     * - Algorithm name
     */
    private final JwtConfig jwtConfig;

    /**
     * Generate JWT Access Token
     *
     * Creates signed JWT з user claims.
     *
     * TOKEN STRUCTURE:
     * ═══════════════
     *
     * Header:
     * {
     *   "alg": "RS256",               // Algorithm
     *   "typ": "JWT",                 // Type
     *   "kid": "auth-service-key-2024" // Key ID
     * }
     *
     * Payload (Claims):
     * {
     *   "sub": "user-uuid",           // Subject (userId)
     *   "username": "admin",          // Custom claim
     *   "email": "admin@example.com", // Custom claim
     *   "roles": ["USER", "ADMIN"],   // Custom claim
     *   "iss": "http://auth-service...", // Issuer
     *   "iat": 1698758400,            // Issued At (timestamp)
     *   "exp": 1698759300,            // Expiration (timestamp)
     *   "jti": "token-uuid"           // JWT ID (unique)
     * }
     *
     * Signature:
     * RSA-SHA256(
     *   base64Url(header) + "." + base64Url(payload),
     *   privateKey
     * )
     *
     * CLAIMS EXPLANATION:
     * ══════════════════
     *
     * Standard claims (JWT RFC 7519):
     * - sub: Subject (primary identifier) → userId
     * - iss: Issuer (who created token) → auth service URL
     * - iat: Issued At (when created) → current timestamp
     * - exp: Expiration (when expires) → current + 15 minutes
     * - jti: JWT ID (unique token ID) → UUID для tracking
     *
     * Custom claims (our application):
     * - username: User's login name
     * - email: User's email address
     * - roles: Array of role names (authorization)
     *
     * WHY CUSTOM CLAIMS:
     * ═════════════════
     * ✅ Gateway can authorize без database lookup
     * ✅ All needed info в token (stateless)
     * ✅ Reduces latency (no extra queries)
     *
     * Trade-off:
     * ⚠️  Token size larger (more claims)
     * ⚠️  Changes not reflected до token expires
     *
     * KEY ID (kid):
     * ════════════
     * Header includes "kid" для key identification.
     *
     * Purpose:
     * - Gateway needs to know which public key to use
     * - Enables key rotation (multiple keys active)
     * - JWKS endpoint provides key by kid
     *
     * Example:
     * Auth Service has 2 keys (rotation):
     * - auth-service-key-2024 (current)
     * - auth-service-key-2023 (old, being phased out)
     *
     * Token signed з key-2024, header includes kid.
     * Gateway fetches key-2024 від JWKS.
     *
     * SIGNATURE PROCESS:
     * ═════════════════
     * 1. Create header + payload JSON
     * 2. Base64Url encode both
     * 3. Concatenate: header.payload
     * 4. Hash з SHA-256
     * 5. Sign hash з RSA private key
     * 6. Base64Url encode signature
     * 7. Append: header.payload.signature
     *
     * @param userDetails authenticated user details
     * @return JWT access token string
     */
    @Override
    public String generateAccessToken(CustomUserDetails userDetails) {
        log.debug("Generating access token for user: {}", userDetails.getUsername());

        // Calculate timestamps
        Date now = new Date();
        Date expiry = new Date(now.getTime() + jwtConfig.getAccessTokenExpiry());

        // ════════════════════════════════════════
        // Build Custom Claims
        // ════════════════════════════════════════
        // Claims = payload data в JWT
        Map<String, Object> claims = new HashMap<>();
        claims.put("username", userDetails.getUsername());
        claims.put("email", userDetails.getEmail());
        claims.put("roles", userDetails.getRoleNames());  // Array: ["USER", "ADMIN"]

        log.debug("Token claims prepared: username={}, roles={}",
                userDetails.getUsername(),
                userDetails.getRoleNames());

        // Get RSA private key для signing
        RSAPrivateKey privateKey = jwtConfig.getPrivateKey();

        // ════════════════════════════════════════
        // Build JWT Token
        // ════════════════════════════════════════
        String token = Jwts.builder()
                // Custom claims (must be set first)
                .setClaims(claims)

                // Standard claims
                .setSubject(userDetails.getUserId())  // sub: userId (primary identifier)
                .setIssuer(jwtConfig.getIssuer())     // iss: auth service URL
                .setIssuedAt(now)                     // iat: current timestamp
                .setExpiration(expiry)                // exp: current + 15 minutes
                .setId(UUID.randomUUID().toString())  // jti: unique token ID

                // Header parameter: Key ID
                // Gateway uses this to fetch public key від JWKS
                .setHeaderParam("kid", "auth-service-key-2024")

                // Sign з RSA private key using RS256 algorithm
                // This creates signature: RSA-SHA256(header.payload, privateKey)
                .signWith(privateKey, SignatureAlgorithm.RS256)

                // Build final JWT string: header.payload.signature
                .compact();

        log.debug("Access token generated successfully: expires at {}", expiry);

        return token;
    }

    /**
     * Validate JWT Token
     *
     * Verifies token signature і checks expiration.
     *
     * VALIDATION CHECKS:
     * ═════════════════
     *
     * 1. Signature Verification:
     * ─────────────────────────
     * - Parse header + payload
     * - Recompute signature з public key
     * - Compare з token signature
     * - If different → token tampered → INVALID
     *
     * 2. Expiration Check:
     * ──────────────────
     * - Get "exp" claim
     * - Compare з current time
     * - If expired → INVALID
     *
     * 3. Format Validation:
     * ───────────────────
     * - Valid JWT structure (3 parts)
     * - Valid Base64Url encoding
     * - Valid JSON payload
     *
     * 4. Issuer Validation:
     * ───────────────────
     * - Get "iss" claim
     * - Compare з expected issuer
     * - If different → INVALID
     *
     * JJWT PARSER:
     * ═══════════
     * JwtParserBuilder configures validation:
     * - setSigningKey(publicKey) → signature validation
     * - requireIssuer(issuer) → issuer validation
     * - Expiration checked automatically
     *
     * ERRORS:
     * ══════
     * Different exceptions для different failures:
     * - ExpiredJwtException: token expired
     * - SignatureException: signature invalid (tampered)
     * - MalformedJwtException: invalid JWT format
     * - UnsupportedJwtException: unsupported algorithm
     * - IllegalArgumentException: null/empty token
     *
     * All wrapped в InvalidTokenException для consistency.
     *
     * @param token JWT token string
     * @return true if valid
     * @throws InvalidTokenException if invalid
     */
    @Override
    public boolean validateToken(String token) {
        log.debug("Validating JWT token");

        try {
            // Get RSA public key для signature validation
            RSAPublicKey publicKey = jwtConfig.getPublicKey();

            // ════════════════════════════════════════
            // Parse and Validate Token
            // ════════════════════════════════════════
            // JwtParserBuilder creates configured parser
            Jwts.parserBuilder()
                    // Set public key для signature verification
                    // Parser will use this to verify token signature
                    .setSigningKey(publicKey)

                    // Require specific issuer (security check)
                    // Token from different issuer will be rejected
                    .requireIssuer(jwtConfig.getIssuer())

                    // Build parser
                    .build()

                    // Parse token (this validates signature + expiration)
                    // Throws exception if validation fails
                    .parseClaimsJws(token);

            log.debug("JWT token validated successfully");
            return true;

        } catch (ExpiredJwtException ex) {
            // Token expired (exp claim < current time)
            log.warn("JWT token expired: {}", ex.getMessage());
            throw new InvalidTokenException("Token expired: " + ex.getMessage());

        } catch (SignatureException ex) {
            // Invalid signature (token tampered or wrong key)
            log.error("JWT signature validation failed: {}", ex.getMessage());
            throw new InvalidTokenException("Invalid signature: " + ex.getMessage());

        } catch (MalformedJwtException ex) {
            // Invalid JWT format (not 3 parts, invalid Base64, тощо)
            log.error("Malformed JWT token: {}", ex.getMessage());
            throw new InvalidTokenException("Malformed token: " + ex.getMessage());

        } catch (UnsupportedJwtException ex) {
            // Unsupported algorithm or features
            log.error("Unsupported JWT token: {}", ex.getMessage());
            throw new InvalidTokenException("Unsupported token: " + ex.getMessage());

        } catch (IllegalArgumentException ex) {
            // Null or empty token
            log.error("Invalid JWT token argument: {}", ex.getMessage());
            throw new InvalidTokenException("Invalid token: " + ex.getMessage());

        } catch (JwtException ex) {
            // Any other JWT-related error
            log.error("JWT validation failed: {}", ex.getMessage());
            throw new InvalidTokenException("Invalid token: " + ex.getMessage());
        }
    }

    /**
     * Extract User ID від JWT
     *
     * Gets "sub" (subject) claim від token.
     *
     * Subject claim = primary identifier of token owner.
     * В нашому випадку: userId (UUID).
     *
     * @param token JWT token string
     * @return userId (UUID string)
     */
    @Override
    public String getUserIdFromToken(String token) {
        return getClaims(token).getSubject();
    }

    /**
     * Extract Username від JWT
     *
     * Gets "username" custom claim від token.
     *
     * @param token JWT token string
     * @return username
     */
    @Override
    public String getUsernameFromToken(String token) {
        return getClaims(token).get("username", String.class);
    }

    /**
     * Extract Email від JWT
     *
     * Gets "email" custom claim від token.
     *
     * @param token JWT token string
     * @return email address
     */
    @Override
    public String getEmailFromToken(String token) {
        return getClaims(token).get("email", String.class);
    }

    /**
     * Extract Roles від JWT
     *
     * Gets "roles" custom claim від token.
     *
     * Stored в JWT як JSON array: ["USER", "ADMIN"]
     * JJWT deserializes to Java List<String>
     * We convert to String[] для convenience.
     *
     * @param token JWT token string
     * @return array of role names
     */
    @Override
    @SuppressWarnings("unchecked")
    public String[] getRolesFromToken(String token) {
        Claims claims = getClaims(token);

        // Get roles claim (stored як List<String> в JWT)
        java.util.List<String> rolesList =
                (java.util.List<String>) claims.get("roles");

        // Convert List → Array
        return rolesList.toArray(new String[0]);
    }

    /**
     * Extract Expiration Date від JWT
     *
     * Gets "exp" (expiration) claim від token.
     *
     * @param token JWT token string
     * @return expiration date
     */
    @Override
    public Date getExpirationFromToken(String token) {
        return getClaims(token).getExpiration();
    }

    /**
     * Check if Token Expired
     *
     * Compares expiration time з current time.
     *
     * @param token JWT token string
     * @return true if expired
     */
    @Override
    public boolean isTokenExpired(String token) {
        Date expiration = getExpirationFromToken(token);
        return expiration.before(new Date());
    }

    /**
     * Get Claims від JWT
     *
     * Internal helper method для parsing JWT і extracting claims.
     *
     * PROCESS:
     * ═══════
     * 1. Get RSA public key
     * 2. Build JWT parser з public key
     * 3. Parse token (validates signature)
     * 4. Extract claims (payload)
     * 5. Return Claims object
     *
     * CLAIMS OBJECT:
     * ═════════════
     * Claims = JWT payload = Map<String, Object>
     *
     * Methods:
     * - getSubject() → sub claim
     * - getIssuer() → iss claim
     * - getExpiration() → exp claim
     * - get(name, type) → custom claim
     *
     * ERRORS:
     * ══════
     * Same exceptions як validateToken():
     * - ExpiredJwtException
     * - SignatureException
     * - MalformedJwtException
     * - тощо
     *
     * Not caught here - let caller handle.
     *
     * @param token JWT token string
     * @return Claims object (payload)
     */
    private Claims getClaims(String token) {
        RSAPublicKey publicKey = jwtConfig.getPublicKey();

        return Jwts.parserBuilder()
                .setSigningKey(publicKey)
                .build()
                .parseClaimsJws(token)
                .getBody();  // Body = Claims = Payload
    }
}
