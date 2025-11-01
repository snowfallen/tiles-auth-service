package com.tiles.auth.config;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import jakarta.annotation.PostConstruct;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * JWT Configuration - RS256
 *
 * Централізоване управління JWT configuration properties.
 *
 * RESPONSIBILITIES:
 * ═══════════════
 * - Load RSA keys від environment variables
 * - Parse PEM format keys → Java objects
 * - Provide keys для TokenService
 * - Configure JWT parameters (expiry, issuer)
 *
 * RSA KEYS:
 * ═════════
 * Algorithm: RS256 (RSA Signature with SHA-256)
 * Key size: 2048 bits (minimum recommended)
 * Format: PEM (Privacy-Enhanced Mail)
 *
 * Private key (d, n, e, p, q):
 * - Used for SIGNING tokens
 * - Must be SECRET
 * - Only Auth Service має access
 *
 * Public key (n, e):
 * - Used for VALIDATING tokens
 * - Can be SHARED publicly
 * - Gateway fetches від JWKS endpoint
 *
 * WHY RS256 (not HS256):
 * ═══════════════════════
 * ✅ Public key можна ділитися (JWKS)
 * ✅ Gateway не може створити tokens (немає private key)
 * ✅ Production standard (OAuth2/OpenID Connect)
 * ✅ Key rotation easier (change keys без restart Gateway)
 *
 * KEY GENERATION:
 * ══════════════
 * Generate new key pair:
 *
 * ```bash
 * # RSA 2048-bit key pair
 * openssl genrsa -out private.pem 2048
 * openssl rsa -in private.pem -pubout -out public.pem
 *
 * # Convert to PKCS8 format (Java compatible)
 * openssl pkcs8 -topk8 -inform PEM -in private.pem \
 *   -out private_pkcs8.pem -nocrypt
 * ```
 *
 * CONFIGURATION:
 * ═════════════
 * Keys loaded від:
 * 1. Environment variables (Kubernetes secrets)
 * 2. application.yml (for local development)
 * 3. Config Server (centralized config)
 *
 * SECURITY NOTES:
 * ══════════════
 * ⚠️  NEVER commit private keys to Git
 * ⚠️  Use Kubernetes Secrets в production
 * ⚠️  Rotate keys periodically (e.g. annually)
 * ⚠️  Monitor key exposure (audit logs)
 *
 * @author snowfallen
 * @version 1.0.0
 * @since 2024-10-31
 */
@Configuration
@Getter
@Slf4j
public class JwtConfig {

    /**
     * JWT Algorithm
     *
     * Algorithm для signing/validation JWT.
     *
     * Supported values:
     * - RS256: RSA Signature with SHA-256 (рекомендовано)
     * - RS384: RSA Signature with SHA-384
     * - RS512: RSA Signature with SHA-512
     *
     * RS256 = industry standard, good balance security/performance
     */
    @Value("${jwt.algorithm:RS256}")
    private String algorithm;

    /**
     * Access Token Expiry
     *
     * How long access token valid (milliseconds).
     *
     * Default: 900000ms = 15 minutes
     *
     * Considerations:
     * - Too short (< 5 min): poor UX (frequent token refreshes)
     * - Too long (> 30 min): security risk (more time для stolen token)
     * - 15 min: recommended balance
     *
     * Lifecycle:
     * 1. User login → access token (15 min TTL)
     * 2. Client uses token для requests
     * 3. Token expires після 15 minutes
     * 4. Client uses refresh token → new access token
     * 5. Repeat
     */
    @Value("${jwt.access-token-expiry:900000}")
    private Long accessTokenExpiry;  // 15 minutes

    /**
     * Refresh Token Expiry
     *
     * How long refresh token valid (milliseconds).
     *
     * Default: 604800000ms = 7 days
     *
     * Considerations:
     * - Too short (< 1 day): annoying (frequent relogin)
     * - Too long (> 30 days): security risk
     * - 7 days: reasonable для most applications
     *
     * Different apps use different values:
     * - Banking apps: 1 day (high security)
     * - Social media: 30 days (convenience)
     * - Enterprise: 7-14 days (balance)
     * - Mobile apps: often longer (up to 90 days)
     */
    @Value("${jwt.refresh-token-expiry:604800000}")
    private Long refreshTokenExpiry;  // 7 days

    /**
     * JWT Issuer
     *
     * "iss" claim в JWT payload.
     * Identifies WHO created the token.
     *
     * Format: URL of Auth Service
     * Example: http://auth-service.tiles-infra.svc.cluster.local:8084
     *
     * Usage:
     * - Resource servers verify issuer
     * - Multiple auth services → different issuers
     * - Part of JWT standard validation
     * - Security: prevents token misuse between services
     */
    @Value("${jwt.issuer}")
    private String issuer;

    /**
     * RSA Private Key (PEM format)
     *
     * Private key для signing JWT tokens.
     *
     * Format: PEM (Privacy-Enhanced Mail)
     * -----BEGIN PRIVATE KEY-----
     * Base64-encoded PKCS8 key data
     * -----END PRIVATE KEY-----
     *
     * SECURITY: MUST BE SECRET!
     * ⚠️  Only Auth Service має access
     * ⚠️  Store в Kubernetes Secret
     * ⚠️  Never commit to Git
     * ⚠️  Rotate periodically
     *
     * Loaded від:
     * - Environment variable: JWT_PRIVATE_KEY
     * - Kubernetes Secret: jwt-keys-secret
     */
    @Value("${jwt.private-key}")
    private String privateKeyPem;

    /**
     * RSA Public Key (PEM format)
     *
     * Public key для validating JWT signatures.
     *
     * Format: PEM (X.509 SubjectPublicKeyInfo)
     * -----BEGIN PUBLIC KEY-----
     * Base64-encoded public key data
     * -----END PUBLIC KEY-----
     *
     * This key CAN BE SHARED publicly via JWKS endpoint.
     * Gateway fetches this key для JWT validation.
     *
     * Loaded від:
     * - Environment variable: JWT_PUBLIC_KEY
     * - Kubernetes Secret: jwt-keys-secret
     */
    @Value("${jwt.public-key}")
    private String publicKeyPem;

    /**
     * Parsed RSA Private Key
     *
     * Java object representation of private key.
     * Used by TokenService для signing JWTs.
     *
     * Contains:
     * - Modulus (n)
     * - Public exponent (e)
     * - Private exponent (d)
     * - Prime factors (p, q)
     * - CRT coefficients
     */
    private RSAPrivateKey privateKey;

    /**
     * Parsed RSA Public Key
     *
     * Java object representation of public key.
     * Used by TokenService для validation (testing)
     * і JwksService для publishing.
     *
     * Contains:
     * - Modulus (n)
     * - Public exponent (e)
     */
    private RSAPublicKey publicKey;

    /**
     * Initialize Keys
     *
     * Виконується ПІСЛЯ того як всі @Value properties set.
     * Parses PEM format keys → Java RSA key objects.
     *
     * LIFECYCLE:
     * ═════════
     * 1. Spring creates JwtConfig bean
     * 2. Spring injects @Value properties
     * 3. @PostConstruct викликає цей метод
     * 4. Keys parsed і ready для use
     *
     * ERRORS:
     * ══════
     * Throws RuntimeException якщо:
     * - Keys not found в properties
     * - Invalid PEM format
     * - Invalid key data
     * - Algorithm not supported
     *
     * Application FAILS TO START при errors → fail-fast approach.
     * Better crash при startup than runtime errors.
     */
    @PostConstruct
    public void init() {
        try {
            log.info("Loading RSA keys for JWT operations...");

            // Parse private key від PEM format
            this.privateKey = parsePrivateKey(privateKeyPem);
            log.debug("Private key loaded successfully");

            // Parse public key від PEM format
            this.publicKey = parsePublicKey(publicKeyPem);
            log.info("Public key loaded successfully: {} bits",
                    publicKey.getModulus().bitLength());

            // Validate key size (minimum 2048 bits recommended)
            int keySize = publicKey.getModulus().bitLength();
            if (keySize < 2048) {
                log.warn("⚠️  RSA key size ({} bits) less than recommended 2048 bits!", keySize);
            }

            log.info("JWT configuration initialized: algorithm={}, keySize={} bits",
                    algorithm, keySize);

        } catch (Exception e) {
            log.error("❌ Failed to load RSA keys - application cannot start!", e);
            throw new RuntimeException("Failed to load RSA keys", e);
        }
    }

    /**
     * Parse Private Key від PEM format
     *
     * Converts PEM string → RSAPrivateKey object.
     *
     * PROCESS:
     * ═══════
     * 1. Remove PEM headers/footers
     * 2. Remove whitespace
     * 3. Base64 decode → byte array
     * 4. Create PKCS8EncodedKeySpec
     * 5. Use KeyFactory → generate PrivateKey
     * 6. Cast → RSAPrivateKey
     *
     * PEM FORMAT:
     * ══════════
     * -----BEGIN PRIVATE KEY-----
     * Base64-encoded PKCS#8 private key data
     * (multiple lines, 64 characters each)
     * -----END PRIVATE KEY-----
     *
     * PKCS#8 = standard format для private keys (RFC 5208)
     *
     * @param pem PEM-encoded private key string
     * @return RSAPrivateKey Java object
     * @throws Exception if parsing fails
     */
    private RSAPrivateKey parsePrivateKey(String pem) throws Exception {
        log.debug("Parsing RSA private key from PEM format...");

        // Clean PEM format: remove headers and whitespace
        String cleanKey = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");  // Remove all whitespace

        // Base64 decode → raw key bytes
        byte[] keyBytes = Base64.getDecoder().decode(cleanKey);

        // Create PKCS8 key specification
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);

        // Get RSA KeyFactory
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        // Generate private key object
        return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
    }

    /**
     * Parse Public Key від PEM format
     *
     * Converts PEM string → RSAPublicKey object.
     *
     * PROCESS:
     * ═══════
     * 1. Remove PEM headers/footers
     * 2. Remove whitespace
     * 3. Base64 decode → byte array
     * 4. Create X509EncodedKeySpec
     * 5. Use KeyFactory → generate PublicKey
     * 6. Cast → RSAPublicKey
     *
     * PEM FORMAT:
     * ══════════
     * -----BEGIN PUBLIC KEY-----
     * Base64-encoded X.509 SubjectPublicKeyInfo
     * (multiple lines, 64 characters each)
     * -----END PUBLIC KEY-----
     *
     * X.509 = standard format для public keys (RFC 5280)
     *
     * @param pem PEM-encoded public key string
     * @return RSAPublicKey Java object
     * @throws Exception if parsing fails
     */
    private RSAPublicKey parsePublicKey(String pem) throws Exception {
        log.debug("Parsing RSA public key from PEM format...");

        // Clean PEM format: remove headers and whitespace
        String cleanKey = pem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");  // Remove all whitespace

        // Base64 decode → raw key bytes
        byte[] keyBytes = Base64.getDecoder().decode(cleanKey);

        // Create X509 key specification
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);

        // Get RSA KeyFactory
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        // Generate public key object
        return (RSAPublicKey) keyFactory.generatePublic(keySpec);
    }

    /**
     * Get Access Token Expiry (seconds)
     *
     * Converts milliseconds → seconds для API responses.
     *
     * JWT standard uses seconds для "exp" claim,
     * але Spring Boot properties часто в milliseconds.
     *
     * @return expiry в seconds (для response DTOs)
     */
    public Long getAccessTokenExpiryInSeconds() {
        return accessTokenExpiry / 1000;
    }

    /**
     * Get Refresh Token Expiry (seconds)
     *
     * @return expiry в seconds
     */
    public Long getRefreshTokenExpiryInSeconds() {
        return refreshTokenExpiry / 1000;
    }
}
