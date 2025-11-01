package com.tiles.auth.service.impl;

import com.tiles.auth.config.JwtConfig;
import com.tiles.auth.service.JwksService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * JWKS Service Implementation
 *
 * Builds і publishes JWKS (JSON Web Key Set) для Auth Service.
 *
 * RESPONSIBILITIES:
 * ═══════════════
 * - Build JWK від RSA public key
 * - Format JWKS response (standard format)
 * - Health check для JWKS endpoint
 * - Public key info (debugging)
 *
 * JWKS STANDARD:
 * ═════════════
 * JWKS = JSON Web Key Set (RFC 7517)
 *
 * Standard format для публікації cryptographic keys.
 * Used by OAuth2, OpenID Connect, JWT validation.
 *
 * Format:
 * {
 *   "keys": [
 *     {
 *       "kty": "RSA",
 *       "kid": "auth-service-key-2024",
 *       "alg": "RS256",
 *       "use": "sig",
 *       "n": "modulus-base64url",
 *       "e": "exponent-base64url"
 *     }
 *   ]
 * }
 *
 * USAGE BY GATEWAY:
 * ════════════════
 * 1. Gateway makes GET /.well-known/jwks.json
 * 2. Extracts public key components (n, e)
 * 3. Reconstructs RSA public key
 * 4. Caches key (24 hours)
 * 5. Uses для JWT signature validation
 *
 * KEY ROTATION:
 * ════════════
 * JWKS can contain multiple keys (array).
 * Each key has unique "kid" (Key ID).
 *
 * JWT header includes "kid":
 * {"alg":"RS256","kid":"auth-service-key-2024"}
 *
 * Gateway uses "kid" to select correct key від JWKS.
 *
 * Rotation process:
 * 1. Add new key до JWKS (keep old)
 * 2. Start signing з new key
 * 3. Gateway fetches JWKS, gets both keys
 * 4. Old tokens validated з old key
 * 5. New tokens validated з new key
 * 6. After transition, remove old key
 *
 * @author snowfallen
 * @version 1.0.0
 * @since 2024-10-31
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class JwksServiceImpl implements JwksService {

    /**
     * JWT Configuration
     *
     * Provides RSA keys:
     * - Private key (not used here, only для signing)
     * - Public key (published via JWKS)
     * - Algorithm name (RS256)
     * - Issuer URL
     */
    private final JwtConfig jwtConfig;

    /**
     * Get JWKS (JSON Web Key Set)
     *
     * Builds JWKS response з RSA public key.
     *
     * PROCESS:
     * ═══════
     * 1. Get RSA public key від JwtConfig
     * 2. Extract key components (modulus, exponent)
     * 3. Build JWK map з metadata
     * 4. Wrap в JWKS structure (keys array)
     * 5. Return JWKS map
     *
     * JWK STRUCTURE:
     * ═════════════
     * Single JWK (JSON Web Key):
     * {
     *   "kty": "RSA",                    // Key Type
     *   "kid": "auth-service-key-2024",  // Key ID
     *   "alg": "RS256",                  // Algorithm
     *   "use": "sig",                    // Usage: signature
     *   "n": "xGOr1H7z...",              // Modulus (base64url)
     *   "e": "AQAB"                      // Exponent (base64url)
     * }
     *
     * JWKS structure (set of keys):
     * {
     *   "keys": [jwk1, jwk2, ...]
     * }
     *
     * Currently we have only one key, але structure
     * supports multiple keys (для rotation).
     *
     * RSA PUBLIC KEY COMPONENTS:
     * ═════════════════════════
     * RSA public key = (n, e)
     *
     * n (modulus):
     * - Large prime number product
     * - Usually 2048 bits
     * - Base64Url encoded для JWK
     *
     * e (exponent):
     * - Usually 65537 (0x010001)
     * - Small number, base64url: "AQAB"
     *
     * BASE64URL ENCODING:
     * ══════════════════
     * JWK requires base64url (RFC 4648):
     * - URL-safe characters
     * - No padding (no "=" at end)
     * - "-" instead of "+"
     * - "_" instead of "/"
     *
     * BigInteger → bytes → base64url
     *
     * @return JWKS map ready для JSON serialization
     */
    @Override
    public Map<String, Object> getJwks() {
        log.debug("Building JWKS response");

        // ════════════════════════════════════════
        // Step 1: Get RSA Public Key
        // ════════════════════════════════════════
        // Load від JwtConfig (already parsed від PEM)
        RSAPublicKey publicKey = jwtConfig.getPublicKey();

        // ════════════════════════════════════════
        // Step 2: Build JWK від Public Key
        // ════════════════════════════════════════
        // Extracts key components і formats як JWK
        Map<String, Object> jwk = buildJwk(publicKey);

        // ════════════════════════════════════════
        // Step 3: Wrap в JWKS Format
        // ════════════════════════════════════════
        // JWKS = {"keys": [jwk1, jwk2, ...]}
        // Currently single key, але supports multiple
        Map<String, Object> jwks = new HashMap<>();
        jwks.put("keys", List.of(jwk));  // Array з single JWK

        // Log key information для monitoring
        log.info("JWKS built successfully: kid={}, algorithm={}, keySize={} bits",
                jwk.get("kid"),
                jwk.get("alg"),
                publicKey.getModulus().bitLength());

        return jwks;
    }

    /**
     * Get JWKS Health Status
     *
     * Checks if keys loaded correctly.
     *
     * HEALTH CHECKS:
     * ═════════════
     * ✅ RSA keys loaded (not null)
     * ✅ Algorithm configured
     * ✅ Key size adequate (>= 2048 bits)
     * ✅ Key ID present
     * ✅ Issuer configured
     *
     * RESPONSE (healthy):
     * ══════════════════
     * {
     *   "status": "UP",
     *   "algorithm": "RS256",
     *   "keyId": "auth-service-key-2024",
     *   "keyBits": 2048,
     *   "issuer": "http://auth-service..."
     * }
     *
     * RESPONSE (unhealthy):
     * ════════════════════
     * {
     *   "status": "DOWN",
     *   "error": "Failed to load keys"
     * }
     *
     * HTTP STATUS:
     * ═══════════
     * Controller should return:
     * - 200 OK if status = UP
     * - 500 Internal Server Error if status = DOWN
     *
     * USE CASES:
     * ═════════
     * - Kubernetes liveness/readiness probes
     * - Monitoring systems (Prometheus, Grafana)
     * - Manual health verification
     * - Debugging key issues
     *
     * @return health status map
     */
    @Override
    public Map<String, Object> getHealthStatus() {
        log.debug("Checking JWKS health status");

        try {
            // ════════════════════════════════════════
            // Try to Access Public Key
            // ════════════════════════════════════════
            // If keys not loaded, this throws exception
            RSAPublicKey publicKey = jwtConfig.getPublicKey();

            // Get key size (bit length of modulus)
            int keyBits = publicKey.getModulus().bitLength();

            // ════════════════════════════════════════
            // Build Health Response (UP)
            // ════════════════════════════════════════
            Map<String, Object> health = new HashMap<>();
            health.put("status", "UP");
            health.put("algorithm", jwtConfig.getAlgorithm());
            health.put("keyId", getKeyId());
            health.put("keyBits", keyBits);
            health.put("issuer", jwtConfig.getIssuer());

            // ════════════════════════════════════════
            // Validate Key Size
            // ════════════════════════════════════════
            // Warn if less than 2048 bits (security concern)
            if (keyBits < 2048) {
                String warning = "Key size less than 2048 bits is not recommended";
                health.put("warning", warning);
                log.warn("⚠️  {}: keyBits={}", warning, keyBits);
            }

            log.debug("JWKS health check: OK - keyBits={}", keyBits);
            return health;

        } catch (Exception e) {
            // ════════════════════════════════════════
            // Build Health Response (DOWN)
            // ════════════════════════════════════════
            log.error("❌ JWKS health check failed", e);

            Map<String, Object> health = new HashMap<>();
            health.put("status", "DOWN");
            health.put("error", e.getMessage());

            return health;
        }
    }

    /**
     * Get Public Key Info
     *
     * Returns detailed public key information.
     *
     * USE CASE:
     * ════════
     * Debugging і verification purposes.
     * Shows raw key components.
     *
     * RESPONSE:
     * ════════
     * {
     *   "algorithm": "RS256",
     *   "keyId": "auth-service-key-2024",
     *   "modulus": "hex-encoded-modulus...",
     *   "exponent": "65537",
     *   "bitLength": 2048
     * }
     *
     * MODULUS FORMAT:
     * ══════════════
     * Displayed як hexadecimal string.
     * Very long (2048 bits = 256 bytes = 512 hex chars).
     *
     * SECURITY:
     * ════════
     * This is PUBLIC information - safe to expose.
     * Cannot derive private key від public key.
     *
     * However, consider disabling в production:
     * - Not needed для normal operations
     * - Reduces attack surface (principle of least privilege)
     * - Less information leakage
     *
     * @return public key info map
     */
    @Override
    public Map<String, Object> getPublicKeyInfo() {
        log.debug("Getting public key info");

        RSAPublicKey publicKey = jwtConfig.getPublicKey();

        // ════════════════════════════════════════
        // Build Key Info Response
        // ════════════════════════════════════════
        Map<String, Object> info = new HashMap<>();
        info.put("algorithm", jwtConfig.getAlgorithm());
        info.put("keyId", getKeyId());

        // Modulus (n) as hexadecimal string
        // toString(16) = convert to hex
        info.put("modulus", publicKey.getModulus().toString(16));

        // Exponent (e) as decimal string
        // Usually 65537
        info.put("exponent", publicKey.getPublicExponent().toString());

        // Key size in bits
        info.put("bitLength", publicKey.getModulus().bitLength());

        log.debug("Public key info retrieved: algorithm={}, keyBits={}",
                jwtConfig.getAlgorithm(),
                publicKey.getModulus().bitLength());

        return info;
    }

    /**
     * Build JWK від RSA Public Key
     *
     * Converts RSA public key → JWK format.
     *
     * PROCESS:
     * ═══════
     * 1. Create JWK map
     * 2. Add metadata (kty, kid, alg, use)
     * 3. Extract RSA components (n, e)
     * 4. Base64Url encode components
     * 5. Add encoded components до JWK
     * 6. Return JWK map
     *
     * JWK FIELDS:
     * ══════════
     *
     * kty (Key Type):
     * - "RSA" для RSA keys
     * - Other values: "EC" (Elliptic Curve), "oct" (symmetric)
     *
     * kid (Key ID):
     * - Unique identifier для this key
     * - Used для select key від JWKS (multiple keys)
     * - Format: "auth-service-key-2024"
     *
     * alg (Algorithm):
     * - "RS256" (RSA + SHA-256)
     * - Other values: "RS384", "RS512", "ES256", тощо
     *
     * use (Public Key Use):
     * - "sig" для signature keys
     * - "enc" для encryption keys
     * - We use "sig" (JWT signature validation)
     *
     * n (Modulus):
     * - RSA public key component 1
     * - Large number (2048 bits)
     * - Base64Url encoded
     *
     * e (Exponent):
     * - RSA public key component 2
     * - Usually 65537 (base64url: "AQAB")
     * - Base64Url encoded
     *
     * @param publicKey RSA public key
     * @return JWK map
     */
    private Map<String, Object> buildJwk(RSAPublicKey publicKey) {
        log.debug("Building JWK from RSA public key");

        // ════════════════════════════════════════
        // Create JWK Map
        // ════════════════════════════════════════
        Map<String, Object> jwk = new HashMap<>();

        // ════════════════════════════════════════
        // Add Metadata Fields
        // ════════════════════════════════════════
        jwk.put("kty", "RSA");                      // Key Type
        jwk.put("kid", getKeyId());                 // Key ID
        jwk.put("alg", jwtConfig.getAlgorithm());   // Algorithm (RS256)
        jwk.put("use", "sig");                      // Usage: signature

        // ════════════════════════════════════════
        // Extract RSA Components
        // ════════════════════════════════════════
        // n (modulus): large prime product
        BigInteger modulus = publicKey.getModulus();

        // e (exponent): usually 65537
        BigInteger exponent = publicKey.getPublicExponent();

        log.debug("RSA components extracted: modulusBits={}, exponent={}",
                modulus.bitLength(), exponent);

        // ════════════════════════════════════════
        // Encode Components (Base64Url)
        // ════════════════════════════════════════
        // JWK requires base64url encoding (no padding)
        jwk.put("n", encodeBase64Url(modulus));
        jwk.put("e", encodeBase64Url(exponent));

        log.debug("JWK built successfully: kid={}", getKeyId());

        return jwk;
    }

    /**
     * Get Key ID
     *
     * Returns unique identifier для this key.
     *
     * KEY ID FORMAT:
     * ═════════════
     * Pattern: {service}-key-{year}
     * Example: "auth-service-key-2024"
     *
     * PURPOSE:
     * ═══════
     * - Identifies which key signed token
     * - Enables key rotation (multiple active keys)
     * - Gateway uses для select key від JWKS
     *
     * ROTATION SCENARIO:
     * ════════════════
     * Year 2024:
     * - Key: auth-service-key-2024
     * - All tokens signed з this key
     *
     * Year 2025 (rotation):
     * - New key: auth-service-key-2025
     * - JWKS has both keys
     * - New tokens: signed з 2025 key
     * - Old tokens: still valid, validated з 2024 key
     * - After transition: remove 2024 key
     *
     * HARDCODED:
     * ═════════
     * Currently hardcoded string.
     *
     * Future improvements:
     * - Generate від key fingerprint (hash)
     * - Store в configuration
     * - Include timestamp (rotation tracking)
     *
     * @return key ID string
     */
    private String getKeyId() {
        return "auth-service-key-2024";
    }

    /**
     * Encode BigInteger to Base64Url
     *
     * Converts BigInteger → Base64Url string (JWK format).
     *
     * PROCESS:
     * ═══════
     * 1. Convert BigInteger → byte array
     * 2. Remove leading zero byte (if present)
     * 3. Base64Url encode bytes
     * 4. Return encoded string
     *
     * BASE64URL:
     * ═════════
     * RFC 4648 - URL-safe Base64:
     * - Uses "-" instead of "+"
     * - Uses "_" instead of "/"
     * - No padding (no "=" at end)
     *
     * Why no padding:
     * JWK standard omits padding для save space.
     * Decoder can infer padding від length.
     *
     * LEADING ZERO BYTE:
     * ═════════════════
     * BigInteger.toByteArray() може add leading zero.
     *
     * Why:
     * Java uses two's complement representation.
     * Leading zero indicates positive number.
     *
     * For cryptographic keys, leading zero unnecessary:
     * - RSA components always positive
     * - JWK format doesn't need sign bit
     * - Must remove для correct encoding
     *
     * Detection:
     * If first byte is 0x00, remove it.
     *
     * Example:
     * Before: [0x00, 0xAB, 0xCD, 0xEF]
     * After:  [0xAB, 0xCD, 0xEF]
     *
     * @param value BigInteger to encode
     * @return base64url encoded string
     */
    private String encodeBase64Url(BigInteger value) {
        log.trace("Encoding BigInteger to Base64Url: bitLength={}",
                value.bitLength());

        // ════════════════════════════════════════
        // Step 1: Convert to Byte Array
        // ════════════════════════════════════════
        // BigInteger → byte[] (big-endian, two's complement)
        byte[] bytes = value.toByteArray();

        log.trace("Byte array length: {} bytes", bytes.length);

        // ════════════════════════════════════════
        // Step 2: Remove Leading Zero (if present)
        // ════════════════════════════════════════
        // Check if first byte is 0x00 (sign bit)
        if (bytes.length > 0 && bytes[0] == 0) {
            log.trace("Removing leading zero byte");

            // Create new array without first byte
            byte[] tmp = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, tmp, 0, tmp.length);
            bytes = tmp;
        }

        // ════════════════════════════════════════
        // Step 3: Base64Url Encode
        // ════════════════════════════════════════
        // Java 8+ Base64.getUrlEncoder():
        // - URL-safe characters (- and _)
        // - withoutPadding(): omits "=" padding
        String encoded = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(bytes);

        log.trace("Base64Url encoded: {} characters", encoded.length());

        return encoded;
    }
}