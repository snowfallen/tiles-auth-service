package com.tiles.auth.service;

import java.util.Map;

/**
 * JWKS Service Interface
 *
 * Defines contract для JWKS (JSON Web Key Set) operations.
 *
 * RESPONSIBILITIES:
 * ═══════════════
 * - Build JWK від RSA public key
 * - Format JWKS response
 * - Health check для JWKS endpoint
 * - Public key info (debugging)
 *
 * JWKS STANDARD:
 * ═════════════
 * JWKS = JSON Web Key Set (RFC 7517)
 * Standard format для публікації public keys.
 *
 * Used by:
 * - OAuth2 / OpenID Connect
 * - JWT validation
 * - Key rotation
 *
 * FORMAT:
 * ══════
 * {
 *   "keys": [
 *     {
 *       "kty": "RSA",
 *       "kid": "auth-service-key-2024",
 *       "alg": "RS256",
 *       "use": "sig",
 *       "n": "modulus-base64url...",
 *       "e": "exponent-base64url..."
 *     }
 *   ]
 * }
 *
 * USAGE:
 * ═════
 * Gateway fetches JWKS:
 * 1. GET /.well-known/jwks.json
 * 2. Extract "n" и "e" від first key
 * 3. Reconstruct RSA public key
 * 4. Cache key (24 hours)
 * 5. Use для JWT validation
 *
 * @author snowfallen
 * @version 1.0.0
 * @since 2024-10-31
 */
public interface JwksService {

    /**
     * Get JWKS (JSON Web Key Set)
     *
     * Builds JWKS response з RSA public key.
     *
     * RESPONSE:
     * ════════
     * {
     *   "keys": [
     *     {
     *       "kty": "RSA",                    // Key type
     *       "kid": "auth-service-key-2024",  // Key ID
     *       "alg": "RS256",                  // Algorithm
     *       "use": "sig",                    // Usage: signature
     *       "n": "xGOr1H7z...",              // Modulus (base64url)
     *       "e": "AQAB"                      // Exponent (base64url, usually 65537)
     *     }
     *   ]
     * }
     *
     * JWK FIELDS:
     * ══════════
     * - kty: Key Type (RSA для нас)
     * - kid: Key ID (identifier для multiple keys)
     * - alg: Algorithm (RS256, RS384, RS512)
     * - use: Usage (sig=signature, enc=encryption)
     * - n: RSA modulus (public key component 1)
     * - e: RSA exponent (public key component 2)
     *
     * BASE64URL ENCODING:
     * ══════════════════
     * JWK standard requires base64url (RFC 4648):
     * - No padding (no "=" at end)
     * - URL-safe characters (- instead of +, _ instead of /)
     *
     * @return JWKS map
     */
    Map<String, Object> getJwks();

    /**
     * Get JWKS Health Status
     *
     * Checks if keys loaded і valid.
     *
     * CHECKS:
     * ══════
     * ✅ RSA keys loaded
     * ✅ Algorithm configured
     * ✅ Key size adequate (>= 2048 bits)
     * ✅ Issuer configured
     *
     * RESPONSE (success):
     * ══════════════════
     * {
     *   "status": "UP",
     *   "algorithm": "RS256",
     *   "keyId": "auth-service-key-2024",
     *   "keyBits": 2048,
     *   "issuer": "http://auth-service..."
     * }
     *
     * RESPONSE (failure):
     * ══════════════════
     * {
     *   "status": "DOWN",
     *   "error": "Failed to load keys"
     * }
     *
     * USE CASES:
     * ═════════
     * - Monitoring (Kubernetes health checks)
     * - Debugging (verify keys loaded)
     * - Alerting (notify if DOWN)
     *
     * @return health status map
     */
    Map<String, Object> getHealthStatus();

    /**
     * Get Public Key Info
     *
     * Returns detailed public key information.
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
     * USE CASES:
     * ═════════
     * - Debugging
     * - Key verification
     * - Security auditing
     *
     * SECURITY:
     * ════════
     * This is public information (public key).
     * Safe to expose - cannot derive private key від this.
     *
     * Note: Consider disabling в production
     * (not needed, reduces attack surface).
     *
     * @return public key info map
     */
    Map<String, Object> getPublicKeyInfo();
}
