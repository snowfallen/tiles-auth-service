package com.tiles.auth.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * JWKS (JSON Web Key Set) Controller
 *
 * Provides public key endpoint for JWT validation.
 *
 * Endpoint: GET /.well-known/jwks.json
 *
 * JWKS = Standard format для публікації public keys.
 * OAuth2/OpenID Connect standard.
 *
 * Gateway використовує цей endpoint для:
 * 1. Fetch public key
 * 2. Cache public key
 * 3. Validate JWT signatures
 *
 * Note: Ми використовуємо HMAC (HS256), тому "public key" = shared secret hash.
 * У production з RS256 це буде справжній RSA public key.
 */
@RestController
@RequestMapping("/.well-known")
@RequiredArgsConstructor
@Slf4j
public class JwksController {

    @Value("${jwt.secret}")
    private String jwtSecret;

    /**
     * JWKS Endpoint
     *
     * GET /.well-known/jwks.json
     *
     * Returns JSON Web Key Set.
     *
     * Response format (JWK Set standard):
     * {
     *   "keys": [
     *     {
     *       "kty": "oct",              // Key type (octet sequence for HMAC)
     *       "kid": "auth-service-key", // Key ID (identifier)
     *       "alg": "HS256",            // Algorithm
     *       "k": "base64-encoded-key"  // Key value (base64url)
     *     }
     *   ]
     * }
     *
     * Note: В production з RS256:
     * {
     *   "keys": [
     *     {
     *       "kty": "RSA",
     *       "kid": "key-2024-10",
     *       "alg": "RS256",
     *       "use": "sig",
     *       "n": "modulus...",    // RSA public key modulus
     *       "e": "exponent..."    // RSA public key exponent
     *     }
     *   ]
     * }
     */
    @GetMapping("/jwks.json")
    public ResponseEntity<Map<String, Object>> getJwks() {
        log.debug("JWKS endpoint called");

        // Build JWK (JSON Web Key)
        Map<String, Object> jwk = new HashMap<>();
        jwk.put("kty", "oct");  // Key type: octet sequence (symmetric key)
        jwk.put("kid", "auth-service-key");  // Key ID
        jwk.put("alg", "HS256");  // Algorithm
        jwk.put("use", "sig");  // Key usage: signature

        // Encode secret as base64url (JWK standard)
        String encodedSecret = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(jwtSecret.getBytes(StandardCharsets.UTF_8));
        jwk.put("k", encodedSecret);

        // Build JWKS (JSON Web Key Set)
        Map<String, Object> jwks = new HashMap<>();
        jwks.put("keys", List.of(jwk));

        return ResponseEntity.ok(jwks);
    }

    /**
     * Alternative: Public Key Hash Endpoint
     *
     * GET /.well-known/public-key
     *
     * Спрощений endpoint для нашого use case.
     * Повертає SHA-256 hash секрета.
     *
     * Gateway може використовувати це для верифікації
     * що має правильний secret.
     *
     * Response:
     * {
     *   "algorithm": "HS256",
     *   "keyId": "auth-service-key",
     *   "keyHash": "sha256-hash-of-secret"
     * }
     */
    @GetMapping("/public-key")
    public ResponseEntity<Map<String, String>> getPublicKeyHash() {
        log.debug("Public key hash endpoint called");

        try {
            // Calculate SHA-256 hash секрета
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(jwtSecret.getBytes(StandardCharsets.UTF_8));
            String hashHex = bytesToHex(hash);

            Map<String, String> response = new HashMap<>();
            response.put("algorithm", "HS256");
            response.put("keyId", "auth-service-key");
            response.put("keyHash", hashHex);

            return ResponseEntity.ok(response);

        } catch (NoSuchAlgorithmException e) {
            log.error("Error calculating key hash", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * Helper: Convert bytes to hex string
     */
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
