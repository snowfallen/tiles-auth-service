package com.tiles.auth.controller;

import com.tiles.auth.service.JwksService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * JWKS Controller
 *
 * Publishes JSON Web Key Set для JWT signature validation.
 *
 * JWKS STANDARD:
 * ═════════════
 * JWKS = JSON Web Key Set (RFC 7517)
 *
 * Standard way to publish public cryptographic keys.
 * Used by OAuth2, OpenID Connect, JWT validation.
 *
 * PURPOSE:
 * ═══════
 * Auth Service signs JWTs з private key.
 * Gateway needs public key для validation.
 *
 * Flow:
 * 1. Auth Service generates JWT (signs з private key)
 * 2. Gateway fetches public key (від JWKS endpoint)
 * 3. Gateway validates JWT signature (з public key)
 * 4. If valid → request allowed
 *
 * WELL-KNOWN PATH:
 * ═══════════════
 * Standard path: /.well-known/jwks.json
 *
 * Convention від OAuth2/OpenID Connect.
 * Clients know where to find public keys.
 *
 * Example URLs:
 * - http://auth-service:8084/.well-known/jwks.json
 * - https://auth.example.com/.well-known/jwks.json
 *
 * PUBLIC ENDPOINT:
 * ═══════════════
 * No authentication required.
 * Public keys = public information.
 *
 * Security considerations:
 * ✅ Safe to expose (public key cryptography)
 * ✅ Cannot derive private key від public key
 * ✅ Read-only (GET only)
 * ✅ Rate limiting (prevent abuse)
 *
 * CACHING:
 * ═══════
 * Gateway should cache JWKS response.
 *
 * Recommended:
 * - TTL: 24 hours (keys rarely change)
 * - Refresh: On validation failure (key rotation)
 * - Invalidate: On 401 error (key changed)
 *
 * Benefits:
 * ✅ Reduced latency (no network call)
 * ✅ Reduced load (less requests)
 * ✅ Offline validation (cache valid)
 *
 * KEY ROTATION:
 * ════════════
 * If keys rotated (rare):
 * 1. Add new key до JWKS (keep old)
 * 2. Start signing з new key (new kid)
 * 3. Gateway fetches JWKS, gets both keys
 * 4. Old tokens validated з old key
 * 5. New tokens validated з new key
 * 6. After transition, remove old key
 *
 * JWKS supports multiple keys (array).
 *
 * ENDPOINTS:
 * ═════════
 * GET /.well-known/jwks.json → JWKS (standard)
 * GET /jwks/health → Health check
 * GET /jwks/public-key → Key info (debugging)
 *
 * MEDIA TYPE:
 * ══════════
 * Content-Type: application/json
 *
 * Standard JSON response.
 *
 * @author snowfallen
 * @version 1.0.0
 * @since 2024-10-31
 */
@RestController
@RequestMapping
@RequiredArgsConstructor
@Slf4j
public class JwksController {

    /**
     * JWKS Service
     *
     * Business logic для JWKS operations.
     *
     * Provides:
     * - getJwks(): Build JWKS від RSA keys
     * - getHealthStatus(): Health check
     * - getPublicKeyInfo(): Key information
     */
    private final JwksService jwksService;

    /**
     * Get JWKS Endpoint
     *
     * Returns JSON Web Key Set з RSA public key.
     *
     * ENDPOINT:
     * ════════
     * GET /.well-known/jwks.json
     *
     * Standard OAuth2/OpenID Connect path.
     *
     * RESPONSE:
     * ════════
     * HTTP 200 OK
     * Content-Type: application/json
     *
     * {
     *   "keys": [
     *     {
     *       "kty": "RSA",
     *       "kid": "auth-service-key-2024",
     *       "alg": "RS256",
     *       "use": "sig",
     *       "n": "xGOr1H7zN9yDi0RvF8u5jY3pKZ...",  // Modulus (base64url)
     *       "e": "AQAB"  // Exponent (base64url, usually 65537)
     *     }
     *   ]
     * }
     *
     * JWKS STRUCTURE:
     * ══════════════
     * Root object:
     * - keys: Array of JWK objects
     *
     * Single JWK object:
     * - kty: Key type ("RSA")
     * - kid: Key ID ("auth-service-key-2024")
     * - alg: Algorithm ("RS256")
     * - use: Usage ("sig" для signature)
     * - n: Modulus (RSA public key component 1)
     * - e: Exponent (RSA public key component 2)
     *
     * GATEWAY USAGE:
     * ═════════════
     * Gateway JWT validation process:
     *
     * 1. Extract JWT від Authorization header:
     *    Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
     *
     * 2. Decode JWT header (без validation):
     *    {
     *      "alg": "RS256",
     *      "typ": "JWT",
     *      "kid": "auth-service-key-2024"
     *    }
     *
     * 3. Fetch JWKS від Auth Service:
     *    GET http://auth-service:8084/.well-known/jwks.json
     *
     * 4. Find key з matching kid:
     *    keys.find(k => k.kid === "auth-service-key-2024")
     *
     * 5. Reconstruct RSA public key від n і e:
     *    - Decode base64url → bytes
     *    - Create RSAPublicKey(modulus, exponent)
     *
     * 6. Verify JWT signature:
     *    - Extract signature від JWT
     *    - Verify з public key
     *    - If valid → JWT authentic
     *
     * 7. Validate claims:
     *    - exp: Not expired
     *    - iss: Correct issuer
     *    - aud: Correct audience (if present)
     *
     * 8. Extract user info від claims:
     *    - sub: User ID
     *    - username: Username
     *    - roles: User roles
     *
     * 9. Forward request з user context:
     *    X-User-Id: 550e8400-...
     *    X-Username: admin
     *    X-Roles: USER,ADMIN
     *
     * CACHING:
     * ═══════
     * Gateway should cache JWKS response.
     *
     * Spring Cloud Gateway example:
     *
     * @Bean
     * public JwksClient jwksClient() {
     *     return JwksClient.builder()
     *         .jwksUrl("http://auth-service:8084/.well-known/jwks.json")
     *         .cacheDuration(Duration.ofHours(24))  // 24h cache
     *         .build();
     * }
     *
     * Cache invalidation:
     * - TTL expires (24 hours)
     * - Validation fails (signature error)
     * - Unknown kid (new key added)
     *
     * KEY ROTATION:
     * ════════════
     * Supporting multiple keys:
     *
     * {
     *   "keys": [
     *     {
     *       "kid": "auth-service-key-2024",
     *       "kty": "RSA",
     *       "alg": "RS256",
     *       "use": "sig",
     *       "n": "...",
     *       "e": "AQAB"
     *     },
     *     {
     *       "kid": "auth-service-key-2025",  // New key
     *       "kty": "RSA",
     *       "alg": "RS256",
     *       "use": "sig",
     *       "n": "...",
     *       "e": "AQAB"
     *     }
     *   ]
     * }
     *
     * Gateway uses kid від JWT header to select key.
     *
     * Rotation process:
     * 1. Generate new key pair
     * 2. Add new key до JWKS (keep old)
     * 3. Update Auth Service (start signing з new key)
     * 4. Gateway fetches JWKS (gets both keys)
     * 5. Old tokens: Validated з old key
     * 6. New tokens: Validated з new key
     * 7. Wait до all old tokens expired (15 min)
     * 8. Remove old key від JWKS
     *
     * SECURITY:
     * ════════
     * Public key = safe to expose:
     * ✅ Cannot derive private key
     * ✅ One-way cryptography
     * ✅ Read-only endpoint
     *
     * Best practices:
     * ✅ HTTPS (prevent MITM)
     * ✅ Rate limiting (prevent abuse)
     * ✅ Monitoring (detect unusual traffic)
     * ✅ CORS (control access)
     *
     * Threats:
     * ⚠️  MITM attack (serve fake key)
     *    → Mitigation: HTTPS, certificate pinning
     * ⚠️  DoS attack (spam requests)
     *    → Mitigation: Rate limiting, caching
     *
     * PERFORMANCE:
     * ═══════════
     * Very fast:
     * - No database queries
     * - No Redis queries
     * - Just build JSON від loaded keys
     *
     * Can handle thousands requests/second.
     *
     * MONITORING:
     * ══════════
     * Log metrics:
     * - Request count
     * - Response time
     * - Error rate
     * - Cache hit rate (Gateway side)
     *
     * Alerts:
     * - High error rate (key loading failed)
     * - Unusual traffic (potential attack)
     * - Gateway unable to fetch (network issue)
     *
     * TESTING:
     * ═══════
     * curl example:
     *
     * curl http://localhost:8084/.well-known/jwks.json
     *
     * Expected output:
     * {
     *   "keys": [
     *     {
     *       "kty": "RSA",
     *       "kid": "auth-service-key-2024",
     *       "alg": "RS256",
     *       "use": "sig",
     *       "n": "xGOr1H7zN9yD...",
     *       "e": "AQAB"
     *     }
     *   ]
     * }
     *
     * Validation:
     * ✅ Returns 200 OK
     * ✅ Content-Type: application/json
     * ✅ Has "keys" array
     * ✅ Each key has required fields (kty, kid, alg, use, n, e)
     * ✅ n і e are base64url encoded
     *
     * DEBUGGING:
     * ═════════
     * Decode JWT header to see kid:
     *
     * echo "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImF1dGgtc2VydmljZS1rZXktMjAyNCJ9" | base64 -d
     * → {"alg":"RS256","typ":"JWT","kid":"auth-service-key-2024"}
     *
     * Check if kid matches JWKS:
     * curl http://localhost:8084/.well-known/jwks.json | jq '.keys[].kid'
     * → "auth-service-key-2024"
     *
     * DOCUMENTATION:
     * ═════════════
     * Document в API docs:
     * - Endpoint URL
     * - Response format
     * - Caching recommendations
     * - Key rotation process
     * - Contact для key issues
     *
     * @return JWKS з RSA public key
     */
    @GetMapping(
            path = "/.well-known/jwks.json",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<Map<String, Object>> getJwks() {
        log.debug("JWKS request received");

        // Get JWKS від service
        // Service builds JWK від RSA public key
        Map<String, Object> jwks = jwksService.getJwks();

        log.debug("JWKS response sent: {} keys",
                ((java.util.List<?>) jwks.get("keys")).size());

        // Return 200 OK з JWKS
        // Content-Type: application/json (automatic)
        return ResponseEntity.ok(jwks);
    }

    /**
     * JWKS Health Check Endpoint
     *
     * Checks if keys loaded correctly.
     *
     * ENDPOINT:
     * ════════
     * GET /jwks/health
     *
     * RESPONSE (healthy):
     * ══════════════════
     * HTTP 200 OK
     * Content-Type: application/json
     *
     * {
     *   "status": "UP",
     *   "algorithm": "RS256",
     *   "keyId": "auth-service-key-2024",
     *   "keyBits": 2048,
     *   "issuer": "http://auth-service:8084"
     * }
     *
     * RESPONSE (unhealthy):
     * ════════════════════
     * HTTP 500 Internal Server Error
     * Content-Type: application/json
     *
     * {
     *   "status": "DOWN",
     *   "error": "Failed to load keys"
     * }
     *
     * HEALTH CHECKS:
     * ═════════════
     * Verifies:
     * ✅ RSA keys loaded (not null)
     * ✅ Algorithm configured
     * ✅ Key size adequate (>= 2048 bits)
     * ✅ Key ID present
     * ✅ Issuer configured
     *
     * USE CASES:
     * ═════════
     * Kubernetes liveness/readiness probes:
     *
     * livenessProbe:
     *   httpGet:
     *     path: /jwks/health
     *     port: 8084
     *   initialDelaySeconds: 30
     *   periodSeconds: 10
     *
     * readinessProbe:
     *   httpGet:
     *     path: /jwks/health
     *     port: 8084
     *   initialDelaySeconds: 5
     *   periodSeconds: 5
     *
     * Monitoring systems:
     * - Prometheus: Scrape /actuator/health
     * - Custom monitoring: Poll /jwks/health
     *
     * Manual verification:
     * - Startup check (keys loaded?)
     * - Deployment verification
     * - Troubleshooting
     *
     * RESPONSE CODES:
     * ══════════════
     * 200 OK:
     * - Keys loaded successfully
     * - Ready to serve JWKS
     * - Can issue і validate JWTs
     *
     * 500 Internal Server Error:
     * - Keys failed to load
     * - Configuration error
     * - Cannot issue JWTs
     * - Service unhealthy
     *
     * COMMON ISSUES:
     * ═════════════
     *
     * Keys not found:
     * - Check application.yml (jwt.public-key, jwt.private-key)
     * - Check file paths (src/main/resources/certs/)
     * - Check file permissions (readable)
     *
     * Invalid key format:
     * - Check PEM format (BEGIN/END markers)
     * - Check key type (RSA, not EC)
     * - Check encoding (UTF-8)
     *
     * Key size too small:
     * - Minimum 2048 bits
     * - Recommended 4096 bits
     * - Generate new keys if needed
     *
     * MONITORING:
     * ══════════
     * Alert on:
     * - status: DOWN (critical)
     * - keyBits < 2048 (warning)
     * - Response time > 1s (warning)
     *
     * TESTING:
     * ═══════
     * curl example:
     *
     * curl http://localhost:8084/jwks/health
     *
     * Expected output (healthy):
     * {
     *   "status": "UP",
     *   "algorithm": "RS256",
     *   "keyId": "auth-service-key-2024",
     *   "keyBits": 2048,
     *   "issuer": "http://auth-service:8084"
     * }
     *
     * @return Health status map
     */
    @GetMapping(
            path = "/jwks/health",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<Map<String, Object>> getHealth() {
        log.debug("JWKS health check request");

        // Get health status від service
        Map<String, Object> health = jwksService.getHealthStatus();

        // Extract status
        String status = (String) health.get("status");

        // Determine HTTP status code
        // UP → 200 OK
        // DOWN → 500 Internal Server Error
        if ("UP".equals(status)) {
            log.debug("JWKS health check: OK");
            return ResponseEntity.ok(health);
        } else {
            log.error("JWKS health check: FAILED - {}", health.get("error"));
            return ResponseEntity
                    .status(500)
                    .body(health);
        }
    }

    /**
     * Public Key Info Endpoint
     *
     * Returns detailed public key information.
     *
     * ENDPOINT:
     * ════════
     * GET /jwks/public-key
     *
     * RESPONSE:
     * ════════
     * HTTP 200 OK
     * Content-Type: application/json
     *
     * {
     *   "algorithm": "RS256",
     *   "keyId": "auth-service-key-2024",
     *   "modulus": "c463abd47ef337dc83...",  // Hex string (very long)
     *   "exponent": "65537",
     *   "bitLength": 2048
     * }
     *
     * DETAILED INFO:
     * ═════════════
     * More detailed than health check:
     * - algorithm: RS256
     * - keyId: Key identifier
     * - modulus: Full modulus (hex)
     * - exponent: Public exponent (decimal)
     * - bitLength: Key size в bits
     *
     * USE CASES:
     * ═════════
     * Debugging:
     * - Verify key loaded correctly
     * - Check key size
     * - Compare з expected values
     * - Troubleshoot signature validation
     *
     * Development:
     * - Inspect key details
     * - Compare keys (old vs new)
     * - Verify key rotation
     *
     * Documentation:
     * - Show key fingerprint
     * - Display key metadata
     * - Reference в docs
     *
     * SECURITY:
     * ════════
     * Public key information = safe to expose.
     * Cannot derive private key від public key.
     *
     * However, consider:
     * ⚠️  Disable в production (optional)
     * ⚠️  Less information leakage
     * ⚠️  Principle of least privilege
     *
     * If disable:
     * @Profile("dev")  // Only в development
     * @GetMapping("/jwks/public-key")
     *
     * MODULUS FORMAT:
     * ══════════════
     * Displayed як hexadecimal string.
     * Very long (2048 bits = 256 bytes = 512 hex chars).
     *
     * Example (shortened):
     * "c463abd47ef337dc838b446f17cbb98d8dep..."
     *
     * Full length: 512 characters
     *
     * EXPONENT:
     * ════════
     * Usually 65537 (0x010001).
     * Standard RSA public exponent.
     *
     * Small number, easy to read.
     *
     * COMPARISON:
     * ══════════
     * JWKS endpoint vs Public Key Info:
     *
     * JWKS (/.well-known/jwks.json):
     * - Standard format (RFC 7517)
     * - Base64url encoded (n, e)
     * - Gateway-friendly
     * - Production use
     *
     * Public Key Info (/jwks/public-key):
     * - Custom format
     * - Hex modulus, decimal exponent
     * - Human-readable
     * - Debugging only
     *
     * TESTING:
     * ═══════
     * curl example:
     *
     * curl http://localhost:8084/jwks/public-key
     *
     * Expected output:
     * {
     *   "algorithm": "RS256",
     *   "keyId": "auth-service-key-2024",
     *   "modulus": "c463abd47ef337dc83...",
     *   "exponent": "65537",
     *   "bitLength": 2048
     * }
     *
     * Verification:
     * ✅ Returns 200 OK
     * ✅ algorithm: "RS256"
     * ✅ keyId: Matches JWKS
     * ✅ modulus: Long hex string (512 chars)
     * ✅ exponent: Usually "65537"
     * ✅ bitLength: >= 2048
     *
     * @return Public key information map
     */
    @GetMapping(
            path = "/jwks/public-key",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<Map<String, Object>> getPublicKeyInfo() {
        log.debug("Public key info request");

        // Get key info від service
        Map<String, Object> keyInfo = jwksService.getPublicKeyInfo();

        log.debug("Public key info sent: algorithm={}, keyBits={}",
                keyInfo.get("algorithm"),
                keyInfo.get("bitLength"));

        // Return 200 OK з key info
        return ResponseEntity.ok(keyInfo);
    }
}
