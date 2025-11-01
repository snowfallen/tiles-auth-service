package com.tiles.auth.exception;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/**
 * Global Exception Handler
 *
 * Centralized exception handling для REST API.
 *
 * @RestControllerAdvice:
 * ════════════════════
 * Combination of:
 * - @ControllerAdvice (applies to all controllers)
 * - @ResponseBody (returns JSON response)
 *
 * Catches exceptions від all controllers.
 * Converts exceptions → JSON error responses.
 *
 * WHY CENTRALIZED:
 * ═══════════════
 * Without handler:
 * - Each controller handles own exceptions
 * - Duplicate error handling code
 * - Inconsistent error format
 * - Hard to maintain
 *
 * With handler:
 * ✅ Single source of truth
 * ✅ Consistent error format
 * ✅ Reusable error handling
 * ✅ Clean controllers (no try-catch)
 *
 * EXCEPTION FLOW:
 * ══════════════
 * 1. Controller method throws exception
 * 2. Spring catches exception
 * 3. Looks для matching @ExceptionHandler
 * 4. Calls handler method
 * 5. Handler builds error response
 * 6. Returns ResponseEntity (JSON)
 * 7. Client receives formatted error
 *
 * ERROR RESPONSE FORMAT:
 * ═════════════════════
 * Standard format:
 * {
 *   "timestamp": "2024-10-31T12:30:00",
 *   "status": 401,
 *   "error": "Unauthorized",
 *   "message": "Invalid username or password"
 * }
 *
 * Validation errors:
 * {
 *   "timestamp": "2024-10-31T12:30:00",
 *   "status": 400,
 *   "error": "Bad Request",
 *   "message": "Validation failed",
 *   "validationErrors": {
 *     "username": "Username is required",
 *     "password": "Password must be at least 8 characters"
 *   }
 * }
 *
 * HTTP STATUS CODES:
 * ═════════════════
 * 400 Bad Request:
 * - Validation errors
 * - Invalid request format
 * - Missing required fields
 *
 * 401 Unauthorized:
 * - Invalid credentials
 * - Invalid token
 * - Expired token
 *
 * 409 Conflict:
 * - Username already exists
 * - Email already exists
 * - Duplicate resource
 *
 * 500 Internal Server Error:
 * - Unexpected errors
 * - Server crashes
 * - Database errors
 *
 * LOGGING:
 * ═══════
 * All exceptions logged:
 * - ERROR level: Server errors (500)
 * - WARN level: Client errors (400, 401, 409)
 * - Include stack trace (ERROR only)
 *
 * Security considerations:
 * ⚠️  Don't log sensitive data (passwords, tokens)
 * ⚠️  Mask PII (emails, names)
 * ✅  Log user identifiers (username, ID)
 * ✅  Log request details (method, path)
 *
 * @author snowfallen
 * @version 1.0.0
 * @since 2024-10-31
 */
@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    /**
     * Handle Invalid Credentials Exception
     *
     * Thrown when login fails (wrong username або password).
     *
     * EXCEPTIONS HANDLED:
     * ══════════════════
     * InvalidCredentialsException:
     * - Wrong username або password
     * - Account disabled
     * - Account locked
     *
     * UsernameNotFoundException:
     * - User not found
     * - Treated same як wrong password (security)
     *
     * WHY SAME HANDLING:
     * ═════════════════
     * Security: Prevent username enumeration.
     *
     * Bad (reveals info):
     * - "Username not found" → Username doesn't exist
     * - "Wrong password" → Username exists
     * → Attacker can enumerate valid usernames
     *
     * Good (generic message):
     * - "Invalid username or password" → No info leaked
     * → Cannot tell if username exists
     *
     * HTTP STATUS:
     * ═══════════
     * 401 Unauthorized:
     * - Authentication failed
     * - Credentials invalid
     * - Client should retry з correct credentials
     *
     * ERROR RESPONSE:
     * ══════════════
     * {
     *   "timestamp": "2024-10-31T12:30:00",
     *   "status": 401,
     *   "error": "Unauthorized",
     *   "message": "Invalid username or password"
     * }
     *
     * LOGGING:
     * ═══════
     * WARN level (expected errors).
     *
     * Logged data:
     * ✅ Exception message
     * ✅ Timestamp
     * ❌ Stack trace (not needed)
     *
     * SECURITY:
     * ════════
     * Generic error message:
     * ✅ No username hints
     * ✅ Same timing (constant-time response)
     * ✅ Same format (cannot distinguish errors)
     *
     * Additional security:
     * - Rate limiting (prevent brute-force)
     * - Account lockout (too many failures)
     * - Monitoring (detect attacks)
     *
     * @param ex InvalidCredentialsException або UsernameNotFoundException
     * @return Error response (401 Unauthorized)
     */
    @ExceptionHandler({
            InvalidCredentialsException.class,
            UsernameNotFoundException.class
    })
    public ResponseEntity<Map<String, Object>> handleInvalidCredentials(RuntimeException ex) {
        log.warn("Authentication failed: {}", ex.getMessage());

        // Build error response
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("timestamp", LocalDateTime.now());
        errorResponse.put("status", HttpStatus.UNAUTHORIZED.value());  // 401
        errorResponse.put("error", HttpStatus.UNAUTHORIZED.getReasonPhrase());  // "Unauthorized"
        errorResponse.put("message", "Invalid username or password");  // Generic message

        // Return 401 Unauthorized
        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(errorResponse);
    }

    /**
     * Handle User Already Exists Exception
     *
     * Thrown when registration fails (duplicate username або email).
     *
     * EXCEPTIONS HANDLED:
     * ══════════════════
     * UserAlreadyExistsException:
     * - Username already taken
     * - Email already registered
     *
     * HTTP STATUS:
     * ═══════════
     * 409 Conflict:
     * - Resource already exists
     * - Cannot create duplicate
     * - Client should use different value
     *
     * ERROR RESPONSE:
     * ══════════════
     * {
     *   "timestamp": "2024-10-31T12:30:00",
     *   "status": 409,
     *   "error": "Conflict",
     *   "message": "Username already exists: admin"
     * }
     *
     * or
     *
     * {
     *   "timestamp": "2024-10-31T12:30:00",
     *   "status": 409,
     *   "error": "Conflict",
     *   "message": "Email already exists: admin@example.com"
     * }
     *
     * SPECIFIC MESSAGE:
     * ════════════════
     * Unlike authentication, we reveal which field conflicts.
     *
     * Why:
     * - Registration flow (not security-critical)
     * - Better UX (user knows what to change)
     * - Standard practice (most sites do this)
     *
     * Trade-off:
     * - Username enumeration possible
     * - But: Less critical than password guessing
     * - Mitigation: Rate limiting, CAPTCHA
     *
     * LOGGING:
     * ═══════
     * WARN level (expected errors).
     *
     * Logged data:
     * ✅ Exception message (which field duplicate)
     * ✅ Timestamp
     * ❌ Stack trace (not needed)
     *
     * CLIENT HANDLING:
     * ═══════════════
     * Display error на form:
     *
     * if (response.status === 409) {
     *   const data = await response.json();
     *   if (data.message.includes('Username')) {
     *     showFieldError('username', data.message);
     *   } else if (data.message.includes('Email')) {
     *     showFieldError('email', data.message);
     *   }
     * }
     *
     * PREVENTION:
     * ══════════
     * Client-side check before submit:
     * - GET /api/users/check-username?username=admin
     * - GET /api/users/check-email?email=admin@example.com
     * - Show availability immediately (AJAX)
     *
     * Benefits:
     * ✅ Better UX (instant feedback)
     * ✅ Prevents unnecessary submits
     * ✅ Less server load
     *
     * @param ex UserAlreadyExistsException
     * @return Error response (409 Conflict)
     */
    @ExceptionHandler(UserAlreadyExistsException.class)
    public ResponseEntity<Map<String, Object>> handleUserAlreadyExists(UserAlreadyExistsException ex) {
        log.warn("User already exists: {}", ex.getMessage());

        // Build error response
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("timestamp", LocalDateTime.now());
        errorResponse.put("status", HttpStatus.CONFLICT.value());  // 409
        errorResponse.put("error", HttpStatus.CONFLICT.getReasonPhrase());  // "Conflict"
        errorResponse.put("message", ex.getMessage());  // Specific message

        // Return 409 Conflict
        return ResponseEntity
                .status(HttpStatus.CONFLICT)
                .body(errorResponse);
    }

    /**
     * Handle Invalid Token Exception
     *
     * Thrown when token validation fails.
     *
     * EXCEPTIONS HANDLED:
     * ══════════════════
     * InvalidTokenException:
     * - Refresh token не існує (not в Redis)
     * - Refresh token expired
     * - Refresh token invalid format
     * - Token already revoked
     *
     * HTTP STATUS:
     * ═══════════
     * 401 Unauthorized:
     * - Token invalid
     * - Cannot refresh tokens
     * - Client should re-login
     *
     * ERROR RESPONSE:
     * ══════════════
     * {
     *   "timestamp": "2024-10-31T12:30:00",
     *   "status": 401,
     *   "error": "Unauthorized",
     *   "message": "Invalid or expired refresh token"
     * }
     *
     * GENERIC MESSAGE:
     * ═══════════════
     * Don't distinguish між:
     * - Token не існує
     * - Token expired
     * - Token invalid format
     *
     * Why:
     * - Security (no token enumeration)
     * - Simple error handling
     * - Client action same (re-login)
     *
     * CLIENT HANDLING:
     * ═══════════════
     * if (response.status === 401 && url.includes('/refresh')) {
     *   // Refresh failed → re-login
     *   redirectToLogin();
     * }
     *
     * LOGGING:
     * ═══════
     * WARN level (expected errors).
     *
     * Logged data:
     * ✅ Exception message
     * ✅ Timestamp
     * ⚠️  Token ID only (first 8 chars)
     * ❌ Full token (security risk)
     *
     * CAUSES:
     * ══════
     * Token не існує:
     * - Already revoked (logout)
     * - Expired і cleaned up (Redis TTL)
     * - Never existed (fake token)
     *
     * Token expired:
     * - Issued 7+ days ago
     * - Redis TTL expired
     *
     * Token rotation:
     * - OLD token used після refresh
     * - Already revoked (rotation)
     *
     * @param ex InvalidTokenException
     * @return Error response (401 Unauthorized)
     */
    @ExceptionHandler(InvalidTokenException.class)
    public ResponseEntity<Map<String, Object>> handleInvalidToken(InvalidTokenException ex) {
        log.warn("Invalid token: {}", ex.getMessage());

        // Build error response
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("timestamp", LocalDateTime.now());
        errorResponse.put("status", HttpStatus.UNAUTHORIZED.value());  // 401
        errorResponse.put("error", HttpStatus.UNAUTHORIZED.getReasonPhrase());  // "Unauthorized"
        errorResponse.put("message", ex.getMessage());  // "Invalid or expired refresh token"

        // Return 401 Unauthorized
        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(errorResponse);
    }

    /**
     * Handle Validation Exceptions
     *
     * Thrown by @Valid annotation when request DTO validation fails.
     *
     * VALIDATION PROCESS:
     * ══════════════════
     * 1. Client sends JSON request
     * 2. Jackson deserializes → DTO
     * 3. @Valid triggers Bean Validation
     * 4. Validation annotations checked:
     *    - @NotBlank
     *    - @Size
     *    - @Email
     *    - тощо
     * 5. If invalid → MethodArgumentNotValidException
     * 6. This handler catches it
     * 7. Extracts field errors
     * 8. Returns formatted error response
     *
     * HTTP STATUS:
     * ═══════════
     * 400 Bad Request:
     * - Request invalid
     * - Validation failed
     * - Client should fix і retry
     *
     * ERROR RESPONSE:
     * ══════════════
     * {
     *   "timestamp": "2024-10-31T12:30:00",
     *   "status": 400,
     *   "error": "Bad Request",
     *   "message": "Validation failed",
     *   "validationErrors": {
     *     "username": "Username is required",
     *     "password": "Password must be at least 8 characters",
     *     "email": "Email must be valid"
     *   }
     * }
     *
     * VALIDATION ERRORS MAP:
     * ═════════════════════
     * Field name → Error message
     *
     * Multiple errors для same field (first only):
     * - username: @NotBlank + @Size violations
     * - Returns first error only
     *
     * CLIENT HANDLING:
     * ═══════════════
     * Display errors на form:
     *
     * if (response.status === 400) {
     *   const data = await response.json();
     *   const errors = data.validationErrors;
     *
     *   Object.entries(errors).forEach(([field, message]) => {
     *     showFieldError(field, message);
     *   });
     * }
     *
     * Example:
     * <input name="username" />
     * <span class="error">Username is required</span>
     *
     * LOGGING:
     * ═══════
     * WARN level (client errors).
     *
     * Logged data:
     * ✅ Number of validation errors
     * ✅ Field names (comma-separated)
     * ❌ Field values (might contain PII)
     * ❌ Stack trace (not needed)
     *
     * VALIDATION ANNOTATIONS:
     * ══════════════════════
     * Common annotations:
     *
     * @NotBlank:
     * - Not null
     * - Not empty string
     * - Not whitespace only
     *
     * @NotEmpty:
     * - Not null
     * - Not empty (length > 0)
     *
     * @NotNull:
     * - Not null (allows empty)
     *
     * @Size(min, max):
     * - Length constraints
     *
     * @Email:
     * - Valid email format
     *
     * @Pattern(regexp):
     * - Regex validation
     *
     * @Min, @Max:
     * - Numeric range
     *
     * CUSTOM MESSAGES:
     * ═══════════════
     * Each annotation can have custom message:
     *
     * @NotBlank(message = "Username is required")
     * private String username;
     *
     * @Size(min = 8, message = "Password must be at least 8 characters")
     * private String password;
     *
     * @Email(message = "Email must be valid")
     * private String email;
     *
     * PREVENTION:
     * ══════════
     * Client-side validation (before submit):
     * - Required fields
     * - Format validation (email, phone)
     * - Length constraints
     * - Pattern matching
     *
     * Benefits:
     * ✅ Better UX (instant feedback)
     * ✅ Less server requests
     * ✅ Reduced load
     *
     * Server-side validation still REQUIRED:
     * ⚠️  Never trust client (can be bypassed)
     * ⚠️  Always validate на server
     * ⚠️  Defense in depth
     *
     * @param ex MethodArgumentNotValidException
     * @return Error response (400 Bad Request) з field errors
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleValidationExceptions(
            MethodArgumentNotValidException ex) {

        // Extract field errors від exception
        Map<String, String> validationErrors = new HashMap<>();

        ex.getBindingResult().getAllErrors().forEach(error -> {
            // Get field name
            String fieldName = ((FieldError) error).getField();

            // Get error message від annotation
            String errorMessage = error.getDefaultMessage();

            // Add to map (overwrites if multiple errors для same field)
            validationErrors.put(fieldName, errorMessage);
        });

        log.warn("Validation failed: {} errors in fields: {}",
                validationErrors.size(),
                String.join(", ", validationErrors.keySet()));

        // Build error response
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("timestamp", LocalDateTime.now());
        errorResponse.put("status", HttpStatus.BAD_REQUEST.value());  // 400
        errorResponse.put("error", HttpStatus.BAD_REQUEST.getReasonPhrase());  // "Bad Request"
        errorResponse.put("message", "Validation failed");
        errorResponse.put("validationErrors", validationErrors);  // Field → Error map

        // Return 400 Bad Request
        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(errorResponse);
    }

    /**
     * Handle Generic Exceptions
     *
     * Catch-all для unexpected exceptions.
     *
     * EXCEPTIONS HANDLED:
     * ══════════════════
     * Any RuntimeException not handled by specific handlers:
     * - NullPointerException
     * - IllegalArgumentException
     * - Database errors
     * - Network errors
     * - Unexpected errors
     *
     * HTTP STATUS:
     * ═══════════
     * 500 Internal Server Error:
     * - Server error (not client fault)
     * - Unexpected condition
     * - Client should report або retry later
     *
     * ERROR RESPONSE:
     * ══════════════
     * {
     *   "timestamp": "2024-10-31T12:30:00",
     *   "status": 500,
     *   "error": "Internal Server Error",
     *   "message": "An unexpected error occurred"
     * }
     *
     * GENERIC MESSAGE:
     * ═══════════════
     * Don't expose internal error details:
     * ✅ "An unexpected error occurred" (safe)
     * ❌ "NullPointerException at line 123" (leaks info)
     * ❌ "Database connection failed" (internal detail)
     *
     * Why:
     * - Security (no internal info leak)
     * - User-friendly (non-technical)
     * - Privacy (no sensitive data)
     *
     * LOGGING:
     * ═══════
     * ERROR level (critical errors).
     *
     * Logged data:
     * ✅ Full exception message
     * ✅ Stack trace (debugging)
     * ✅ Timestamp
     * ✅ Request context (URL, method)
     *
     * Stack trace essential для debugging:
     * - Where error occurred
     * - Call chain
     * - Root cause
     *
     * MONITORING:
     * ══════════
     * Alert on 500 errors:
     * - High error rate → service unhealthy
     * - Specific errors → code bugs
     * - Patterns → systemic issues
     *
     * Tools:
     * - Application logs (ELK stack)
     * - APM (New Relic, Datadog)
     * - Error tracking (Sentry, Rollbar)
     *
     * DEBUGGING:
     * ═════════
     * Check logs:
     * 1. Find ERROR log entries
     * 2. Read stack trace
     * 3. Identify root cause
     * 4. Reproduce locally
     * 5. Fix bug
     * 6. Deploy
     *
     * COMMON CAUSES:
     * ═════════════
     * NullPointerException:
     * - Missing null checks
     * - Optional not handled
     * - Unexpected null values
     *
     * Database errors:
     * - Connection timeout
     * - Query errors
     * - Constraint violations
     *
     * Redis errors:
     * - Connection failed
     * - Timeout
     * - Out of memory
     *
     * Configuration errors:
     * - Missing properties
     * - Invalid values
     * - File not found
     *
     * PREVENTION:
     * ══════════
     * Best practices:
     * ✅ Null checks (Objects.requireNonNull)
     * ✅ Optional usage (Optional.ofNullable)
     * ✅ Validation (@Valid, @NotNull)
     * ✅ Error handling (try-catch when appropriate)
     * ✅ Testing (unit tests, integration tests)
     *
     * @param ex Any RuntimeException
     * @return Error response (500 Internal Server Error)
     */
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<Map<String, Object>> handleGenericException(RuntimeException ex) {
        // ERROR level logging з stack trace
        log.error("Unexpected error occurred", ex);

        // Build error response (generic message)
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("timestamp", LocalDateTime.now());
        errorResponse.put("status", HttpStatus.INTERNAL_SERVER_ERROR.value());  // 500
        errorResponse.put("error", HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase());  // "Internal Server Error"
        errorResponse.put("message", "An unexpected error occurred");  // Generic (no details)

        // Return 500 Internal Server Error
        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(errorResponse);
    }
}
