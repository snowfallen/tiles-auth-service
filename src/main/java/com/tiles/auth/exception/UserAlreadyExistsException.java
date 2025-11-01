package com.tiles.auth.exception;

/**
 * User Already Exists Exception
 *
 * Thrown when attempting to create duplicate user.
 *
 * USE CASES:
 * ═════════
 * Registration failures:
 * - Username already taken
 * - Email already registered
 * - Duplicate account
 *
 * WHEN THROWN:
 * ═══════════
 * UserServiceImpl.registerUser():
 * - userRepository.existsByUsername() returns true
 * - userRepository.existsByEmail() returns true
 *
 * AuthServiceImpl.register():
 * - Delegates to userService.registerUser()
 * - Exception propagates to controller
 *
 * HANDLING:
 * ════════
 * GlobalExceptionHandler catches this exception.
 *
 * Handler method:
 * @ExceptionHandler(UserAlreadyExistsException.class)
 *
 * Response:
 * - HTTP 409 Conflict
 * - Specific error message (which field)
 *
 * ERROR RESPONSE:
 * ══════════════
 * Username conflict:
 * {
 *   "timestamp": "2024-10-31T12:30:00",
 *   "status": 409,
 *   "error": "Conflict",
 *   "message": "Username already exists: admin"
 * }
 *
 * Email conflict:
 * {
 *   "timestamp": "2024-10-31T12:30:00",
 *   "status": 409,
 *   "error": "Conflict",
 *   "message": "Email already exists: admin@example.com"
 * }
 *
 * WHY SPECIFIC MESSAGE:
 * ════════════════════
 * Unlike authentication, registration can reveal conflicts.
 *
 * Reasons:
 * ✅ Better UX (user knows what to change)
 * ✅ Common practice (most sites do this)
 * ✅ Less critical than password guessing
 *
 * Trade-off:
 * ⚠️  Username enumeration possible
 * ⚠️  Can discover registered emails
 *
 * Mitigation:
 * - Rate limiting (prevent mass enumeration)
 * - CAPTCHA (prevent automation)
 * - Monitoring (detect suspicious patterns)
 *
 * Alternative approach:
 * - Generic message: "This account already exists"
 * - Pro: More secure (no field revealed)
 * - Con: Poor UX (user doesn't know what's wrong)
 *
 * HTTP STATUS CODE:
 * ════════════════
 * 409 Conflict:
 * - Resource already exists
 * - Cannot create duplicate
 * - Client should use different value
 *
 * Alternative codes:
 * - 400 Bad Request (too generic)
 * - 422 Unprocessable Entity (less common)
 *
 * 409 most appropriate:
 * - Standard REST practice
 * - Clearly indicates conflict
 * - Distinguishes від validation errors (400)
 *
 * EXCEPTION HIERARCHY:
 * ═══════════════════
 * RuntimeException
 *   ↓
 * UserAlreadyExistsException
 *
 * Unchecked exception:
 * - No throws declaration needed
 * - Can be thrown від any method
 * - Caught by GlobalExceptionHandler
 *
 * CONSTRUCTOR:
 * ═══════════
 * Single constructor з message parameter.
 *
 * Usage:
 * throw new UserAlreadyExistsException("Username already exists: admin");
 * throw new UserAlreadyExistsException("Email already exists: admin@example.com");
 *
 * Message format:
 * - Descriptive (which field, what value)
 * - User-friendly (clear error)
 * - Actionable (user knows what to change)
 *
 * USAGE EXAMPLES:
 * ══════════════
 *
 * Example 1: Username check
 * if (userRepository.existsByUsername(username)) {
 *     throw new UserAlreadyExistsException(
 *         "Username already exists: " + username
 *     );
 * }
 *
 * Example 2: Email check
 * if (userRepository.existsByEmail(email)) {
 *     throw new UserAlreadyExistsException(
 *         "Email already exists: " + email
 *     );
 * }
 *
 * Example 3: Combined check
 * if (userRepository.existsByUsername(username)) {
 *     throw new UserAlreadyExistsException(
 *         "Username already exists: " + username
 *     );
 * }
 * if (userRepository.existsByEmail(email)) {
 *     throw new UserAlreadyExistsException(
 *         "Email already exists: " + email
 *     );
 * }
 * // Both checks passed → proceed з registration
 *
 * DATABASE CONSTRAINTS:
 * ════════════════════
 * Database has UNIQUE constraints:
 * - users.username (UNIQUE)
 * - users.email (UNIQUE)
 *
 * Double protection:
 * 1. Application check (existsByUsername/Email)
 * 2. Database constraint (UNIQUE)
 *
 * If application check bypassed:
 * - Database throws exception
 * - Transaction rolled back
 * - No duplicate data saved
 *
 * Why check в application:
 * ✅ Better error message
 * ✅ Avoid database error
 * ✅ Faster response (no save attempt)
 *
 * Why keep database constraint:
 * ✅ Data integrity (final safety net)
 * ✅ Concurrent requests protection
 * ✅ Direct database access protection
 *
 * RACE CONDITION:
 * ══════════════
 * Possible scenario:
 * 1. Request A: Check username "admin" → not exists
 * 2. Request B: Check username "admin" → not exists
 * 3. Request A: Save user "admin" → success
 * 4. Request B: Save user "admin" → database error
 *
 * Protection:
 * - Database UNIQUE constraint (fails request B)
 * - Transaction isolation (serializable)
 * - Optimistic locking (version field)
 *
 * LOGGING:
 * ═══════
 * Exception logged в:
 * - GlobalExceptionHandler (WARN level)
 * - UserService (DEBUG level)
 *
 * Logged data:
 * ✅ Exception message (which field)
 * ✅ Username або email (audit trail)
 * ✅ IP address (security)
 * ✅ Timestamp
 *
 * CLIENT HANDLING:
 * ═══════════════
 * JavaScript example:
 *
 * if (response.status === 409) {
 *   const data = await response.json();
 *   const message = data.message;
 *
 *   // Determine which field has conflict
 *   if (message.includes('Username')) {
 *     showFieldError('username', message);
 *     usernameInput.focus();
 *   } else if (message.includes('Email')) {
 *     showFieldError('email', message);
 *     emailInput.focus();
 *   }
 * }
 *
 * PREVENTION:
 * ══════════
 * Client-side availability check:
 *
 * // Check username availability (AJAX)
 * async function checkUsername(username) {
 *   const response = await fetch(
 *     `/api/users/check-username?username=${username}`
 *   );
 *   const data = await response.json();
 *
 *   if (!data.available) {
 *     showFieldError('username', 'Username already taken');
 *     return false;
 *   }
 *
 *   clearFieldError('username');
 *   return true;
 * }
 *
 * // Check on blur
 * usernameInput.addEventListener('blur', async (e) => {
 *   await checkUsername(e.target.value);
 * });
 *
 * Benefits:
 * ✅ Instant feedback (before submit)
 * ✅ Better UX (no failed submit)
 * ✅ Less server load (catch early)
 *
 * TESTING:
 * ═══════
 * Unit test:
 *
 * @Test
 * void testUserAlreadyExistsException() {
 *     // Given
 *     String message = "Username already exists: admin";
 *
 *     // When
 *     UserAlreadyExistsException ex =
 *         new UserAlreadyExistsException(message);
 *
 *     // Then
 *     assertEquals(message, ex.getMessage());
 *     assertTrue(ex instanceof RuntimeException);
 * }
 *
 * Integration test:
 *
 * @Test
 * void testRegisterWithDuplicateUsername() {
 *     // Given
 *     RegisterRequest request = new RegisterRequest();
 *     request.setUsername("admin");  // Already exists
 *     request.setEmail("newuser@example.com");
 *     request.setPassword("password123");
 *
 *     // When
 *     ResponseEntity<?> response = authController.register(request);
 *
 *     // Then
 *     assertEquals(409, response.getStatusCodeValue());
 *
 *     Map<String, Object> body = (Map<String, Object>) response.getBody();
 *     assertTrue(body.get("message").toString().contains("Username"));
 * }
 *
 * ALTERNATIVES:
 * ════════════
 * Could use DataIntegrityViolationException (Spring):
 * - Thrown automatically by database
 * - Generic exception (not specific)
 * - Poor error message
 *
 * Why custom exception:
 * ✅ Specific message (which field)
 * ✅ Better UX (clear error)
 * ✅ Application-level (before DB)
 * ✅ Type-safe (explicit handling)
 *
 * SECURITY CONSIDERATIONS:
 * ═══════════════════════
 * Username enumeration concern:
 * - Attacker can discover valid usernames
 * - Less critical than password guessing
 * - Acceptable trade-off для UX
 *
 * Mitigation:
 * ✅ Rate limiting (max 10 attempts/minute)
 * ✅ CAPTCHA (prevent automation)
 * ✅ Monitoring (detect enumeration attempts)
 * ✅ Account lockout (suspicious activity)
 *
 * Email privacy concern:
 * - Reveals if email registered
 * - Privacy consideration (GDPR)
 * - Alternative: Send email regardless
 *
 * Pattern:
 * if (email exists) {
 *     throw exception;
 * }
 *
 * vs
 *
 * if (email exists) {
 *     sendEmail("Account already exists");
 * } else {
 *     createAccount();
 *     sendEmail("Welcome!");
 * }
 * return "Check email for next steps";
 *
 * @author snowfallen
 * @version 1.0.0
 * @since 2024-10-31
 */
public class UserAlreadyExistsException extends RuntimeException {

    /**
     * Constructor
     *
     * Creates exception з descriptive message.
     *
     * MESSAGE GUIDELINES:
     * ══════════════════
     * Be specific about conflict:
     * ✅ "Username already exists: admin"
     * ✅ "Email already exists: admin@example.com"
     *
     * Include conflicting value:
     * ✅ Helps user understand problem
     * ✅ Actionable error message
     *
     * Don't use generic messages:
     * ❌ "User already exists"
     * ❌ "Duplicate account"
     *
     * Why specific:
     * - User knows exactly what to change
     * - Better UX (clear feedback)
     * - Standard practice (common pattern)
     *
     * USAGE:
     * ═════
     * throw new UserAlreadyExistsException(
     *     "Username already exists: " + username
     * );
     *
     * throw new UserAlreadyExistsException(
     *     "Email already exists: " + email
     * );
     *
     * Message available via:
     * - ex.getMessage()
     * - Used в GlobalExceptionHandler
     * - Returned в error response
     *
     * PRIVACY:
     * ═══════
     * Message may contain PII:
     * - Username (public identifier)
     * - Email (personal information)
     *
     * Considerations:
     * - Log carefully (mask email?)
     * - Monitor access (who checks?)
     * - GDPR compliance (data protection)
     *
     * @param message error message (specific field і value)
     */
    public UserAlreadyExistsException(String message) {
        // Pass message to parent RuntimeException
        // Available via getMessage()
        super(message);
    }
}
