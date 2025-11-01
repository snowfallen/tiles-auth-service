package com.tiles.auth.exception;

/**
 * Invalid Credentials Exception
 *
 * Thrown when authentication fails.
 *
 * USE CASES:
 * ═════════
 * Login failures:
 * - Wrong username or password
 * - Account disabled
 * - Account locked
 * - Account expired
 *
 * WHEN THROWN:
 * ═══════════
 * AuthServiceImpl.login():
 * - authenticationManager.authenticate() fails
 * - Wraps BadCredentialsException
 * - Wraps DisabledException
 * - Wraps LockedException
 *
 * UserServiceImpl.loadUserByUsername():
 * - Account disabled (user.enabled = false)
 *
 * HANDLING:
 * ════════
 * GlobalExceptionHandler catches this exception.
 *
 * Handler method:
 * @ExceptionHandler(InvalidCredentialsException.class)
 *
 * Response:
 * - HTTP 401 Unauthorized
 * - Generic error message (security)
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
 * WHY GENERIC MESSAGE:
 * ═══════════════════
 * Security best practice: Prevent username enumeration.
 *
 * Bad (reveals info):
 * - "Username not found" → Username doesn't exist
 * - "Wrong password" → Username exists, password wrong
 * - "Account disabled" → Username exists, account disabled
 *
 * Attacker can:
 * - Enumerate valid usernames
 * - Focus brute-force on valid accounts
 * - Learn account status
 *
 * Good (generic):
 * - "Invalid username or password" → No info leaked
 *
 * Cannot distinguish:
 * - Username not found
 * - Wrong password
 * - Account disabled
 * - Account locked
 *
 * EXCEPTION HIERARCHY:
 * ═══════════════════
 * RuntimeException (Spring default)
 *   ↓
 * InvalidCredentialsException (our custom)
 *
 * RuntimeException:
 * - Unchecked exception (no throws declaration needed)
 * - Can be thrown від any method
 * - Caught by GlobalExceptionHandler
 *
 * CONSTRUCTOR:
 * ═══════════
 * Single constructor з message parameter.
 *
 * Usage:
 * throw new InvalidCredentialsException("Invalid username or password");
 *
 * Message passed to:
 * - super(message) → RuntimeException
 * - Available via getMessage()
 * - Used в error response
 *
 * USAGE EXAMPLES:
 * ══════════════
 *
 * Example 1: Login failure
 * try {
 *     authenticationManager.authenticate(authToken);
 * } catch (BadCredentialsException e) {
 *     throw new InvalidCredentialsException("Invalid username or password");
 * }
 *
 * Example 2: Account disabled
 * if (!user.getEnabled()) {
 *     throw new InvalidCredentialsException("Account is disabled");
 * }
 *
 * Example 3: Account locked
 * if (!user.getAccountNonLocked()) {
 *     throw new InvalidCredentialsException("Account is locked");
 * }
 *
 * SECURITY CONSIDERATIONS:
 * ═══════════════════════
 *
 * Generic messages:
 * ✅ Same message для all failures
 * ✅ Same response time (constant-time)
 * ✅ Same HTTP status (401)
 *
 * Additional security:
 * - Rate limiting (max 5 attempts/minute)
 * - Account lockout (10 failed attempts)
 * - Monitoring (detect brute-force)
 * - Logging (audit trail)
 *
 * LOGGING:
 * ═══════
 * Exception logged в:
 * - GlobalExceptionHandler (WARN level)
 * - AuthService (DEBUG level)
 *
 * Logged data:
 * ✅ Exception message
 * ✅ Username (audit trail)
 * ✅ IP address (security)
 * ✅ Timestamp
 * ❌ Password (never log)
 *
 * CLIENT HANDLING:
 * ═══════════════
 * if (response.status === 401) {
 *   const data = await response.json();
 *   showError(data.message);  // "Invalid username or password"
 *
 *   // Clear password field
 *   passwordInput.value = '';
 *
 *   // Focus username field
 *   usernameInput.focus();
 * }
 *
 * TESTING:
 * ═══════
 * Unit test example:
 *
 * @Test
 * void testInvalidCredentialsException() {
 *     // Given
 *     String message = "Invalid username or password";
 *
 *     // When
 *     InvalidCredentialsException ex =
 *         new InvalidCredentialsException(message);
 *
 *     // Then
 *     assertEquals(message, ex.getMessage());
 *     assertTrue(ex instanceof RuntimeException);
 * }
 *
 * Integration test:
 *
 * @Test
 * void testLoginWithWrongPassword() {
 *     // Given
 *     LoginRequest request = new LoginRequest();
 *     request.setUsername("admin");
 *     request.setPassword("wrongpassword");
 *
 *     // When
 *     ResponseEntity<?> response = authController.login(request);
 *
 *     // Then
 *     assertEquals(401, response.getStatusCodeValue());
 *
 *     Map<String, Object> body = (Map<String, Object>) response.getBody();
 *     assertEquals("Invalid username or password", body.get("message"));
 * }
 *
 * ALTERNATIVES:
 * ════════════
 * Could use Spring Security exceptions directly:
 * - BadCredentialsException
 * - DisabledException
 * - LockedException
 *
 * Why custom exception:
 * ✅ Consistent error handling
 * ✅ Single catch block
 * ✅ Generic message control
 * ✅ Application-specific
 *
 * RELATED EXCEPTIONS:
 * ══════════════════
 * Spring Security exceptions wrapped:
 * - BadCredentialsException (wrong password)
 * - UsernameNotFoundException (user not found)
 * - DisabledException (account disabled)
 * - LockedException (account locked)
 * - AccountExpiredException (account expired)
 * - CredentialsExpiredException (password expired)
 *
 * All converted to InvalidCredentialsException.
 *
 * @author snowfallen
 * @version 1.0.0
 * @since 2024-10-31
 */
public class InvalidCredentialsException extends RuntimeException {

    /**
     * Constructor
     *
     * Creates exception з custom message.
     *
     * MESSAGE GUIDELINES:
     * ══════════════════
     * Always use generic messages:
     * ✅ "Invalid username or password"
     * ✅ "Invalid credentials"
     *
     * Never use specific messages:
     * ❌ "Username not found"
     * ❌ "Wrong password"
     * ❌ "Account disabled"
     *
     * Exception:
     * Internal logging can be specific (not shown to client).
     *
     * USAGE:
     * ═════
     * throw new InvalidCredentialsException("Invalid username or password");
     *
     * Message available via:
     * - ex.getMessage()
     * - Used в GlobalExceptionHandler
     * - Returned в error response
     *
     * @param message error message (generic recommended)
     */
    public InvalidCredentialsException(String message) {
        // Pass message to parent RuntimeException
        // Available via getMessage()
        super(message);
    }
}
