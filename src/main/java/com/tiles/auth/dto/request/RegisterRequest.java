package com.tiles.auth.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

/**
 * Registration Request DTO
 *
 * Data Transfer Object для POST /auth/register endpoint.
 *
 * REGISTRATION FLOW:
 * ═════════════════
 * 1. Client sends registration data (this DTO)
 * 2. @Valid triggers validation
 * 3. If validation fails → 400 Bad Request
 * 4. If validation passes → proceed to service
 * 5. Service checks uniqueness (username, email)
 * 6. If exists → 409 Conflict
 * 7. If available → create user
 * 8. Hash password (BCrypt)
 * 9. Save to database
 * 10. Auto-login (generate tokens)
 * 11. Return LoginResponse
 *
 * VALIDATION LAYERS:
 * ═════════════════
 * Layer 1: Format validation (this DTO)
 * - @NotBlank: Not empty
 * - @Size: Length constraints
 * - @Email: Email format
 *
 * Layer 2: Business validation (service)
 * - Username uniqueness
 * - Email uniqueness
 * - Password strength (future)
 *
 * Layer 3: Database constraints
 * - UNIQUE constraints
 * - NOT NULL constraints
 * - Length limits (VARCHAR)
 *
 * Defense in depth: Multiple validation layers.
 *
 * FIELDS:
 * ══════
 * Minimum data для create account:
 * - username: Login name
 * - email: Email address
 * - password: Plain password (будет hashed)
 *
 * NOT included:
 * ❌ Roles (assigned automatically: USER)
 * ❌ Account flags (set by default: enabled=true)
 * ❌ Timestamps (automatic: createdAt, updatedAt)
 *
 * SECURITY:
 * ════════
 * Password validation critical:
 * - Minimum length (8 characters)
 * - Future: Complexity rules
 * - Future: Breach detection (HaveIBeenPwned API)
 *
 * Email verification:
 * - Future: Send confirmation email
 * - Future: Account enabled після verification
 * - Current: Immediate activation
 *
 * @author snowfallen
 * @version 1.0.0
 * @since 2024-10-31
 */
@Data
public class RegisterRequest {

    /**
     * Username
     *
     * Unique login name для new user.
     *
     * VALIDATION:
     * ══════════
     * @NotBlank:
     * - Required field
     * - Cannot be empty або whitespace
     *
     * @Size(min=3, max=50):
     * - Minimum 3 characters (readability)
     * - Maximum 50 characters (reasonable limit)
     *
     * Error messages:
     * - If blank: "Username is required"
     * - If too short/long: "Username must be between 3 and 50 characters"
     *
     * WHY 3 CHARACTERS MINIMUM:
     * ════════════════════════
     * - Readability (too short = confusing)
     * - Prevents single-char usernames
     * - Common standard (3-50 chars)
     *
     * WHY 50 CHARACTERS MAXIMUM:
     * ════════════════════════
     * - Reasonable limit (most users < 20)
     * - UI/UX considerations (display space)
     * - Database efficiency (index size)
     *
     * Database limit: 255 chars (much higher)
     * API limit: 50 chars (user-friendly)
     *
     * FORMAT RULES (future):
     * ═════════════════════
     * Consider adding @Pattern validation:
     * - Letters, numbers, underscore, hyphen
     * - Must start з letter
     * - No consecutive special chars
     * - No special chars at start/end
     *
     * Example:
     * @Pattern(
     *   regexp = "^[a-zA-Z][a-zA-Z0-9_-]*$",
     *   message = "Username must start з letter..."
     * )
     *
     * UNIQUENESS CHECK:
     * ════════════════
     * Format validation here (DTO).
     * Uniqueness validation в service:
     *
     * if (userRepository.existsByUsername(username)) {
     *     throw new UserAlreadyExistsException(...);
     * }
     *
     * Why separate:
     * - Format check: Fast, no DB query
     * - Uniqueness check: Requires DB query
     * - Separation of concerns
     *
     * CASE SENSITIVITY:
     * ════════════════
     * Database: Case-sensitive (PostgreSQL default)
     * "Admin" ≠ "admin" ≠ "ADMIN"
     *
     * Consider case-insensitive (future):
     * - Store lowercase: "admin"
     * - Query lowercase: WHERE LOWER(username) = ?
     * - Prevents confusion (Admin vs admin)
     */
    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    private String username;

    /**
     * Email
     *
     * Unique email address для new user.
     *
     * VALIDATION:
     * ══════════
     * @NotBlank:
     * - Required field
     * - Cannot be empty
     *
     * @Email:
     * - Valid email format
     * - Uses Jakarta Validation default regex
     * - Checks: local-part@domain.tld
     *
     * Error messages:
     * - If blank: "Email is required"
     * - If invalid format: "Email must be valid"
     *
     * EMAIL VALIDATION:
     * ════════════════
     * @Email annotation validates format:
     * ✅ Valid: "user@example.com"
     * ✅ Valid: "user.name+tag@example.co.uk"
     * ✅ Valid: "user_123@sub.example.com"
     * ❌ Invalid: "user@"
     * ❌ Invalid: "@example.com"
     * ❌ Invalid: "user example.com"
     * ❌ Invalid: "user@example"
     *
     * LIMITATIONS:
     * ═══════════
     * Format validation ≠ Email exists
     *
     * "fake@nonexistent.com" passes validation
     * але email doesn't exist.
     *
     * Email verification (future):
     * 1. User registers
     * 2. Account created (enabled=false)
     * 3. Send verification email
     * 4. User clicks link
     * 5. Account enabled (enabled=true)
     *
     * Benefits:
     * ✅ Confirms email works
     * ✅ Prevents typos
     * ✅ Reduces fake accounts
     * ✅ Compliance (GDPR, CAN-SPAM)
     *
     * UNIQUENESS CHECK:
     * ════════════════
     * Similar to username, checked в service:
     *
     * if (userRepository.existsByEmail(email)) {
     *     throw new UserAlreadyExistsException(...);
     * }
     *
     * DATABASE CONSTRAINT:
     * ═══════════════════
     * Column: email VARCHAR(255) UNIQUE NOT NULL
     *
     * If duplicate somehow reaches DB:
     * - UNIQUE constraint violation
     * - PostgreSQL error
     * - Transaction rollback
     *
     * CASE SENSITIVITY:
     * ════════════════
     * Email standard: Case-insensitive (RFC 5321)
     * "User@Example.com" = "user@example.com"
     *
     * Implementation:
     * - Store lowercase: "user@example.com"
     * - Convert before save: email.toLowerCase()
     * - Query lowercase
     *
     * PRIVACY:
     * ═══════
     * Email = PII (Personally Identifiable Information)
     *
     * Considerations:
     * ⚠️  GDPR compliance (EU users)
     * ⚠️  Data retention policies
     * ⚠️  Right to deletion
     * ⚠️  Secure storage
     * ⚠️  Encrypted backups
     *
     * USE CASES:
     * ═════════
     * - Account recovery (password reset)
     * - Email verification
     * - Notifications (optional)
     * - Alternative login (username або email)
     * - Communication (updates, security alerts)
     */
    @NotBlank(message = "Email is required")
    @Email(message = "Email must be valid")
    private String email;

    /**
     * Password (Plain Text)
     *
     * Plain password для new account.
     * Will be hashed before storage (BCrypt).
     *
     * VALIDATION:
     * ══════════
     * @NotBlank:
     * - Required field
     * - Cannot be empty
     *
     * @Size(min=8):
     * - Minimum 8 characters
     * - No maximum (reasonable passwords < 100)
     *
     * Error messages:
     * - If blank: "Password is required"
     * - If too short: "Password must be at least 8 characters"
     *
     * PASSWORD STRENGTH:
     * ═════════════════
     * Current: Only length validation (min 8)
     *
     * Recommended rules (future):
     * - At least 8 characters ✅ (implemented)
     * - At least one uppercase (future)
     * - At least one lowercase (future)
     * - At least one number (future)
     * - At least one special char (future)
     *
     * Example @Pattern:
     * @Pattern(
     *   regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$",
     *   message = "Password must contain uppercase, lowercase, number, special char"
     * )
     *
     * WHY 8 CHARACTERS:
     * ════════════════
     * NIST recommendations (SP 800-63B):
     * - Minimum 8 characters for user-chosen passwords
     * - Consider longer (12+) for better security
     *
     * Entropy calculation:
     * - 8 chars, lowercase only: 26^8 = 209 billion
     * - 8 chars, mixed case + numbers: 62^8 = 218 trillion
     * - 8 chars, all printable: 95^8 = 6.6 quadrillion
     *
     * Trade-offs:
     * - Longer = more secure
     * - Longer = harder to remember
     * - 8 chars = reasonable balance
     *
     * BREACH DETECTION (future):
     * ═════════════════════════
     * Check against known breached passwords.
     *
     * Integration з HaveIBeenPwned API:
     * 1. Hash password (SHA-1)
     * 2. Send first 5 chars to API (k-anonymity)
     * 3. API returns matching hashes
     * 4. Check if full hash matches
     * 5. If match → reject password
     *
     * Benefits:
     * ✅ Prevents common passwords
     * ✅ Protects against credential stuffing
     * ✅ Privacy-preserving (k-anonymity)
     *
     * COMMON WEAK PASSWORDS:
     * ═════════════════════
     * Blacklist (future):
     * - "password", "password123"
     * - "12345678", "qwerty"
     * - "admin", "admin123"
     * - User's username
     * - User's email
     * - Common words (dictionary)
     *
     * PASSWORD HASHING:
     * ════════════════
     * Plain password received, immediately hashed:
     *
     * String hash = passwordEncoder.encode(password);
     * // $2a$10$N9qo8uLOickgx2ZMRZoMyeIjZ...
     *
     * BCrypt properties:
     * - 10 rounds (2^10 = 1024 iterations)
     * - Unique salt (automatic)
     * - ~100ms per hash
     * - One-way function
     *
     * SECURITY:
     * ════════
     * ⚠️  HTTPS only (TLS encryption)
     * ⚠️  Never log password
     * ⚠️  Hash immediately
     * ⚠️  Clear від memory
     * ⚠️  Rate limit registration (prevent abuse)
     *
     * PASSWORD CONFIRMATION (future):
     * ══════════════════════════════
     * Consider adding confirmation field:
     *
     * private String password;
     * private String confirmPassword;
     *
     * Validation:
     * @AssertTrue(message = "Passwords must match")
     * public boolean isPasswordMatch() {
     *     return password.equals(confirmPassword);
     * }
     *
     * Benefits:
     * ✅ Prevents typos
     * ✅ Better UX (catch mistakes early)
     *
     * STORAGE:
     * ═══════
     * Plain password:
     * - Never stored
     * - Hashed immediately
     * - Hash stored в passwordHash field
     *
     * Password recovery:
     * - Cannot retrieve original password
     * - Must reset (new password)
     * - Send reset link via email
     */
    @NotBlank(message = "Password is required")
    @Size(min = 8, message = "Password must be at least 8 characters")
    private String password;
}
