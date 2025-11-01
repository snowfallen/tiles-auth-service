package com.tiles.auth.dto.response;

/**
 * Message Response DTO
 *
 * Simple response для operations that return only message.
 *
 * USAGE:
 * ═════
 * Success operations without data:
 * - POST /auth/logout → "Logged out successfully"
 * - POST /auth/logout-all → "Logged out from all devices"
 * - PUT /api/users/{id} → "User updated successfully"
 * - DELETE /api/users/{id} → "User deleted successfully"
 *
 * RECORD TYPE:
 * ═══════════
 * Java 14+ record = immutable data class
 *
 * Equivalent to:
 * public class MessageResponse {
 *     private final String message;
 *
 *     public MessageResponse(String message) {
 *         this.message = message;
 *     }
 *
 *     public String getMessage() {
 *         return message;
 *     }
 *
 *     // equals, hashCode, toString generated
 * }
 *
 * Benefits:
 * ✅ Concise (one line)
 * ✅ Immutable (final field)
 * ✅ Thread-safe
 * ✅ Clean code
 *
 * WHY RECORD (not @Data class):
 * ═════════════════════════════
 * Records for:
 * - Immutable DTOs
 * - Simple data carriers
 * - Value objects
 *
 * Classes для:
 * - Mutable objects
 * - Complex behavior
 * - Inheritance needed
 *
 * MessageResponse = perfect for record:
 * ✅ Single field
 * ✅ Immutable
 * ✅ No behavior
 * ✅ Value object
 *
 * JSON SERIALIZATION:
 * ══════════════════
 * Jackson supports records (Java 14+):
 *
 * Object:
 * new MessageResponse("Logged out successfully")
 *
 * JSON:
 * {
 *   "message": "Logged out successfully"
 * }
 *
 * ALTERNATIVE:
 * ═══════════
 * Could use Map:
 * Map.of("message", "Logged out successfully")
 *
 * Why DTO better:
 * ✅ Type-safe
 * ✅ Self-documenting
 * ✅ Consistent API
 * ✅ Swagger/OpenAPI docs
 *
 * EXAMPLES:
 * ════════
 *
 * Success logout:
 * POST /auth/logout
 * Response: 200 OK
 * {
 *   "message": "Logged out successfully"
 * }
 *
 * Success logout all:
 * POST /auth/logout-all
 * Response: 200 OK
 * {
 *   "message": "Logged out from all devices"
 * }
 *
 * Success update:
 * PUT /api/users/550e8400-e29b-41d4-a716-446655440000
 * Response: 200 OK
 * {
 *   "message": "User updated successfully"
 * }
 *
 * ERROR RESPONSES:
 * ═══════════════
 * Don't use MessageResponse для errors.
 * Use ErrorResponse (від GlobalExceptionHandler):
 *
 * {
 *   "timestamp": "2024-10-31T12:30:00",
 *   "status": 401,
 *   "error": "Unauthorized",
 *   "message": "Invalid or expired refresh token"
 * }
 *
 * BEST PRACTICES:
 * ══════════════
 * Messages should be:
 * ✅ Clear і concise
 * ✅ Action-oriented ("Logged out", not "Logout complete")
 * ✅ User-friendly (no technical jargon)
 * ✅ Consistent format (past tense)
 *
 * Examples:
 * ✅ "Logged out successfully"
 * ✅ "User created successfully"
 * ✅ "Email sent successfully"
 *
 * ❌ "Operation completed"
 * ❌ "Success"
 * ❌ "200 OK"
 *
 * LOCALIZATION (future):
 * ═════════════════════
 * Consider i18n:
 * - Store message keys
 * - Client translates
 * - Support multiple languages
 *
 * Example:
 * {
 *   "messageKey": "logout.success",
 *   "message": "Logged out successfully",
 *   "messageParams": {}
 * }
 *
 * Client:
 * const message = i18n.t(messageKey);
 *
 * @param message Success message
 *
 * @author snowfallen
 * @version 1.0.0
 * @since 2024-10-31
 */
public record MessageResponse(String message) {
}
