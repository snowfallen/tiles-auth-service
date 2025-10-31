package com.tiles.auth.exception;

/**
 * Invalid Token Exception
 *
 * Викидається коли:
 * - JWT signature invalid
 * - JWT expired
 * - Refresh token не знайдено в Redis
 * - Refresh token expired
 */
public class InvalidTokenException extends AuthException {

    public InvalidTokenException(String message) {
        super(message);
    }

    public InvalidTokenException(String message, Throwable cause) {
        super(message, cause);
    }
}
