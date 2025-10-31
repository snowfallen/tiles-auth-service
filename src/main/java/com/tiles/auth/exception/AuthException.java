package com.tiles.auth.exception;

/**
 * Base Auth Exception
 *
 * Parent для всіх auth-related exceptions.
 * Дозволяє catch всі auth exceptions в одному місці.
 */
public class AuthException extends RuntimeException {

    public AuthException(String message) {
        super(message);
    }

    public AuthException(String message, Throwable cause) {
        super(message, cause);
    }
}
