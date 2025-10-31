package com.tiles.auth.exception;

/**
 * Invalid Credentials Exception
 *
 * Викидається при login коли:
 * - Username не існує
 * - Password неправильний
 * - Account disabled
 */
public class InvalidCredentialsException extends AuthException {

    public InvalidCredentialsException(String message) {
        super(message);
    }
}
