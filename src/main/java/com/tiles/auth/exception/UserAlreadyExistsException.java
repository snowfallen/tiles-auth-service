package com.tiles.auth.exception;

/**
 * User Already Exists Exception
 *
 * Викидається при registration коли:
 * - Username вже зайнятий
 * - Email вже зайнятий
 */
public class UserAlreadyExistsException extends AuthException {

    public UserAlreadyExistsException(String message) {
        super(message);
    }
}
