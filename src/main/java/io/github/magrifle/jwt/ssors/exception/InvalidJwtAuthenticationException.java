package io.github.magrifle.jwt.ssors.exception;

public class InvalidJwtAuthenticationException extends RuntimeException
{
    public InvalidJwtAuthenticationException(String message, Throwable e)
    {
        super(message, e);
    }


    public InvalidJwtAuthenticationException(String message)
    {
        super(message);
    }
}
