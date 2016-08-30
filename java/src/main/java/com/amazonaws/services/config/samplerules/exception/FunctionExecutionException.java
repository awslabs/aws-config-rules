package com.amazonaws.services.config.samplerules.exception;

public class FunctionExecutionException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public FunctionExecutionException(String message) {
        super(message);
    }
}
