package com.hansjoerg.coloringbook.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.NOT_FOUND)
@Getter
public class ResourceNotFoundException extends RuntimeException {
    private final String resourceName; // Keep for specific context if needed, but messageKey will be primary
    private final String fieldName;
    private final Object fieldValue;
    private final String messageKey;
    private final Object[] args;

    public ResourceNotFoundException(String messageKey, Object[] args, String resourceName, String fieldName, Object fieldValue) {
        super(messageKey); // Call super with the key for internal logging/identification
        this.messageKey = messageKey;
        this.args = args;
        this.resourceName = resourceName;
        this.fieldName = fieldName;
        this.fieldValue = fieldValue;
    }

    // Original constructor for compatibility, will be updated in usage
    public ResourceNotFoundException(String resourceName, String fieldName, Object fieldValue) {
        this("error.resourceNotFound", new Object[]{resourceName, fieldName, fieldValue}, resourceName, fieldName, fieldValue);
    }
}
