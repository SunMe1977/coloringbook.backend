package com.hansjoerg.coloringbook.exception;

import com.hansjoerg.coloringbook.payload.ApiResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class GlobalExceptionHandler {

    private final MessageSource messageSource;

    @Autowired
    public GlobalExceptionHandler(MessageSource messageSource) {
        this.messageSource = messageSource;
    }

    @ExceptionHandler(BadRequestException.class)
    public ResponseEntity<ApiResponse> handleBadRequestException(BadRequestException ex) {
        String localizedMessage = messageSource.getMessage(ex.getMessageKey(), ex.getArgs(), LocaleContextHolder.getLocale());
        return new ResponseEntity<>(new ApiResponse(false, localizedMessage), HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ApiResponse> handleResourceNotFoundException(ResourceNotFoundException ex) {
        String localizedMessage = messageSource.getMessage(ex.getMessageKey(), ex.getArgs(), LocaleContextHolder.getLocale());
        return new ResponseEntity<>(new ApiResponse(false, localizedMessage), HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(OAuth2AuthenticationProcessingException.class)
    public ResponseEntity<ApiResponse> handleOAuth2AuthenticationProcessingException(OAuth2AuthenticationProcessingException ex) {
        String localizedMessage = messageSource.getMessage(ex.getMessageKey(), ex.getArgs(), LocaleContextHolder.getLocale());
        return new ResponseEntity<>(new ApiResponse(false, localizedMessage), HttpStatus.BAD_REQUEST); // OAuth2 processing errors are often bad requests
    }

    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<String> handleRuntimeException(RuntimeException ex) {
        // For generic RuntimeExceptions, we might not have a specific message key,
        // so we'll just use the exception's message or a generic error message.
        String localizedMessage = messageSource.getMessage("error.internalServerError", null, "Something went wrong: " + ex.getMessage(), LocaleContextHolder.getLocale());
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(localizedMessage);
    }
}
