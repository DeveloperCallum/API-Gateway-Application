package com.beamedcallum.gateway.application.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import common.exception.RestErrorObject;
import common.exception.RestRuntimeException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

@ControllerAdvice
public class GatewayControllerAdvice extends ResponseEntityExceptionHandler {

    @ExceptionHandler(value = {RuntimeException.class})
    protected ResponseEntity<Object> handleConflict(RuntimeException ex, WebRequest request) {
        ex.printStackTrace();

        ObjectMapper objectMapper = new ObjectMapper();
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.setContentType(MediaType.APPLICATION_JSON);

        try {
            if (ex instanceof RestRuntimeException) {
                RestRuntimeException exception = (RestRuntimeException) ex;

                RestErrorObject errorObject = exception.getErrorObject();
                String data = objectMapper.writeValueAsString(errorObject);

                return handleExceptionInternal(ex, "{\"error\":" + data + "}", httpHeaders, errorObject.getStatus(), request);
            }

            RestErrorObject errorObject = new RestErrorObject(ex.getMessage(), "Unexpected Server Error", HttpStatus.INTERNAL_SERVER_ERROR);
            String data = objectMapper.writeValueAsString(errorObject);

            return handleExceptionInternal(ex, "{\"error\":" + data + "}", httpHeaders, errorObject.getStatus(), request);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
            return handleExceptionInternal(ex, "{\"error\":" + "Json Processing Exception!" + "}", httpHeaders, HttpStatus.INTERNAL_SERVER_ERROR, request);
        }
    }
}