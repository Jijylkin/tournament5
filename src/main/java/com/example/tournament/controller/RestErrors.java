package com.example.tournament.controller;

import com.example.tournament.security.JwtAuthenticationException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;

@RestControllerAdvice
public class RestErrors {

    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<?> business(ResponseStatusException e) {
        return error(e.getStatusCode().value(), e.getReason() == null ? "Запрос отклонён" : e.getReason());
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<?> denied() {
        return error(403, "Недостаточно прав");
    }

    @ExceptionHandler(JwtAuthenticationException.class)
    public ResponseEntity<?> unauthorized(JwtAuthenticationException e) {
        return error(401, e.getMessage());
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<?> conflict() {
        return error(409, "Запись уже существует или связана с другими данными");
    }

    @ExceptionHandler({HttpMessageNotReadableException.class, MethodArgumentTypeMismatchException.class})
    public ResponseEntity<?> invalid() {
        return error(400, "Неверный формат запроса");
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> unexpected() {
        return error(500, "Ошибка сервера");
    }

    private ResponseEntity<?> error(int status, String message) {
        String error = switch (status) {
            case 400 -> "Bad Request";
            case 401 -> "Unauthorized";
            case 403 -> "Forbidden";
            case 404 -> "Not Found";
            case 409 -> "Conflict";
            default -> "Internal Server Error";
        };
        return ResponseEntity.status(status).body(Map.of("error", error, "status", status, "message", message));
    }
}
