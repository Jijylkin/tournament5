package com.example.tournament.controller;

import com.example.tournament.dto.LoginRequest;
import com.example.tournament.dto.RefreshRequest;
import com.example.tournament.dto.RegisterRequest;
import com.example.tournament.dto.TokenPair;
import com.example.tournament.service.AuthService;
import com.example.tournament.service.TokenPairService;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;
    private final TokenPairService tokenPairs;

    public AuthController(AuthService authService, TokenPairService tokenPairs) {
        this.authService = authService;
        this.tokenPairs = tokenPairs;
    }

    @PostMapping("/login")
    public TokenPair login(@RequestBody LoginRequest request) {
        return authService.login(request);
    }

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public TokenPair register(@RequestBody RegisterRequest request) {
        return authService.register(request);
    }

    @PostMapping("/refresh")
    public TokenPair refresh(@RequestBody RefreshRequest request) {
        if (request == null || request.refreshToken() == null || request.refreshToken().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "refreshToken обязателен");
        }
        return tokenPairs.refresh(request.refreshToken());
    }
}
