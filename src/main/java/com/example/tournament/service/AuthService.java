package com.example.tournament.service;

import com.example.tournament.dto.LoginRequest;
import com.example.tournament.dto.RegisterRequest;
import com.example.tournament.dto.TokenPair;
import com.example.tournament.dto.UserRequest;
import com.example.tournament.model.User;
import com.example.tournament.repository.UserRepository;
import com.example.tournament.security.JwtAuthenticationException;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository users;
    private final UserService userService;
    private final TokenPairService tokenPairs;

    public AuthService(AuthenticationManager authenticationManager, UserRepository users,
                       UserService userService, TokenPairService tokenPairs) {
        this.authenticationManager = authenticationManager;
        this.users = users;
        this.userService = userService;
        this.tokenPairs = tokenPairs;
    }

    @Transactional
    public TokenPair login(LoginRequest request) {
        if (request == null || blank(request.username()) || blank(request.password())) {
            throw bad("Нужно указать username и password");
        }
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    request.username(), request.password()));
        } catch (AuthenticationException e) {
            throw new JwtAuthenticationException("Неверные учётные данные");
        }
        User user = users.findByEmailIgnoreCase(request.username())
                .orElseThrow(() -> new JwtAuthenticationException("Неверные учётные данные"));
        return tokenPairs.issuePair(user, request.deviceId());
    }

    @Transactional
    public TokenPair register(RegisterRequest request) {
        if (request == null) throw bad("Тело запроса обязательно");
        User user = userService.register(new UserRequest(
                request.name(), request.email(), request.password(), null, null));
        return tokenPairs.issuePair(user, request.deviceId());
    }

    private boolean blank(String value) {
        return value == null || value.isBlank();
    }

    private ResponseStatusException bad(String message) {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, message);
    }
}
