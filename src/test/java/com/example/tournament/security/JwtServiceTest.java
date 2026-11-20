package com.example.tournament.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

class JwtServiceTest {

    private JwtService jwtService;

    @BeforeEach
    void setUp() {
        JwtProperties properties = new JwtProperties();
        properties.setSecret("test-secret-that-is-longer-than-thirty-two-bytes");
        properties.setAccessTokenTtl(Duration.ofMinutes(15));
        properties.setRefreshTokenTtl(Duration.ofDays(7));
        jwtService = new JwtService(properties);
        jwtService.initializeKey();
    }

    @Test
    void accessAndRefreshHaveRequiredClaimsAndDifferentTypes() {
        IssuedToken access = jwtService.createAccessToken("player@example.com");
        IssuedToken refresh = jwtService.createRefreshToken("player@example.com");

        ParsedToken parsedAccess = jwtService.parseAccessToken(access.value());
        ParsedToken parsedRefresh = jwtService.parseRefreshToken(refresh.value());

        assertEquals("player@example.com", parsedAccess.subject());
        assertEquals(TokenType.ACCESS, parsedAccess.type());
        assertFalse(parsedAccess.jti().isBlank());
        assertEquals(access.expiresAt(), parsedAccess.expiresAt());

        assertEquals("player@example.com", parsedRefresh.subject());
        assertEquals(TokenType.REFRESH, parsedRefresh.type());
        assertFalse(parsedRefresh.jti().isBlank());
        assertEquals(refresh.expiresAt(), parsedRefresh.expiresAt());
        assertNotEquals(parsedAccess.jti(), parsedRefresh.jti());
    }

    @Test
    void tokenTypeCannotBeSubstituted() {
        String access = jwtService.createAccessToken("player@example.com").value();
        String refresh = jwtService.createRefreshToken("player@example.com").value();

        assertThrows(JwtAuthenticationException.class, () -> jwtService.parseRefreshToken(access));
        assertThrows(JwtAuthenticationException.class, () -> jwtService.parseAccessToken(refresh));
    }

    @Test
    void modifiedTokenIsRejected() {
        String token = jwtService.createAccessToken("player@example.com").value();
        String modified = token.substring(0, token.length() - 2) + "xx";
        assertThrows(JwtAuthenticationException.class, () -> jwtService.parseAccessToken(modified));
    }
}
