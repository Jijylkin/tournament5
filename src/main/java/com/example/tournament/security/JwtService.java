package com.example.tournament.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.UUID;

@Service
public class JwtService {

    private final JwtProperties properties;
    private SecretKey key;

    public JwtService(JwtProperties properties) {
        this.properties = properties;
    }

    @PostConstruct
    void initializeKey() {
        if (properties.getSecret() == null
                || properties.getSecret().getBytes(StandardCharsets.UTF_8).length < 32) {
            throw new IllegalStateException("JWT_SECRET должен содержать не менее 32 байт");
        }
        key = Keys.hmacShaKeyFor(properties.getSecret().getBytes(StandardCharsets.UTF_8));
    }

    public IssuedToken createAccessToken(String username) {
        return create(username, TokenType.ACCESS, properties.getAccessTokenTtl());
    }

    public IssuedToken createRefreshToken(String username) {
        return create(username, TokenType.REFRESH, properties.getRefreshTokenTtl());
    }

    public ParsedToken parseAccessToken(String token) {
        return parse(token, TokenType.ACCESS);
    }

    public ParsedToken parseRefreshToken(String token) {
        return parse(token, TokenType.REFRESH);
    }

    private IssuedToken create(String username, TokenType type, Duration ttl) {
        Instant issuedAt = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiresAt = issuedAt.plus(ttl).truncatedTo(ChronoUnit.SECONDS);
        String value = Jwts.builder()
                .subject(username)
                .id(UUID.randomUUID().toString())
                .claim("type", type.claimValue())
                .issuedAt(Date.from(issuedAt))
                .expiration(Date.from(expiresAt))
                .signWith(key, Jwts.SIG.HS256)
                .compact();
        return new IssuedToken(value, expiresAt);
    }

    private ParsedToken parse(String token, TokenType expectedType) {
        if (token == null || token.isBlank()) {
            throw unauthorized();
        }
        try {
            Claims claims = Jwts.parser().verifyWith(key).build()
                    .parseSignedClaims(token).getPayload();
            String subject = claims.getSubject();
            String jti = claims.getId();
            String type = claims.get("type", String.class);
            Date expiration = claims.getExpiration();
            if (subject == null || subject.isBlank() || jti == null || jti.isBlank()
                    || expiration == null || !expectedType.claimValue().equals(type)) {
                throw unauthorized();
            }
            return new ParsedToken(subject, jti, expectedType,
                    expiration.toInstant().truncatedTo(ChronoUnit.SECONDS));
        } catch (JwtAuthenticationException e) {
            throw e;
        } catch (JwtException | IllegalArgumentException e) {
            throw unauthorized();
        }
    }

    private JwtAuthenticationException unauthorized() {
        return new JwtAuthenticationException("Неверный, просроченный или неподходящий токен");
    }
}
