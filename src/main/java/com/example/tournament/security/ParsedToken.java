package com.example.tournament.security;

import java.time.Instant;

public record ParsedToken(String subject, String jti, TokenType type, Instant expiresAt) {
}
