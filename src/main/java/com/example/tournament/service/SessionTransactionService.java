package com.example.tournament.service;

import com.example.tournament.dto.TokenPair;
import com.example.tournament.model.SessionStatus;
import com.example.tournament.model.User;
import com.example.tournament.model.UserSession;
import com.example.tournament.repository.UserRepository;
import com.example.tournament.repository.UserSessionRepository;
import com.example.tournament.security.IssuedToken;
import com.example.tournament.security.JwtAuthenticationException;
import com.example.tournament.security.JwtService;
import com.example.tournament.security.ParsedToken;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

@Service
public class SessionTransactionService {

    private final UserSessionRepository sessions;
    private final UserRepository users;
    private final JwtService jwtService;

    public SessionTransactionService(UserSessionRepository sessions, UserRepository users,
                                     JwtService jwtService) {
        this.sessions = sessions;
        this.users = users;
        this.jwtService = jwtService;
    }

    @Transactional
    public TokenPair issue(User user, String deviceId) {
        ensureEnabled(user);
        return createAndSave(user.getEmail(), normalizeDeviceId(deviceId));
    }

    @Transactional
    public RefreshResult rotate(String refreshToken, ParsedToken parsed) {
        UserSession previous = sessions.findByRefreshTokenForUpdate(refreshToken)
                .orElseThrow(this::unauthorized);

        if (previous.getStatus() == SessionStatus.USED) {
            previous.setStatus(SessionStatus.REVOKED);
            sessions.saveAndFlush(previous);
            return RefreshResult.reuseDetected();
        }
        if (previous.getStatus() != SessionStatus.ACTIVE) {
            throw unauthorized();
        }

        Instant now = Instant.now();
        Instant storedExpiry = previous.getRefreshTokenExpiry().truncatedTo(ChronoUnit.SECONDS);
        if (!previous.getUsername().equalsIgnoreCase(parsed.subject())
                || !storedExpiry.equals(parsed.expiresAt())
                || !storedExpiry.isAfter(now)) {
            throw unauthorized();
        }

        User user = users.findByEmailIgnoreCase(parsed.subject())
                .orElseThrow(this::unauthorized);
        ensureEnabled(user);

        previous.setStatus(SessionStatus.USED);
        sessions.save(previous);
        TokenPair pair = createAndSave(user.getEmail(), previous.getDeviceId());
        sessions.flush();
        return RefreshResult.success(pair);
    }

    private TokenPair createAndSave(String username, String deviceId) {
        IssuedToken access = jwtService.createAccessToken(username);
        IssuedToken refresh = jwtService.createRefreshToken(username);

        UserSession session = new UserSession();
        session.setUsername(username);
        session.setDeviceId(deviceId);
        session.setAccessToken(access.value());
        session.setRefreshToken(refresh.value());
        session.setAccessTokenExpiry(access.expiresAt());
        session.setRefreshTokenExpiry(refresh.expiresAt());
        session.setStatus(SessionStatus.ACTIVE);
        sessions.save(session);
        return new TokenPair(access.value(), refresh.value());
    }

    private void ensureEnabled(User user) {
        if (!Boolean.TRUE.equals(user.getEnabled())) {
            throw unauthorized();
        }
    }

    private String normalizeDeviceId(String deviceId) {
        if (deviceId == null || deviceId.isBlank()) return null;
        if (deviceId.length() > 255) {
            throw new org.springframework.web.server.ResponseStatusException(
                    org.springframework.http.HttpStatus.BAD_REQUEST,
                    "deviceId не должен превышать 255 символов");
        }
        return deviceId.trim();
    }

    private JwtAuthenticationException unauthorized() {
        return new JwtAuthenticationException("Refresh-сессия не существует, использована или отозвана");
    }
}
