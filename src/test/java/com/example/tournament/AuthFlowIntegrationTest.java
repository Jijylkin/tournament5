package com.example.tournament;

import com.example.tournament.dto.LoginRequest;
import com.example.tournament.dto.RefreshRequest;
import com.example.tournament.dto.RegisterRequest;
import com.example.tournament.dto.TokenPair;
import com.example.tournament.model.SessionStatus;
import com.example.tournament.model.User;
import com.example.tournament.repository.UserRepository;
import com.example.tournament.repository.UserSessionRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;

import static org.junit.jupiter.api.Assertions.*;

@ActiveProfiles("test")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AuthFlowIntegrationTest {

    @Autowired
    private TestRestTemplate http;
    @Autowired
    private UserRepository users;
    @Autowired
    private UserSessionRepository sessions;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @BeforeEach
    void setUp() {
        sessions.deleteAll();
        users.deleteAll();

        User organizer = new User();
        organizer.setName("Организатор");
        organizer.setEmail("organizer@tournament.local");
        organizer.setPasswordHash(passwordEncoder.encode("Organize2026!"));
        organizer.setRole("ORGANIZER");
        organizer.setEnabled(true);
        users.saveAndFlush(organizer);
    }

    @Test
    void loginRefreshAndReplayFollowSessionStateContract() {
        ResponseEntity<TokenPair> login = http.postForEntity("/auth/login",
                new LoginRequest("organizer@tournament.local", "Organize2026!", "integration-test"),
                TokenPair.class);
        assertEquals(HttpStatus.OK, login.getStatusCode());
        TokenPair firstPair = requirePair(login.getBody());
        assertEquals(1, sessions.count());
        assertEquals(SessionStatus.ACTIVE, sessions.findAll().getFirst().getStatus());

        HttpHeaders accessHeaders = new HttpHeaders();
        accessHeaders.setBearerAuth(firstPair.accessToken());
        ResponseEntity<String> profile = http.exchange("/api/account/me", HttpMethod.GET,
                new HttpEntity<>(accessHeaders), String.class);
        assertEquals(HttpStatus.OK, profile.getStatusCode());

        ResponseEntity<TokenPair> refresh = http.postForEntity("/auth/refresh",
                new RefreshRequest(firstPair.refreshToken()), TokenPair.class);
        assertEquals(HttpStatus.OK, refresh.getStatusCode());
        requirePair(refresh.getBody());
        assertEquals(2, sessions.count());
        assertEquals(1, sessions.findAll().stream()
                .filter(session -> session.getStatus() == SessionStatus.USED).count());
        assertEquals(1, sessions.findAll().stream()
                .filter(session -> session.getStatus() == SessionStatus.ACTIVE).count());

        ResponseEntity<String> replay = http.postForEntity("/auth/refresh",
                new RefreshRequest(firstPair.refreshToken()), String.class);
        assertEquals(HttpStatus.UNAUTHORIZED, replay.getStatusCode());
        assertEquals(2, sessions.count());
        assertEquals(1, sessions.findAll().stream()
                .filter(session -> session.getStatus() == SessionStatus.REVOKED).count());
        assertEquals(1, sessions.findAll().stream()
                .filter(session -> session.getStatus() == SessionStatus.ACTIVE).count());
    }

    @Test
    void registrationCreatesPlayerAndSessionAndDuplicateReturnsConflict() {
        RegisterRequest request = new RegisterRequest("Новый игрок", "new.player@example.com",
                "Player2026!", "integration-test");

        ResponseEntity<TokenPair> created = http.postForEntity("/auth/register", request, TokenPair.class);
        assertEquals(HttpStatus.CREATED, created.getStatusCode());
        requirePair(created.getBody());
        User player = users.findByEmailIgnoreCase("new.player@example.com").orElseThrow();
        assertEquals("PLAYER", player.getRole());
        assertEquals(1, sessions.findAll().stream()
                .filter(session -> session.getUsername().equals("new.player@example.com")
                        && session.getStatus() == SessionStatus.ACTIVE).count());

        ResponseEntity<String> duplicate = http.postForEntity("/auth/register", request, String.class);
        assertEquals(HttpStatus.CONFLICT, duplicate.getStatusCode());
        assertEquals(1, sessions.findAll().stream()
                .filter(session -> session.getUsername().equals("new.player@example.com")).count());
    }

    private TokenPair requirePair(TokenPair pair) {
        assertNotNull(pair);
        assertNotNull(pair.accessToken());
        assertFalse(pair.accessToken().isBlank());
        assertNotNull(pair.refreshToken());
        assertFalse(pair.refreshToken().isBlank());
        return pair;
    }
}
