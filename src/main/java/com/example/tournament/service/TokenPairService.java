package com.example.tournament.service;

import com.example.tournament.dto.TokenPair;
import com.example.tournament.model.User;
import com.example.tournament.security.JwtAuthenticationException;
import com.example.tournament.security.JwtService;
import com.example.tournament.security.ParsedToken;
import org.springframework.stereotype.Service;

@Service
public class TokenPairService {

    private final JwtService jwtService;
    private final SessionTransactionService transactions;

    public TokenPairService(JwtService jwtService, SessionTransactionService transactions) {
        this.jwtService = jwtService;
        this.transactions = transactions;
    }

    public TokenPair issuePair(User user, String deviceId) {
        return transactions.issue(user, deviceId);
    }

    public TokenPair refresh(String refreshToken) {
        ParsedToken parsed = jwtService.parseRefreshToken(refreshToken);
        RefreshResult result = transactions.rotate(refreshToken, parsed);
        if (result.reused()) {
            throw new JwtAuthenticationException("Повторное использование refresh-токена запрещено");
        }
        return result.tokenPair();
    }
}
