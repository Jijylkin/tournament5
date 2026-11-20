package com.example.tournament.service;

import com.example.tournament.dto.TokenPair;

record RefreshResult(TokenPair tokenPair, boolean reused) {

    static RefreshResult success(TokenPair tokenPair) {
        return new RefreshResult(tokenPair, false);
    }

    static RefreshResult reuseDetected() {
        return new RefreshResult(null, true);
    }
}
