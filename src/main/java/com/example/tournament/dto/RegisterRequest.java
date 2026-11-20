package com.example.tournament.dto;

public record RegisterRequest(String name, String email, String password, String deviceId) {
}
