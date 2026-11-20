package com.example.tournament.controller;

import com.example.tournament.model.User;
import com.example.tournament.security.AccessService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/account")
public class AccountController {

    @Autowired
    private AccessService access;

    @GetMapping("/me")
    public Map<String, Object> me() {
        return profile(access.currentUser());
    }

    private Map<String, Object> profile(User user) {
        return Map.of("id", user.getId(), "name", user.getName(), "email", user.getEmail(),
                "role", user.getRole(), "enabled", user.getEnabled());
    }
}
