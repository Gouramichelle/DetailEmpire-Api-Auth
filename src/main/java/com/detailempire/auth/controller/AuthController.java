package com.detailempire.auth.controller;


import com.detailempire.auth.model.AuthResponse;
import com.detailempire.auth.model.LoginRequest;
import com.detailempire.auth.model.RegisterRequest;
import com.detailempire.auth.model.UserEntity;
import com.detailempire.auth.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@CrossOrigin
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public AuthResponse register(@Valid @RequestBody RegisterRequest request) {
        return authService.register(request);
    }

    @PostMapping("/login")
    public AuthResponse login(@Valid @RequestBody LoginRequest request) {
        return authService.login(request);
    }

    @GetMapping("/me")
    public AuthResponse me(@AuthenticationPrincipal UserEntity user) {
        if (user == null) {
            throw new RuntimeException("No autenticado");
        }

        return AuthResponse.builder()
                .token(null)
                .userId(user.getId())
                .name(user.getName())
                .email(user.getEmail())
                .role(user.getRole())
                .build();
    }
}
