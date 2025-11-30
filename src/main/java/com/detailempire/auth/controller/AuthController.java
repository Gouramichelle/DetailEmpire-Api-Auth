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
import com.detailempire.auth.model.ForgotPasswordRequest;
import com.detailempire.auth.model.ResetPasswordRequest;
import org.springframework.http.ResponseEntity;


@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@CrossOrigin(origins = "http://localhost:5173")
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
    @PostMapping("/forgot-password")
    public ResponseEntity<String> forgotPassword(@RequestBody ForgotPasswordRequest request) {
        authService.initiatePasswordReset(request.getEmail());
        return ResponseEntity.ok(
                "Si el correo existe, se enviaron instrucciones para recuperar tu contraseña."
        );
    }

    @PostMapping("/reset-password")
    public ResponseEntity<String> resetPassword(@RequestBody ResetPasswordRequest request) {
        authService.resetPassword(request);
        return ResponseEntity.ok("Tu contraseña ha sido actualizada correctamente.");
    }

}
