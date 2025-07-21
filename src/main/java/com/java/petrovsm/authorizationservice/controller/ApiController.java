package com.java.petrovsm.authorizationservice.controller;

import com.java.petrovsm.authorizationservice.dto.JwtResponse;
import com.java.petrovsm.authorizationservice.dto.LoginRequest;
import com.java.petrovsm.authorizationservice.dto.SignupRequest;
import com.java.petrovsm.authorizationservice.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class ApiController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody SignupRequest signupRequest) {
        try {
            String message = authService.registerUser(signupRequest);
            return ResponseEntity.ok(Map.of(
                    "message", message,
                    "status", "success"
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "message", e.getMessage(),
                    "status", "error"
            ));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest loginRequest) {
        try {
            JwtResponse jwtResponse = authService.authenticateUser(loginRequest);
            return ResponseEntity.ok(jwtResponse);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "message", "Неверный логин или пароль",
                    "status", "error"
            ));
        }
    }

    @PostMapping("/revoke-token")
    public ResponseEntity<?> revokeToken(Authentication authentication, HttpServletRequest request) {
        try {
            String currentAccessToken = extractTokenFromRequest(request);
            authService.revokeCurrentToken(authentication, currentAccessToken);
            return ResponseEntity.ok(Map.of(
                    "message", "Токен успешно отозван",
                    "status", "success"
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "message", e.getMessage(),
                    "status", "error"
            ));
        }
    }

    private String extractTokenFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    @GetMapping("/access/guest")
    @PreAuthorize("hasRole('GUEST')")
    public ResponseEntity<?> guestAccess(Authentication authentication) {
        return ResponseEntity.ok(Map.of(
                "message", "Добро пожаловать в гостевую зону!",
                "user", authentication.getName(),
                "role", "GUEST",
                "data", Map.of(
                        "availableFeatures", new String[]{
                                "Все гостевые функции"
                        },
                        "limitations", new String[]{"Нет доступа к премиум контенту", "Нет административных прав"}
                )
        ));
    }

    @GetMapping("/access/premium")
    @PreAuthorize("hasRole('PREMIUM_USER')")
    public ResponseEntity<?> premiumAccess(Authentication authentication) {
        return ResponseEntity.ok(Map.of(
                "message", "Добро пожаловать в премиум зону!",
                "user", authentication.getName(),
                "role", "PREMIUM_USER",
                "data", Map.of(
                        "availableFeatures", new String[]{
                                "Все гостевые функции",
                                "Все премиум функции"
                        },
                        "guestData", "Доступны все данные для гостей",
                        "premiumData", "Эксклюзивный премиум контент"
                )
        ));
    }

    @GetMapping("/access/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> adminAccess(Authentication authentication) {
        return ResponseEntity.ok(Map.of(
                "message", "Добро пожаловать в административную панель!",
                "user", authentication.getName(),
                "role", "ADMIN",
                "data", Map.of(
                        "availableFeatures", new String[]{
                                "Все гостевые функции",
                                "Все премиум функции",
                                "Управление пользователями"
                        },
                        "guestData", "Полный доступ к гостевым данным",
                        "premiumData", "Полный доступ к премиум данным",
                        "adminData", "Административные функции и настройки"
                )
        ));
    }

    @GetMapping("/access/check")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> checkAccess(Authentication authentication) {
        String[] roles = authentication.getAuthorities().stream()
                .map(auth -> auth.getAuthority().replace("ROLE_", ""))
                .toArray(String[]::new);

        boolean isGuest = authentication.getAuthorities().stream()
                .anyMatch(auth -> auth.getAuthority().equals("ROLE_GUEST"));
        boolean isPremium = authentication.getAuthorities().stream()
                .anyMatch(auth -> auth.getAuthority().equals("ROLE_PREMIUM_USER"));
        boolean isAdmin = authentication.getAuthorities().stream()
                .anyMatch(auth -> auth.getAuthority().equals("ROLE_ADMIN"));

        return ResponseEntity.ok(Map.of(
                "user", authentication.getName(),
                "roles", roles,
                "access", Map.of(
                        "guest", isGuest || isPremium || isAdmin,
                        "premium", isPremium || isAdmin,
                        "admin", isAdmin
                ),
                "availableEndpoints", Map.of(
                        "guest", isGuest || isPremium || isAdmin ? "/api/access/guest" : "Нет доступа",
                        "premium", isPremium || isAdmin ? "/api/access/premium" : "Нет доступа",
                        "admin", isAdmin ? "/api/access/admin" : "Нет доступа"
                )
        ));
    }
}
