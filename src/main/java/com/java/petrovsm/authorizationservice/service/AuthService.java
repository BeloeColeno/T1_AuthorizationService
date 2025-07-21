package com.java.petrovsm.authorizationservice.service;

import com.java.petrovsm.authorizationservice.dto.JwtResponse;
import com.java.petrovsm.authorizationservice.dto.LoginRequest;
import com.java.petrovsm.authorizationservice.dto.SignupRequest;
import com.java.petrovsm.authorizationservice.exception.RoleNotFoundException;
import com.java.petrovsm.authorizationservice.model.ERole;
import com.java.petrovsm.authorizationservice.model.Role;
import com.java.petrovsm.authorizationservice.model.User;
import com.java.petrovsm.authorizationservice.repository.RoleRepository;
import com.java.petrovsm.authorizationservice.repository.UserRepository;
import com.java.petrovsm.authorizationservice.security.jwt.JwtUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtils jwtUtils;
    private final TokenService tokenService;

    @Transactional
    public JwtResponse authenticateUser(LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getLogin(), loginRequest.getPassword()));

        User user = userRepository.findByLogin(loginRequest.getLogin())
                .orElseThrow(() -> new RuntimeException("Пользователь не найден"));

        user.setLastLoginTime(Instant.now());
        userRepository.save(user);

        tokenService.revokeAllUserTokens(user);

        String accessToken = jwtUtils.generateAccessToken(authentication);
        String refreshToken = jwtUtils.generateRefreshToken(user.getLogin());

        tokenService.createRefreshToken(user, refreshToken);

        List<String> roles = user.getRoles().stream()
                .map(role -> role.getName().name())
                .toList();

        return new JwtResponse(
                accessToken,
                refreshToken,
                user.getId(),
                user.getLogin(),
                user.getEmail(),
                roles
        );
    }

    @Transactional
    public String registerUser(SignupRequest signupRequest) {
        if (userRepository.existsByLogin(signupRequest.getLogin())) {
            throw new RuntimeException("Логин уже используется!");
        }

        if (userRepository.existsByEmail(signupRequest.getEmail())) {
            throw new RuntimeException("Email уже используется!");
        }

        User user = new User();
        user.setLogin(signupRequest.getLogin());
        user.setEmail(signupRequest.getEmail());
        user.setPassword(passwordEncoder.encode(signupRequest.getPassword()));

        Set<String> strRoles = signupRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null || strRoles.isEmpty()) {
            Role guestRole = roleRepository.findByName(ERole.ROLE_GUEST)
                    .orElseThrow(() -> new RoleNotFoundException("Роль GUEST не найдена"));
            roles.add(guestRole);
        } else {
            strRoles.forEach(role -> {
                switch (role.toLowerCase()) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RoleNotFoundException("Роль ADMIN не найдена"));
                        roles.add(adminRole);
                        break;
                    case "premium_user":
                    case "premium":
                        Role premiumRole = roleRepository.findByName(ERole.ROLE_PREMIUM_USER)
                                .orElseThrow(() -> new RoleNotFoundException("Роль PREMIUM_USER не найдена"));
                        roles.add(premiumRole);
                        break;
                    case "guest":
                    default:
                        Role guestRole = roleRepository.findByName(ERole.ROLE_GUEST)
                                .orElseThrow(() -> new RoleNotFoundException("Роль GUEST не найдена"));
                        roles.add(guestRole);
                }
            });
        }

        user.setRoles(roles);
        userRepository.save(user);

        String roleNames = roles.stream()
                .map(role -> role.getName().name().replace("ROLE_", ""))
                .reduce((a, b) -> a + ", " + b)
                .orElse("GUEST");

        return String.format("Пользователь %s успешно зарегистрир��ван с ролью: %s",
                user.getLogin(), roleNames);
    }

    @Transactional
    public void revokeCurrentToken(Authentication authentication, String currentAccessToken) {
        String username = authentication.getName();
        User user = userRepository.findByLogin(username)
                .orElseThrow(() -> new RuntimeException("Пользователь не найден"));

        tokenService.revokeAllUserTokens(user);

        if (currentAccessToken != null && !currentAccessToken.isEmpty()) {
            tokenService.addAccessTokenToBlacklist(user, currentAccessToken);
            log.info("Access токен пользователя {} добавлен в blacklist", username);
        }

        log.info("Все токены пользователя {} были отозваны", username);
    }
}
