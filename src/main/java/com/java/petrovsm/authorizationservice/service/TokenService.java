package com.java.petrovsm.authorizationservice.service;

import com.java.petrovsm.authorizationservice.model.Token;
import com.java.petrovsm.authorizationservice.model.User;
import com.java.petrovsm.authorizationservice.repository.TokenRepository;
import com.java.petrovsm.authorizationservice.repository.UserRepository;
import com.java.petrovsm.authorizationservice.security.jwt.JwtUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

@Service
@RequiredArgsConstructor
@Slf4j
public class TokenService {

    private final TokenRepository tokenRepository;
    private final JwtUtils jwtUtils;
    private final UserRepository userRepository;

    @Value("${app.jwt.refresh-expiration}")
    private long refreshTokenDuration;

    public Token createRefreshToken(User user, String refreshToken) {
        Token token = new Token();
        token.setUser(user);
        token.setToken(refreshToken);
        token.setExpiryDate(Instant.now().plusMillis(refreshTokenDuration));
        token.setTokenType(Token.TokenType.REFRESH);
        token.setRevoked(false);

        tokenRepository.deleteByUserAndTokenType(user, Token.TokenType.REFRESH);

        return tokenRepository.save(token);
    }

    public void addAccessTokenToBlacklist(User user, String accessToken) {
        Token token = new Token();
        token.setUser(user);
        token.setToken(accessToken);
        token.setExpiryDate(jwtUtils.getExpirationFromToken(accessToken));
        token.setTokenType(Token.TokenType.ACCESS);
        token.setRevoked(true);

        tokenRepository.save(token);
    }

    @Transactional
    public void revokeAllUserTokens(User user) {
        var validUserTokens = tokenRepository.findAllValidTokensByUser(user.getId());
        if (validUserTokens.isEmpty()) {
            return;
        }

        validUserTokens.forEach(token -> token.setRevoked(true));
        tokenRepository.saveAll(validUserTokens);
        log.info("Отозваны все токены пользователя: {}", user.getLogin());
    }

    public boolean isTokenRevoked(String tokenValue) {
        return tokenRepository.findByToken(tokenValue)
                .map(Token::isRevoked)
                .orElse(false);
    }

    public boolean isTokenExpiredByReLogin(String tokenValue, String username) {
        try {
            Instant tokenLoginTime = jwtUtils.getLoginTimeFromToken(tokenValue);
            if (tokenLoginTime == null) {
                return false;
            }

            User user = userRepository.findByLogin(username).orElse(null);
            if (user == null || user.getLastLoginTime() == null) {
                return false;
            }

            return tokenLoginTime.isBefore(user.getLastLoginTime());
        } catch (Exception e) {
            log.error("Ошибка при проверке времени создания токена: {}", e.getMessage());
            return false;
        }
    }
}
