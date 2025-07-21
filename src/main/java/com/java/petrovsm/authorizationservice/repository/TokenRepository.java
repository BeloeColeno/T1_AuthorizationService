package com.java.petrovsm.authorizationservice.repository;

import com.java.petrovsm.authorizationservice.model.Token;
import com.java.petrovsm.authorizationservice.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Repository
public interface TokenRepository extends JpaRepository<Token, Long> {
    List<Token> findByUserAndRevokedFalseAndTokenType(User user, Token.TokenType tokenType);
    Optional<Token> findByToken(String token);
    boolean existsByTokenAndRevokedFalse(String token);

    @Query("SELECT t FROM Token t WHERE t.user.id = :userId AND t.revoked = false")
    List<Token> findAllValidTokensByUser(Long userId);

    void deleteByUserAndTokenType(User user, Token.TokenType tokenType);
    void deleteByExpiryDateBefore(Instant expiryDate);
}
