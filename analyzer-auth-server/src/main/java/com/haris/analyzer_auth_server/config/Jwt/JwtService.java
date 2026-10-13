package com.haris.analyzer_auth_server.config.Jwt;

import com.haris.analyzer_auth_server.user.User;
import com.haris.analyzer_auth_server.user.UserRepository;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.*;

/**
 * Service class that handles everything related to JWT authentication. It creates JWTs, parses and verifies JWTs.
 */
@Service
public class JwtService {
    private final UserRepository userRepository;
    private final SecretKey secretKey;

    public JwtService(UserRepository userRepository,
                      @Value("${jwt.secret}") String secret) {
        this.userRepository = userRepository;
        this.secretKey = getSecretkey(secret);
    }

    public String generateToken(User user) {
        // call generateToken with no extra claims
        return generateToken(user, new HashMap<>());
    }

    public String generateToken(User user, Map<String, Object> extraClaims) {
        // Build token and return it
        return Jwts.builder()
                .subject(user.getEmail())
                .issuedAt(Date.from(Instant.now()))
                .expiration(new Date(System.currentTimeMillis() + (60 * 60 * 1000))) //60 minutes
                .claims().add(extraClaims).and()
                .signWith(secretKey, Jwts.SIG.HS256)
                .compact();
    }

    public boolean isValid(String token) {
        // Parse token (this also verifies and validates token; throws specific exceptions for invalid tokens)
        String email;
        try {
            email = extractUsername(token);
        } catch (Exception e) {
            //System.out.println(e.getMessage());
            return false;
        }

        // Check that the user exists
        return userRepository.existsByEmail(email);
    }

    /**
     * Parses a given token, and extracts the "subject" claim of a JWT, which should be the username/email.
     * @param token JWT token as a string, from the header of a request.
     * @return a string containing the username
     */
    public String extractUsername(String token) {
        return tokenClaims(token).getSubject();
    }

    private Claims tokenClaims(String token) {
        return Jwts.parser()
                .verifyWith(secretKey) //get the key of the auth server, which the parser will use to verify.
                .build()
                .parseSignedClaims(token)
                .getPayload(); //parse all signed claims. This gives access to the Header and Payload.
    }

    private SecretKey getSecretkey(String secret) {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
    }

    public Date extractExpiration(String token) {
        return tokenClaims(token).getExpiration();
    }
}
