package com.haris.analyzer_auth_server.jwt_tests;

import com.haris.analyzer_auth_server.jwt_tests.test_doubles.UserRepositoryStub;
import com.haris.analyzer_auth_server.user.User;
import com.haris.analyzer_auth_server.config.Jwt.JwtService;

import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class TestJwtService {
    private final JwtService jwtService;
    private final String testEmail = "me123@test.com";
    private final String testPassword = "abcxyz";

    public TestJwtService() {
        String secret = "IBjsiXVNkcPPYWqw+dKcyouP2Pefs71pko8+xeXlfAg=";
        this.jwtService = new JwtService(new UserRepositoryStub(), secret);
    }

    @Test
    public void extractUsernameIsCorrect() {
        //Given the JwtService
        //When a token is generated
        final String token = jwtService.generateToken(new User(testEmail, testPassword));

        //Then extractUsername returns the same email
        assertTrue(testEmail.equals(jwtService.extractUsername(token)));
    }

    @Test
    public void generatedTokensAreValid() {
        //Given the JwtService
        //When a token is generated
        final String token = jwtService.generateToken(new User(testEmail, testPassword));

        //Then this token should be valid, assuming user with email exists (this is true for UserRepositoryStub)
        assertTrue(jwtService.isValid(token));
    }

    @Test
    public void jwtWithoutSignatureIsInvalid() {
        //Given the JwtService
        //When a token is generated
        final String token = jwtService.generateToken(new User(testEmail, testPassword));

        //If it doesn't contain the signature
        final String[] tokenParts = token.split("\\.");
        assertTrue(tokenParts.length == 3);
        final String noSignatureToken = tokenParts[0] + "." + tokenParts[1];

        //Then this token should be invalid, since it doesn't have a signature
        assertFalse(jwtService.isValid(noSignatureToken));
    }

    @Test
    public void jwtWithWrongSignatureIsInvalid() {
        //Given the JwtService
        //When a token is generated with signature from wrong key
        final String wrongSignatureToken = new JwtService(
                new UserRepositoryStub(),
                "JBjsiXVNkcPPYWqw+dKcyouP2Pefs71pko8+xeXlfAg=") //changed the first letter of secret
                        .generateToken(new User(testEmail, testPassword));


        //Then this token should be invalid, since it has a signature that was generated with a wrong key
        assertFalse(jwtService.isValid(wrongSignatureToken));
    }

    @Test
    public void expiredJwtIsInvalid() {
        //Given the JwtService
        //When a token is generated
        Map<String, Object> expirationClaim = new HashMap<>();
        //...see https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.4
        expirationClaim.put("exp", new Date(System.currentTimeMillis() - (60*1000)));
        final String expiredToken = jwtService.generateToken(
                new User(testEmail, testPassword),
                expirationClaim);

        //then this token should be invalid
        assertFalse(jwtService.isValid(expiredToken));
    }

    @Test
    public void garbageTokenIsInvalid() {
        //Given the JwtService
        //When a garbage token is generated
        final String garbageToken = "APawibgpawibtAB.AWIBTjbaltjwbtaWT.AIWPBTYblakdbysi";

        //Then it should be invalid (with high probability)
        assertFalse(jwtService.isValid(garbageToken));
    }

    @Test
    public void tamperedPayloadIsInvalid() {
        //Given the JwtService
        //When a valid token is generated
        final String token = jwtService.generateToken(new User(testEmail, testPassword));

        //If the payload is tampered with
        final String[] tokenParts = token.split("\\.");
        assertTrue(tokenParts.length == 3);
        final String payload = tokenParts[1];
        assertTrue(payload.length() > 5);
        final String tamperedPayload =
                payload.substring(0,3) + (payload.charAt(3) + 1) + payload.substring(4);
        final String tamperedPayloadToken = tokenParts[0] + "." + tamperedPayload + "." + tokenParts[2];

        //Then the tampered token should be invalid
        assertFalse(jwtService.isValid(tamperedPayloadToken));
    }

    @Test
    public void tamperedHeaderIsInvalid() {
        //Given the JwtService
        //When a valid token is generated
        final String token = jwtService.generateToken(new User(testEmail, testPassword));

        //If the payload is tampered with
        final String[] tokenParts = token.split("\\.");
        assertTrue(tokenParts.length == 3);
        final String header = tokenParts[0];
        assertTrue(header.length() > 5);
        final String tamperedHeader =
                header.substring(0,3) + (header.charAt(3) + 1) + header.substring(4);
        final String tamperedHeaderToken = tokenParts[0] + "." + tamperedHeader + "." + tokenParts[2];

        //Then the tampered token should be invalid
        assertFalse(jwtService.isValid(tamperedHeaderToken));
    }
}
