package com.haris.analyzer_auth_server.jwt_tests.test_doubles;

import com.haris.analyzer_auth_server.config.Jwt.JwtService;
import com.haris.analyzer_auth_server.user.UserRepository;

public class JwtServiceStub extends JwtService {
    private boolean valid;
    private String email;

    public JwtServiceStub(UserRepository userRepository, String secret) {
        super(userRepository, secret);
        this.valid = false;
        this.email = "";
    }

    @Override
    public boolean isValid(String token) {
        return valid;
    }

    public void setValid(boolean valid) {
        this.valid = valid;
    }

    @Override
    public String extractUsername(String token) {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }
}
