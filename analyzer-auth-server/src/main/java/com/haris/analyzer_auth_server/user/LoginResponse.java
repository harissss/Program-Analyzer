package com.haris.analyzer_auth_server.user;

public record LoginResponse(String accessToken, String tokenType, String expiration, String message) {
}
