package com.haris.analyzer_auth_server.config.Jwt;

import com.haris.analyzer_auth_server.user.User;
import com.haris.analyzer_auth_server.user.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Optional;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final UserRepository userRepository;

    public JwtAuthFilter(JwtService jwtService, UserRepository userRepository) {
        this.jwtService = jwtService;
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {
        // Get the token from request Authorization header (Bearer schema), and validate it is a standard jwt token.
        // JWT format: header.payload.signature
        final String authHeader = request.getHeader("Authorization");
        final String tokenPrefix = "Bearer "; //using bearer schema

        if(authHeader == null || !authHeader.startsWith(tokenPrefix)) {
            filterChain.doFilter(request, response);
            return;
        }

        // User should not already be authenticated
        if(SecurityContextHolder.getContext().getAuthentication() instanceof UsernamePasswordAuthenticationToken) {
            throw new ServletException("Request can't already be authenticated");
        }

        // Validate the token
        final String token = authHeader.substring(tokenPrefix.length());

        if(!jwtService.isValid(token)) {
            filterChain.doFilter(request, response);
            return;
        }

        // Get user's email from token payload
        final String userEmail = jwtService.extractUsername(token);

        if(userEmail != null) {
            Optional<User> user = userRepository.findByEmail(userEmail);

            // Check user exists
            if(user.isPresent()) {
                // Create an authentication token, and give it to the SecurityContextHolder
                // to show that the user is authenticated
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        user,
                        null,
                        new ArrayList<>());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        filterChain.doFilter(request, response);
    }
}
