package com.haris.analyzer_auth_server.config;

import com.haris.analyzer_auth_server.config.Jwt.JwtAuthFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
class SecurityConfig {
    private final JwtAuthFilter jwtAuthFilter;

    public SecurityConfig(JwtAuthFilter jwtAuthFilter) {
        this.jwtAuthFilter = jwtAuthFilter;
    }

    /**
        A bean for encoding passwords, using the secure BCrypt password encoder 
        @Return a new BCryptPasswordEncoder object
    */
    @Bean 
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        //disable the built-in automatic login redirect
        http
                .csrf(csrf -> csrf.disable()) //disable cookie based auth
                .authorizeHttpRequests(authorize ->
                        authorize //define endpoints where auth isn't required
                                .requestMatchers("/api/auth/login", "/api/auth/register").permitAll()
                                .anyRequest().authenticated())
                .sessionManagement(session ->
                        //stateless bcs every request is authenticated using JWT
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}
