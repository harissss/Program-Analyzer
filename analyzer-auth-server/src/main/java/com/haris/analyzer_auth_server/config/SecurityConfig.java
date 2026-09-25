package com.haris.analyzer_auth_server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration 
class SecurityConfig {
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
        http.csrf(csrf -> csrf.disable());
        return http.build();
    }
}
