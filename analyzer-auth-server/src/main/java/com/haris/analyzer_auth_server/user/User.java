package com.haris.analyzer_auth_server.user;

import java.time.Instant;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(unique = true, nullable = false)
    private String email;

    @Column(nullable = false)
    private String passwordHash;

    @Column(updatable = false, nullable = false)
    private final Instant createdAt = Instant.now();

    public User() {
    }

    public User(UUID id, String email, String passwordHash) {
        this.id = id; 
        this.email = email;
        this.passwordHash = passwordHash; 
    }
    
    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id; 
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash; 
    }

    public Instant getCreatedAt() {
        return createdAt; 
    }
}