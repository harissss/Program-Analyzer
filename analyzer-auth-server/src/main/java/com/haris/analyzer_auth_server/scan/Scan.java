package com.haris.analyzer_auth_server.scan;

import jakarta.persistence.*;

import java.time.Instant;
import java.util.Date;
import java.util.UUID;

@Entity
public class Scan {
    @Id
    @GeneratedValue(strategy=GenerationType.UUID)
    private UUID scanId;

    @Column(nullable = false)
    private UUID userId;

    @Column(nullable = false, updatable = false)
    private final Instant createdAt = Instant.now();

    @Column(nullable = false)
    private ScanStatus status;

    private Date completedAt;

    public Scan(UUID userId) {
        this.userId = userId;
    }

    public Scan() {
    }

    public Date getCompletedAt() {
        return completedAt;
    }

    public void setCompletedAt(Date completedAt) {
        this.completedAt = completedAt;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public ScanStatus getStatus() {
        return status;
    }

    public void setStatus(ScanStatus status) {
        this.status = status;
    }

    public UUID getScanId() {
        return scanId;
    }

    public void setScanId(UUID scanId) {
        this.scanId = scanId;
    }

    public UUID getUserId() {
        return userId;
    }

    public void setUserId(UUID userId) {
        this.userId = userId;
    }
}
