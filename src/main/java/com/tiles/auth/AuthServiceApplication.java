package com.tiles.auth;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.core.env.Environment;

import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * Auth Service Application
 *
 * Головний entry point для Authentication Service.
 *
 * RESPONSIBILITIES:
 * ═══════════════
 * - User authentication (login/register)
 * - JWT token generation (RS256 algorithm)
 * - Refresh token management (Redis storage)
 * - JWKS endpoint для public key distribution
 * - User session tracking
 *
 * TECH STACK:
 * ═══════════
 * - Spring Boot 3.3.0
 * - Spring Security (authentication & password hashing)
 * - Spring Data JPA (PostgreSQL для users/roles)
 * - Spring Data Redis (refresh tokens storage)
 * - Liquibase (database migrations)
 * - JJWT 0.12.5 (JWT operations)
 *
 * ARCHITECTURE:
 * ═════════════
 * - Microservice architecture
 * - Stateless authentication (JWT-based)
 * - Config від Config Server
 * - Database: PostgreSQL (persistent user data)
 * - Cache: Redis (temporary refresh tokens)
 * - RSA keys: RS256 algorithm (production-ready)
 *
 * SECURITY:
 * ═════════
 * - Passwords: BCrypt hashing (10 rounds)
 * - JWT: RS256 signature (2048-bit RSA keys)
 * - Refresh tokens: UUID + Redis TTL (7 days)
 * - Token rotation: old refresh token revoked при refresh
 * - Session tracking: можливість logout all devices
 *
 * @author snowfallen
 * @version 1.0.0
 * @since 2024-10-31
 */
@SpringBootApplication
@Slf4j
public class AuthServiceApplication {

    /**
     * Main method - application entry point
     *
     * Запускає Spring Boot application context.
     * Spring Boot автоматично:
     * - Налаштовує embedded Tomcat server
     * - Сканує components (@Service, @Controller, тощо)
     * - Конфігурує beans
     * - Підключається до databases (PostgreSQL, Redis)
     * - Запускає Liquibase migrations
     *
     * @param args command line arguments
     */
    public static void main(String[] args) {
        SpringApplication.run(AuthServiceApplication.class, args);
    }

    /**
     * Application Ready Event Handler
     *
     * Виконується коли application повністю initialized і ready.
     * Moment коли всі beans created, databases connected, migrations finished.
     *
     * LOGS IMPORTANT INFO:
     * ══════════════════════
     * - Application name
     * - Active Spring profiles (dev/prod/test)
     * - Server port
     * - Local access URL (localhost)
     * - External access URL (network IP)
     * - Available REST endpoints
     *
     * Корисно для:
     * - Quick debugging (бачиш URLs одразу)
     * - Testing (можеш скопіювати URL)
     * - Development (швидкий доступ до endpoints)
     *
     * @param event ApplicationReadyEvent від Spring Boot
     */
    @EventListener(ApplicationReadyEvent.class)
    public void onApplicationReady(ApplicationReadyEvent event) {
        // Get Spring Environment для читання properties
        Environment env = event.getApplicationContext().getEnvironment();

        // Extract application properties
        String appName = env.getProperty("spring.application.name", "auth-service");
        String port = env.getProperty("server.port", "8084");
        String profiles = String.join(", ", env.getActiveProfiles());

        // Default profile якщо не заданий
        if (profiles.isEmpty()) {
            profiles = "default";
        }

        try {
            // Get host IP address для external URL
            String hostAddress = InetAddress.getLocalHost().getHostAddress();

            // Log startup info з красивим форматуванням
            log.info("""
                
                ════════════════════════════════════════════════════════════════
                🚀 Application '{}' is running!
                ════════════════════════════════════════════════════════════════
                
                📍 Access URLs:
                   Local:      http://localhost:{}
                   External:   http://{}:{}
                
                🔧 Profile(s):  {}
                
                📋 Available Endpoints:
                   POST   /auth/login              - User login
                   POST   /auth/register           - User registration
                   POST   /auth/refresh            - Refresh access token
                   POST   /auth/logout             - Logout (revoke token)
                   POST   /auth/logout-all         - Logout all devices
                   GET    /.well-known/jwks.json   - JWKS endpoint (public key)
                   GET    /.well-known/health      - JWKS health check
                   GET    /actuator/health         - Application health
                   GET    /actuator/info           - Application info
                   GET    /actuator/liquibase      - Database migrations
                
                ════════════════════════════════════════════════════════════════
                """,
                    appName,
                    port,
                    hostAddress,
                    port,
                    profiles
            );

        } catch (UnknownHostException e) {
            log.warn("Unable to determine host address", e);
        }
    }
}
