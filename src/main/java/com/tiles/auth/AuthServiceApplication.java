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
 * Main entry point для Auth Service.
 *
 * Features:
 * - User authentication
 * - JWT generation (access tokens)
 * - Refresh token management
 * - User registration
 * - JWKS endpoint для Gateway
 *
 * Stack:
 * - Spring Boot 3.3.0
 * - Spring Security
 * - Spring Data JPA (PostgreSQL)
 * - Spring Data Redis
 * - Liquibase (DB migrations)
 * - JJWT (JWT library)
 *
 * Architecture:
 * - Microservice architecture
 * - Stateless (JWT-based auth)
 * - Config from Config Server
 * - Database: PostgreSQL (users, roles)
 * - Cache: Redis (refresh tokens)
 */
@SpringBootApplication
@Slf4j
public class AuthServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthServiceApplication.class, args);
    }

    /**
     * Application Ready Event
     *
     * Виконується коли application повністю initialized.
     *
     * Logs:
     * - Application name
     * - Active profiles
     * - Server port
     * - Local URL
     * - External URL (if available)
     *
     * Корисно для debugging та швидкого доступу до сервісу.
     */
    @EventListener(ApplicationReadyEvent.class)
    public void onApplicationReady(ApplicationReadyEvent event) {
        Environment env = event.getApplicationContext().getEnvironment();

        String appName = env.getProperty("spring.application.name", "auth-service");
        String port = env.getProperty("server.port", "8084");
        String profiles = String.join(", ", env.getActiveProfiles());

        if (profiles.isEmpty()) {
            profiles = "default";
        }

        try {
            String hostAddress = InetAddress.getLocalHost().getHostAddress();

            log.info("""
                
                ----------------------------------------------------------
                Application '{}' is running!
                Access URLs:
                    Local:      http://localhost:{}
                    External:   http://{}:{}
                Profile(s):     {}
                ----------------------------------------------------------
                Available Endpoints:
                    POST   /auth/login           - User login
                    POST   /auth/register        - User registration
                    POST   /auth/refresh         - Refresh access token
                    POST   /auth/logout          - Logout (revoke token)
                    POST   /auth/logout-all      - Logout all devices
                    GET    /.well-known/jwks.json - JWKS endpoint
                    GET    /actuator/health      - Health check
                    GET    /actuator/liquibase   - Database migrations status
                ----------------------------------------------------------
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
