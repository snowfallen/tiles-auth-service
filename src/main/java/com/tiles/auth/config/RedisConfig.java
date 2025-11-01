package com.tiles.auth.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

/**
 * Redis Configuration
 *
 * Налаштування Spring Data Redis для Auth Service.
 *
 * RESPONSIBILITIES:
 * ═══════════════
 * - Redis connection configuration
 * - Serialization setup (Java ↔ Redis)
 * - RedisTemplate configuration
 *
 * REDIS USAGE:
 * ═══════════
 * - Refresh tokens storage (UUID → user data)
 * - User sessions tracking (userId → set of token IDs)
 * - Rate limiting (future)
 * - Cache (future)
 *
 * WHY REDIS:
 * ═════════
 * ✅ In-memory storage (blazing fast)
 * ✅ TTL support (automatic expiration)
 * ✅ Atomic operations (thread-safe)
 * ✅ Data structures (strings, sets, hashes)
 * ✅ Pub/Sub capabilities
 * ✅ Persistence options (RDB, AOF)
 *
 * REDIS DATA MODEL:
 * ════════════════
 *
 * 1. Refresh Tokens:
 * Key: refresh_token:{uuid}
 * Value: JSON {userId, username, email, issuedAt, expiresAt}
 * TTL: 7 days
 *
 * 2. User Sessions:
 * Key: user_session:{userId}
 * Value: Set of refresh token UUIDs
 * TTL: 7 days
 *
 * LETTUCE VS JEDIS:
 * ════════════════
 * Lettuce (ми використовуємо):
 * ✅ Async/reactive support
 * ✅ Thread-safe (one connection для all threads)
 * ✅ Netty-based (non-blocking I/O)
 * ✅ Modern, actively maintained
 * ✅ Spring Boot default
 *
 * Jedis (old client):
 * ❌ Synchronous only
 * ❌ NOT thread-safe (need connection pool)
 * ❌ Blocking I/O
 * ⚠️  Legacy, less active development
 *
 * SERIALIZATION:
 * ═════════════
 * Keys: StringRedisSerializer (UTF-8 strings)
 * Values: GenericJackson2JsonRedisSerializer (JSON)
 *
 * Example:
 * Key: "refresh_token:550e8400-e29b-41d4-a716-446655440000"
 * Value: {"userId":"123","username":"admin",...}
 *
 * @author snowfallen
 * @version 1.0.0
 * @since 2024-10-31
 */
@Configuration
@Slf4j
public class RedisConfig {

    /**
     * Redis Host
     *
     * Hostname або IP address Redis server.
     *
     * Environments:
     * - Local: localhost
     * - Docker: redis
     * - Kubernetes: auth-redis.tiles-infra.svc.cluster.local
     *
     * Loaded від:
     * - application.yml: spring.data.redis.host
     * - Environment variable: SPRING_DATA_REDIS_HOST
     */
    @Value("${spring.data.redis.host}")
    private String redisHost;

    /**
     * Redis Port
     *
     * TCP port Redis server listening.
     *
     * Default: 6379 (standard Redis port)
     *
     * Loaded від:
     * - application.yml: spring.data.redis.port
     * - Environment variable: SPRING_DATA_REDIS_PORT
     */
    @Value("${spring.data.redis.port}")
    private Integer redisPort;

    /**
     * Redis Password
     *
     * Authentication password для Redis server.
     *
     * SECURITY:
     * ════════
     * ⚠️  NEVER commit passwords to Git
     * ⚠️  Use Kubernetes Secrets
     * ⚠️  Rotate passwords periodically
     * ⚠️  Use strong passwords (random, long)
     *
     * Redis ACL (Access Control Lists):
     * Redis 6+ supports granular permissions
     * Example: user auth-service на read/write до specific keys
     *
     * Loaded від:
     * - Kubernetes Secret: auth-redis-secret
     * - Environment variable: REDIS_PASSWORD
     */
    @Value("${spring.data.redis.password}")
    private String redisPassword;

    /**
     * Redis Connection Factory
     *
     * Creates і manages connections до Redis server.
     * Uses Lettuce client (async, reactive, thread-safe).
     *
     * CONFIGURATION:
     * ═════════════
     * - Hostname: від @Value redisHost
     * - Port: від @Value redisPort
     * - Password: від @Value redisPassword
     * - Database: 0 (default Redis database)
     *
     * REDIS DATABASES:
     * ═══════════════
     * Redis supports 16 databases (0-15) by default.
     * Database = namespace для keys (логічна ізоляція).
     *
     * Usage:
     * - Database 0: refresh tokens (our choice)
     * - Database 1: cache
     * - Database 2: rate limiting
     * - тощо
     *
     * Note: Redis Cluster не підтримує multiple databases.
     *
     * LETTUCE FEATURES:
     * ════════════════
     * - Connection pooling: automatic
     * - Auto-reconnect: yes
     * - Cluster support: yes
     * - Sentinel support: yes
     * - SSL/TLS support: yes
     * - Reactive support: yes (Project Reactor)
     *
     * LIFECYCLE:
     * ═════════
     * 1. Spring creates this bean
     * 2. Lettuce creates connection pool
     * 3. Applications uses connections від pool
     * 4. Connections automatically managed (acquire/release)
     * 5. On shutdown, pool gracefully closes
     *
     * @return configured LettuceConnectionFactory
     */
    @Bean
    public RedisConnectionFactory redisConnectionFactory() {
        log.info("Configuring Redis connection to {}:{}", redisHost, redisPort);

        // Create standalone configuration (single Redis instance)
        // For cluster: use RedisClusterConfiguration
        // For sentinel: use RedisSentinelConfiguration
        RedisStandaloneConfiguration config = new RedisStandaloneConfiguration();

        // Set connection parameters
        config.setHostName(redisHost);
        config.setPort(redisPort);
        config.setPassword(redisPassword);

        // Set database index (0-15 available by default)
        // Database 0 = default choice
        config.setDatabase(0);

        // Create Lettuce connection factory
        // Uses default pool configuration:
        // - Max connections: 8
        // - Max idle: 8
        // - Min idle: 0
        // Can customize if needed: LettucePoolingClientConfiguration
        LettuceConnectionFactory factory = new LettuceConnectionFactory(config);

        log.info("Redis connection factory configured successfully");
        return factory;
    }

    /**
     * Redis Template
     *
     * High-level abstraction для Redis operations.
     * Provides typed access до Redis data structures.
     *
     * OPERATIONS:
     * ══════════
     *
     * 1. Value Operations (Strings):
     * ```java
     * redisTemplate.opsForValue().set("key", "value");
     * String value = redisTemplate.opsForValue().get("key");
     * redisTemplate.opsForValue().set("key", "value", Duration.ofHours(1));
     * ```
     *
     * 2. Hash Operations (Maps):
     * ```java
     * redisTemplate.opsForHash().put("user:1", "name", "John");
     * String name = redisTemplate.opsForHash().get("user:1", "name");
     * ```
     *
     * 3. Set Operations:
     * ```java
     * redisTemplate.opsForSet().add("tags", "java", "spring", "redis");
     * Set<String> tags = redisTemplate.opsForSet().members("tags");
     * ```
     *
     * 4. List Operations:
     * ```java
     * redisTemplate.opsForList().rightPush("queue", "task1");
     * String task = redisTemplate.opsForList().leftPop("queue");
     * ```
     *
     * 5. Sorted Set Operations:
     * ```java
     * redisTemplate.opsForZSet().add("leaderboard", "player1", 100);
     * ```
     *
     * SERIALIZATION:
     * ═════════════
     * Automatic conversion між Java objects і Redis bytes.
     *
     * Keys: String → UTF-8 bytes
     * Values: Object → JSON → bytes
     *
     * Example:
     * Java: Map.of("userId", "123", "username", "admin")
     * Redis: {"userId":"123","username":"admin"}
     *
     * WHY JSON:
     * ════════
     * ✅ Human-readable (debugging easier)
     * ✅ Language-agnostic (interoperability)
     * ✅ Flexible schema (can add fields)
     * ✅ Widely supported
     *
     * Alternative: Java serialization (not recommended)
     * ❌ Not human-readable
     * ❌ Java-specific
     * ❌ Brittle (version changes break)
     *
     * @param connectionFactory Redis connection factory
     * @return configured RedisTemplate
     */
    @Bean
    public RedisTemplate<String, String> redisTemplate(
            RedisConnectionFactory connectionFactory) {

        log.debug("Configuring RedisTemplate with JSON serialization...");

        // Create template
        RedisTemplate<String, String> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);

        // ════════════════════════════════════════
        // Configure Serializers
        // ════════════════════════════════════════

        // Key serializer: String → UTF-8 bytes
        // Used for both keys і hash keys
        StringRedisSerializer stringSerializer = new StringRedisSerializer();
        template.setKeySerializer(stringSerializer);
        template.setHashKeySerializer(stringSerializer);

        // Value serializer: Object → JSON
        // Uses Jackson ObjectMapper для conversion
        // Supports Java 8 date/time types (LocalDateTime, Instant, тощо)
        GenericJackson2JsonRedisSerializer jsonSerializer =
                new GenericJackson2JsonRedisSerializer(objectMapper());
        template.setValueSerializer(jsonSerializer);
        template.setHashValueSerializer(jsonSerializer);

        // Initialize template
        // Validates configuration і sets up connections
        template.afterPropertiesSet();

        log.info("RedisTemplate configured successfully");
        return template;
    }

    /**
     * Object Mapper для JSON Serialization
     *
     * Jackson ObjectMapper configured для proper handling
     * Java 8+ date/time types і other features.
     *
     * CONFIGURATION:
     * ═════════════
     *
     * 1. Java 8 Date/Time Module:
     * ──────────────────────────
     * Registers JavaTimeModule для support:
     * - LocalDateTime
     * - LocalDate
     * - LocalTime
     * - Instant
     * - ZonedDateTime
     * - Duration
     * - тощо
     *
     * Without this module:
     * ❌ LocalDateTime serialized as array: [2024,10,31,12,30,0]
     *
     * With this module:
     * ✅ LocalDateTime serialized as string: "2024-10-31T12:30:00"
     *
     * 2. Date Format:
     * ─────────────
     * Disable WRITE_DATES_AS_TIMESTAMPS
     *
     * With timestamps (default):
     * ❌ Date as number: 1698758400000
     *
     * With ISO-8601 (our config):
     * ✅ Date as string: "2024-10-31T12:30:00Z"
     *
     * Benefits:
     * ✅ Human-readable
     * ✅ Time zone information preserved
     * ✅ Standard format (ISO-8601)
     *
     * 3. Pretty Print (optional):
     * ─────────────────────────
     * Currently disabled (commented).
     *
     * Without pretty print:
     * {"userId":"123","username":"admin"}
     *
     * With pretty print:
     * {
     *   "userId": "123",
     *   "username": "admin"
     * }
     *
     * Trade-offs:
     * - Debugging: easier with pretty print
     * - Storage: smaller without pretty print
     * - Network: faster without pretty print
     *
     * Recommendation: disable в production
     *
     * USAGE:
     * ═════
     * This ObjectMapper shared by RedisTemplate
     * для serialization/deserialization всіх values.
     *
     * @return configured ObjectMapper
     */
    @Bean
    public ObjectMapper objectMapper() {
        log.debug("Configuring Jackson ObjectMapper for Redis serialization...");

        ObjectMapper mapper = new ObjectMapper();

        // ════════════════════════════════════════
        // 1. Register Java 8 Date/Time Module
        // ════════════════════════════════════════
        // Enables support для LocalDateTime, Instant, тощо
        mapper.registerModule(new JavaTimeModule());

        log.debug("Registered JavaTimeModule for date/time serialization");

        // ════════════════════════════════════════
        // 2. Disable Writing Dates as Timestamps
        // ════════════════════════════════════════
        // Dates будуть as ISO-8601 strings instead of numeric timestamps
        // Example: "2024-10-31T12:30:00" instead of 1698758400000
        mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

        log.debug("Configured date serialization to ISO-8601 format");

        // ════════════════════════════════════════
        // 3. Pretty Print (optional, disabled)
        // ════════════════════════════════════════
        // Uncomment для easier debugging (but larger payload)
        // mapper.enable(SerializationFeature.INDENT_OUTPUT);

        log.info("ObjectMapper configured successfully");
        return mapper;
    }
}
