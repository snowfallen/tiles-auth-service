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
 * Налаштування Spring Data Redis для:
 * - Connection до Redis
 * - Serialization (Java objects ↔ Redis bytes)
 * - RedisTemplate (high-level Redis operations)
 *
 * Redis використовується для:
 * - Refresh tokens storage
 * - User sessions tracking
 * - Rate limiting (future)
 * - Cache (future)
 */
@Configuration
@Slf4j
public class RedisConfig {

    @Value("${spring.data.redis.host}")
    private String redisHost;

    @Value("${spring.data.redis.port}")
    private Integer redisPort;

    @Value("${spring.data.redis.password}")
    private String redisPassword;

    /**
     * Redis Connection Factory
     *
     * Creates connections до Redis server.
     * Uses Lettuce (async Redis client).
     *
     * Lettuce vs Jedis:
     * - Lettuce: async, reactive, thread-safe
     * - Jedis: sync, blocking, NOT thread-safe
     *
     * Lettuce = modern choice, Spring Boot default
     */
    @Bean
    public RedisConnectionFactory redisConnectionFactory() {
        log.info("Configuring Redis connection to {}:{}", redisHost, redisPort);

        // Configure Redis connection
        RedisStandaloneConfiguration config = new RedisStandaloneConfiguration();
        config.setHostName(redisHost);
        config.setPort(redisPort);
        config.setPassword(redisPassword);

        // Set database index (0-15 available by default)
        config.setDatabase(0);  // Default database

        // Create Lettuce connection factory
        return new LettuceConnectionFactory(config);
    }

    /**
     * Redis Template
     *
     * High-level abstraction для Redis operations.
     *
     * Operations:
     * - opsForValue(): String operations (SET, GET)
     * - opsForHash(): Hash operations (HSET, HGET)
     * - opsForList(): List operations (LPUSH, RPOP)
     * - opsForSet(): Set operations (SADD, SMEMBERS)
     * - opsForZSet(): Sorted Set operations
     *
     * Serialization:
     * - Key: String (UTF-8)
     * - Value: JSON (via Jackson)
     * - Hash Key: String
     * - Hash Value: JSON
     *
     * Example usage:
     * redisTemplate.opsForValue().set("key", "value");
     * String value = redisTemplate.opsForValue().get("key");
     */
    @Bean
    public RedisTemplate<String, String> redisTemplate(
            RedisConnectionFactory connectionFactory) {

        RedisTemplate<String, String> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);

        // Configure serializers

        // Key serializer: String → UTF-8 bytes
        StringRedisSerializer stringSerializer = new StringRedisSerializer();
        template.setKeySerializer(stringSerializer);
        template.setHashKeySerializer(stringSerializer);

        // Value serializer: Object → JSON
        GenericJackson2JsonRedisSerializer jsonSerializer =
                new GenericJackson2JsonRedisSerializer(objectMapper());
        template.setValueSerializer(jsonSerializer);
        template.setHashValueSerializer(jsonSerializer);

        // Initialize template
        template.afterPropertiesSet();

        log.info("RedisTemplate configured successfully");
        return template;
    }

    /**
     * Object Mapper для JSON serialization
     *
     * Configured для proper handling:
     * - Java 8+ date/time (LocalDateTime, Instant, тощо)
     * - Pretty printing (optional, для debugging)
     * - Ignore unknown properties
     *
     * Використовується RedisTemplate для serialization objects → JSON.
     */
    @Bean
    public ObjectMapper objectMapper() {
        ObjectMapper mapper = new ObjectMapper();

        // Register Java 8 date/time module
        // Supports LocalDateTime, Instant, ZonedDateTime, тощо
        mapper.registerModule(new JavaTimeModule());

        // Disable writing dates as timestamps
        // Dates будуть як ISO-8601 strings: "2024-10-30T10:30:00"
        mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

        // Pretty print JSON (optional, для debugging)
        // Disable в production для менших розмірів
        // mapper.enable(SerializationFeature.INDENT_OUTPUT);

        return mapper;
    }
}
