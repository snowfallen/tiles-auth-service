# Multi-stage Docker build для Auth Service
#
# Stage 1: Build
# - Uses Maven image
# - Compiles Java code
# - Packages JAR
#
# Stage 2: Runtime
# - Uses slim JRE image
# - Copies JAR from build stage
# - Runs application
#
# Benefits:
# - Small final image (no Maven, no source code)
# - Fast builds (Maven dependencies cached)
# - Production-ready

# ============================================
# Stage 1: Build
# ============================================
FROM maven:3.9-eclipse-temurin-17-alpine AS build

# Set working directory
WORKDIR /app

# Copy pom.xml first (for dependency caching)
# Docker caches layers, so if pom.xml unchanged → skip dependency download
COPY pom.xml .

# Download dependencies (cached layer if pom.xml unchanged)
RUN mvn dependency:go-offline -B

# Copy source code
COPY src ./src

# Build application
# -DskipTests: skip tests (run tests in CI/CD, not in Docker build)
# -B: batch mode (non-interactive)
RUN mvn clean package -DskipTests -B

# Verify JAR created
RUN ls -la target/

# ============================================
# Stage 2: Runtime
# ============================================
FROM eclipse-temurin:17-jre-alpine

# Install curl для health checks
RUN apk add --no-cache curl

# Create non-root user для security
# Running as root = security risk
RUN addgroup -S spring && adduser -S spring -G spring

# Set working directory
WORKDIR /app

# Copy JAR from build stage
# --from=build: copy from previous stage
COPY --from=build /app/target/auth-service-*.jar app.jar

# Change ownership до spring user
RUN chown spring:spring app.jar

# Switch до non-root user
USER spring:spring

# Expose port
EXPOSE 8084

# Health check
# Kubernetes використовує це для liveness/readiness probes
HEALTHCHECK --interval=30s --timeout=3s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8084/actuator/health || exit 1

# Run application
# -XX:+UseContainerSupport: JVM aware of container memory limits
# -XX:MaxRAMPercentage=75.0: use max 75% of container memory
# -Djava.security.egd=file:/dev/./urandom: faster startup (better random)
ENTRYPOINT ["java", \
    "-XX:+UseContainerSupport", \
    "-XX:MaxRAMPercentage=75.0", \
    "-Djava.security.egd=file:/dev/./urandom", \
    "-jar", \
    "app.jar"]
