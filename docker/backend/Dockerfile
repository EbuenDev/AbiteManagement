# ==============================================================================
# Multi-Stage Production Dockerfile for Enterprise Auth Backend
# ==============================================================================

# --- Stage 1: Build & Package ---
FROM maven:3.9.9-eclipse-temurin-21 AS builder
WORKDIR /workspace

# Cache dependencies layer
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Compile and package application
COPY src ./src
RUN mvn clean package -DskipTests -B

# --- Stage 2: Hardened Runtime ---
FROM eclipse-temurin:21-jre-jammy
WORKDIR /app

# Run as non-root user for container security
RUN groupadd -r appuser && useradd -r -g appuser -d /app appuser
USER appuser:appuser

# Copy built artifact from builder
COPY --from=builder /workspace/target/*.jar app.jar

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=40s \
  CMD curl -f http://localhost:8080/actuator/health || exit 1

ENTRYPOINT ["java", "-XX:+UseG1GC", "-XX:MaxRAMPercentage=75.0", "-jar", "app.jar"]
