# ---- Stage 1: build ----
# Full Maven + JDK image. Large (~500MB+), but it never ships -- only its
# OUTPUT (the jar) survives into the final image.
FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /build

# Copy pom.xml FIRST, separately from the source code. This is a deliberate
# Docker layer-caching trick: as long as pom.xml doesn't change, Docker
# reuses the cached "dependencies downloaded" layer on every rebuild,
# instead of re-downloading the entire internet every time you edit a
# single Java file.
COPY pom.xml .
RUN mvn dependency:go-offline -B

COPY src ./src
RUN mvn clean package -DskipTests -B

# ---- Stage 2: runtime ----
# JRE only (no compiler, no Maven, no build tools) -- this is the image
# that actually ships and runs. Alpine-based: small footprint.
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app

# Run as a non-root user -- if this container is ever compromised, the
# attacker doesn't get root inside it for free. Small habit, real hardening.
RUN addgroup -S cerberus && adduser -S cerberus -G cerberus
USER cerberus

COPY --from=build /build/target/*.jar app.jar

EXPOSE 8080

# Docker's own health check -- separate from Spring's, this is what
# `docker compose ps` reads to report "healthy". Alpine ships busybox,
# which includes a minimal wget -- no need to install curl separately.
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=5 \
    CMD wget --spider -q http://localhost:8080/swagger-ui.html || exit 1

ENTRYPOINT ["java", "-jar", "app.jar"]
