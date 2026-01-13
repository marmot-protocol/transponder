# Build stage
FROM rust:1.90-alpine AS builder

# Install build dependencies
RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static pkgconfig sqlite-dev

WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Create a dummy main.rs to build dependencies
RUN mkdir -p src && \
    echo "fn main() {}" > src/main.rs

# Build dependencies only (this layer will be cached)
RUN cargo build --release && rm -rf src

# Copy actual source code
COPY src ./src
COPY config ./config

# Build the application
RUN touch src/main.rs && cargo build --release

# Runtime stage
FROM alpine:3.21

# Install runtime dependencies
RUN apk add --no-cache ca-certificates

# Create non-root user
RUN addgroup -S transponder && adduser -S transponder -G transponder

# Copy binary from builder
COPY --from=builder /app/target/release/transponder /usr/local/bin/transponder

# Copy default config
COPY --from=builder /app/config/default.toml /etc/transponder/config.toml

# Set ownership
RUN chown -R transponder:transponder /etc/transponder

# Switch to non-root user
USER transponder

# Expose health check port
EXPOSE 8080

# Default command
ENTRYPOINT ["transponder"]
CMD ["--config", "/etc/transponder/config.toml"]
