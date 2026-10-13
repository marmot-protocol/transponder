ARG DHI_RUST_IMAGE=dhi.io/rust:1.95-alpine3.22-dev@sha256:6f183e866caaaa2c306bd1779e43eaaf0d94178d4ddb090c43fbefce231d567c
ARG DHI_STATIC_IMAGE=dhi.io/static:20250419@sha256:74fc43fa240887b8159970e434244039aab0c6efaaa9cf044004cdc22aa2a34d
ARG CARGO_FEATURES=

# Build stage
FROM ${DHI_RUST_IMAGE} AS builder
ARG CARGO_FEATURES

# Install build dependencies
RUN apk add --no-cache musl-dev pkgconfig sqlite-dev

WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./
# SDK patch preserves observable notification-channel overflow.
COPY vendor/nostr-sdk ./vendor/nostr-sdk

# Create a dummy main.rs to build dependencies
RUN mkdir -p src && \
    echo "fn main() {}" > src/main.rs

# Build dependencies only (this layer will be cached)
RUN cargo build --locked --release ${CARGO_FEATURES} && rm -rf src

# Copy actual source code
COPY src ./src
COPY config ./config

# Build the application
RUN touch src/main.rs && cargo build --locked --release ${CARGO_FEATURES}

# Runtime stage
FROM ${DHI_STATIC_IMAGE}

# Copy binary from builder
COPY --from=builder /app/target/release/transponder /bin/transponder

# Copy default config
COPY --from=builder /app/config/default.toml /etc/transponder/config.toml

# Run as an unprivileged user in the final image.
USER 65532:65532

# Expose health check port
EXPOSE 8080

# Default command
ENTRYPOINT ["/bin/transponder"]
CMD ["--config", "/etc/transponder/config.toml"]
