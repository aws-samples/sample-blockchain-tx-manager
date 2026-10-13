# Build stage
# Base images are pinned by digest (multi-arch manifest list); see tx_broadcast_lambda/Dockerfile.
# rust:1.94.1-slim-bookworm
FROM --platform=$BUILDPLATFORM rust@sha256:cf9dd0ec73e75f827fe59123fff9dc65af1a1c8363c3c31ee8d7f8ad0b6a5fb2 AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests first for dependency caching
COPY nonce_manager/Cargo.toml nonce_manager/Cargo.lock ./nonce_manager/
COPY tx_watcher/Cargo.toml tx_watcher/Cargo.lock ./tx_watcher/

# Create dummy source files to build dependencies
RUN mkdir -p nonce_manager/src tx_watcher/src && \
    echo "pub fn dummy() {}" > nonce_manager/src/lib.rs && \
    echo "fn main() {}" > tx_watcher/src/main.rs

# Build dependencies only (cached layer)
WORKDIR /app/tx_watcher
RUN cargo build --release 2>/dev/null || true

# Copy actual source code
WORKDIR /app
COPY nonce_manager/src ./nonce_manager/src
COPY tx_watcher/src ./tx_watcher/src

# Touch to invalidate the dummy files and rebuild with real source
RUN touch nonce_manager/src/lib.rs tx_watcher/src/main.rs

# Build the application
WORKDIR /app/tx_watcher
RUN cargo build --release

# Runtime stage
# debian:trixie-slim (Debian 13.6), pinned by multi-arch manifest digest.
FROM debian@sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132

RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system watcher && useradd --system --gid watcher --no-create-home watcher

WORKDIR /app

# Copy the binary
COPY --from=builder /app/tx_watcher/target/release/tx_watcher /app/tx_watcher

# No chain/table defaults are baked in: the ECS task definition supplies them, and a
# missing value must fail loudly rather than silently watch the wrong chain or table.
ENV RUST_LOG=info

# Non-root. The heartbeat file lives in /tmp, which is writable for the service user.
USER watcher

CMD ["/app/tx_watcher"]
