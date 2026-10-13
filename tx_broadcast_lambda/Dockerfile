# Build stage using AWS Lambda Rust runtime
# Base images are pinned by digest (multi-arch manifest list) so a tag re-push upstream
# cannot change what this repository builds. Refresh deliberately, with the tag comment.
# rust:1.94.1-slim-bookworm
FROM --platform=$BUILDPLATFORM rust@sha256:cf9dd0ec73e75f827fe59123fff9dc65af1a1c8363c3c31ee8d7f8ad0b6a5fb2 AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    zip \
    git \
    curl \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Install Zig (required by cargo-lambda for cross-compilation), arch-aware with a
# pinned checksum per architecture (from https://ziglang.org/download/index.json).
# The builder stage runs on the BUILDPLATFORM (arm64 on Apple Silicon, x86_64 in CI),
# so both variants are pinned and the build fails if either archive changes.
ARG ZIG_VERSION=0.13.0
ARG ZIG_SHA256_X86_64=d45312e61ebcc48032b77bc4cf7fd6915c11fa16e4aad116b66c9468211230ea
ARG ZIG_SHA256_AARCH64=041ac42323837eb5624068acd8b00cd5777dac4cf91179e8dad7a7e90dd0c556
RUN set -eux; \
    arch="$(uname -m)"; \
    case "$arch" in \
      x86_64)  zig_arch=x86_64;  zig_sha="${ZIG_SHA256_X86_64}" ;; \
      aarch64) zig_arch=aarch64; zig_sha="${ZIG_SHA256_AARCH64}" ;; \
      *) echo "unsupported build arch: $arch" >&2; exit 1 ;; \
    esac; \
    curl -LsSf --retry 5 --retry-all-errors --retry-delay 5 -o /tmp/zig.tar.xz "https://ziglang.org/download/${ZIG_VERSION}/zig-linux-${zig_arch}-${ZIG_VERSION}.tar.xz"; \
    echo "${zig_sha}  /tmp/zig.tar.xz" | sha256sum -c -; \
    tar -xJ -C /usr/local -f /tmp/zig.tar.xz; \
    ln -s "/usr/local/zig-linux-${zig_arch}-${ZIG_VERSION}/zig" /usr/local/bin/zig; \
    rm /tmp/zig.tar.xz

# Install uv from a pinned GitHub release with its published checksum (never
# `curl | sh`), then a pinned cargo-lambda through it. Arch-aware like zig above.
ARG UV_VERSION=0.12.12
ARG UV_SHA256_X86_64=ab9b309d4586403f024e100abaceb396616e178a553e2500c36087d180f09509
ARG UV_SHA256_AARCH64=fe08db50cc1b56cd1da7801065ed1103d27ed3f9571cd122386cfc7faf1b8df5
ARG CARGO_LAMBDA_VERSION=1.9.2
RUN set -eux; \
    arch="$(uname -m)"; \
    case "$arch" in \
      x86_64)  uv_arch=x86_64;  uv_sha="${UV_SHA256_X86_64}" ;; \
      aarch64) uv_arch=aarch64; uv_sha="${UV_SHA256_AARCH64}" ;; \
      *) echo "unsupported build arch: $arch" >&2; exit 1 ;; \
    esac; \
    curl -LsSf --retry 5 --retry-all-errors --retry-delay 5 -o /tmp/uv.tar.gz "https://github.com/astral-sh/uv/releases/download/${UV_VERSION}/uv-${uv_arch}-unknown-linux-gnu.tar.gz"; \
    echo "${uv_sha}  /tmp/uv.tar.gz" | sha256sum -c -; \
    tar -xz -C /usr/local/bin --strip-components=1 -f /tmp/uv.tar.gz "uv-${uv_arch}-unknown-linux-gnu/uv"; \
    rm /tmp/uv.tar.gz; \
    uv tool install "cargo-lambda==${CARGO_LAMBDA_VERSION}"

ENV PATH="/root/.local/bin:${PATH}"

# Copy manifests first for dependency caching
COPY nonce_manager/Cargo.toml nonce_manager/Cargo.lock ./nonce_manager/
COPY tx_broadcast_lambda/Cargo.toml tx_broadcast_lambda/Cargo.lock ./tx_broadcast_lambda/

# Create dummy source files to build dependencies
RUN mkdir -p nonce_manager/src tx_broadcast_lambda/src && \
    echo "pub fn dummy() {}" > nonce_manager/src/lib.rs && \
    echo "fn main() {}" > tx_broadcast_lambda/src/main.rs

# Build dependencies only (cached layer)
WORKDIR /app/tx_broadcast_lambda
RUN cargo lambda build --release --arm64 2>/dev/null || true

# Copy actual source code
WORKDIR /app
COPY nonce_manager/src ./nonce_manager/src
COPY tx_broadcast_lambda/src ./tx_broadcast_lambda/src

# Touch to invalidate the dummy files
RUN touch nonce_manager/src/lib.rs tx_broadcast_lambda/src/main.rs

# Build the Lambda function
WORKDIR /app/tx_broadcast_lambda
RUN cargo lambda build --release --arm64

# Runtime stage - AWS Lambda provided.al2023 base
# public.ecr.aws/lambda/provided:al2023-arm64 (2026-09-14)
FROM public.ecr.aws/lambda/provided@sha256:b501fd60cfbd920688576f5cfd6040bf3533a15ce160673758c77ca2dabd312e

# The base digest fixes the starting filesystem; install vendor security errata published
# after that image was cut, then record the resulting exact image digest in release evidence.
RUN dnf --releasever=latest upgrade -y \
    && dnf clean all \
    && rm -rf /var/cache/dnf

# Copy the bootstrap binary
COPY --from=builder /app/tx_broadcast_lambda/target/lambda/tx_broadcast_lambda/bootstrap ${LAMBDA_RUNTIME_DIR}/bootstrap

# Set the handler
CMD ["bootstrap"]
