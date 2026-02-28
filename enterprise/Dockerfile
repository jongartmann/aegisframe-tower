# ============================================================
# AegisFrame PSCP Hardware Proof Container (Rust)
# X-Loop³ Labs · Patent Pending · USPTO 63/983,493
#
# Proves Pre-Semantic control via:
#   1. NVML GPU counter attestation
#   2. eBPF kernel-level socket monitoring
#   3. Process isolation proof via /proc + cgroups
# ============================================================

# --- Build Stage ---
FROM rust:1.83-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy workspace manifest
COPY Cargo.toml /build/Cargo.toml

# Copy enterprise crate
COPY enterprise/Cargo.toml /build/enterprise/Cargo.toml
COPY enterprise/src/ /build/enterprise/src/

# Create stub render crate so workspace resolves
RUN mkdir -p /build/render/src && echo 'fn main() {}' > /build/render/src/main.rs
COPY render/Cargo.toml /build/render/Cargo.toml

# Build release binary
RUN cargo build --release -p aegisframe-enterprise

# --- Runtime Stage ---
FROM nvidia/cuda:12.2.0-base-ubuntu22.04

ENV DEBIAN_FRONTEND=noninteractive

# System deps: eBPF tools, openssl (for TSA), curl
RUN apt-get update && apt-get install -y --no-install-recommends \
    bpfcc-tools bpftrace linux-headers-generic \
    openssl curl procps iproute2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy binary from build stage
COPY --from=builder /build/target/release/aegisframe-enterprise /app/aegisframe-enterprise

# Copy static assets
COPY enterprise/static/ /app/static/

WORKDIR /app

# eBPF needs privileged or CAP_BPF + CAP_SYS_ADMIN
# GPU needs --gpus all
# Both set in docker-compose.yml

EXPOSE 10000

CMD ["/app/aegisframe-enterprise"]
