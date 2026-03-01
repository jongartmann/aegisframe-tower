# AegisFrame — Build Guide (Rust)

Complete guide for building, testing, and deploying the Rust edition.

---

## Prerequisites

### Minimal (Standard Build)

| Tool | Version | Installation |
|------|---------|-------------|
| Rust | 1.78+ | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` |
| cargo | (with Rust) | Automatically included with rustup |
| pkg-config | any | `apt install pkg-config` / `brew install pkg-config` |
| OpenSSL dev | 3.x | `apt install libssl-dev` / `brew install openssl` |

### Enterprise Build (GPU + eBPF)

| Tool | Version | Installation |
|------|---------|-------------|
| NVIDIA Driver | 535+ | `apt install nvidia-driver-535` |
| CUDA Toolkit | 12.2+ | NVIDIA CUDA Repository |
| bpftrace | 0.19+ | `apt install bpftrace` |
| bpfcc-tools | any | `apt install bpfcc-tools` |
| Linux Headers | matching kernel | `apt install linux-headers-$(uname -r)` |
| Docker | 24+ | [docker.com](https://docs.docker.com/engine/install/) |
| nvidia-container-toolkit | 1.14+ | [NVIDIA Container Toolkit](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/) |

### Recommended Dev Tools

```bash
# cargo-watch — Auto-rebuild on changes
cargo install cargo-watch

# cargo-nextest — Faster test runner
cargo install cargo-nextest

# cargo-deny — License + dependency auditing
cargo install cargo-deny

# cargo-machete — Find unused dependencies
cargo install cargo-machete
```

## Workspace Structure

AegisFrame uses a Cargo workspace with four crates:

```
Cargo.toml (workspace root)
├── crates/aegis-core/     # Core Logic: Evidence, ECDSA, Hash Chain, Gates
├── crates/aegis-pscp/     # PSCP Hardware Proof Engine
├── crates/aegis-tsa/      # RFC 3161 TSA Client
└── crates/aegis-server/   # Axum HTTP Server
```

### Dependency Graph

```
aegis-server
    ├── aegis-core
    ├── aegis-pscp
    │     └── aegis-core
    └── aegis-tsa
          └── aegis-core
```

`aegis-core` has no dependency on the other crates — it is the base layer.

## Build Commands

### Standard Build (Render / without GPU)

```bash
# Debug build
cargo build

# Release build (optimized)
cargo build --release

# Binary located at:
# target/release/aegis-server
```

### Enterprise Build (GPU + eBPF)

```bash
# Enable all enterprise features
cargo build --release --features enterprise

# GPU only
cargo build --release --features gpu

# eBPF only
cargo build --release --features ebpf
```

### Build Individual Crates

```bash
# Core only
cargo build -p aegis-core

# TSA client only
cargo build -p aegis-tsa

# PSCP engine only (without GPU)
cargo build -p aegis-pscp

# PSCP engine with GPU
cargo build -p aegis-pscp --features gpu
```

## Feature Flags

### Workspace-Level Features

```toml
[workspace.features]
default = ["tsa-live"]
enterprise = ["gpu", "ebpf"]
gpu = ["nvml-wrapper"]
ebpf = []
tsa-live = []
tsa-mock = []
```

### Feature Combinations

| Scenario | Command |
|----------|---------|
| Render (standard) | `cargo build --release` |
| Enterprise (full) | `cargo build --release --features enterprise` |
| GPU tests only | `cargo build --release --features gpu` |
| CI/CD (no network) | `cargo build --release --features tsa-mock` |
| Everything off | `cargo build --release --no-default-features` |

### Feature Detection in Code

```rust
// In aegis-pscp/src/gpu.rs
#[cfg(feature = "gpu")]
use nvml_wrapper::Nvml;

#[cfg(feature = "gpu")]
pub fn snapshot_gpu() -> GpuSnapshot { /* NVML calls */ }

#[cfg(not(feature = "gpu"))]
pub fn snapshot_gpu() -> GpuSnapshot {
    GpuSnapshot::unavailable()
}
```

## Docker

### Standard (Render)

```bash
cd render
docker build -t aegisframe:latest .
docker run -p 10000:10000 aegisframe:latest
```

### Enterprise (GPU)

```bash
cd enterprise
docker compose up --build
```

### Multi-Stage Build Explained

```
Stage 1: rust:1.78-bookworm (Builder)
  - Compiles source to static binary
  - ~2 GB image (build only)
  - NOT shipped

Stage 2: debian:bookworm-slim (Runtime)
  - Only the binary + ca-certificates
  - ~30 MB (standard) / ~200 MB (enterprise with CUDA)
  - No Rust compiler, no source code
```

## Development with cargo-watch

Auto-rebuild and restart on code changes:

```bash
# Restart server on every change
cargo watch -x 'run --release'

# With enterprise features
cargo watch -x 'run --release --features enterprise'

# Run tests only
cargo watch -x test

# Tests + Clippy on every change
cargo watch -x 'clippy -- -W clippy::all' -x test
```

## Clippy (Linting)

```bash
# Standard Clippy
cargo clippy

# Strict mode (recommended for CI)
cargo clippy -- -W clippy::all -W clippy::pedantic -W clippy::nursery

# Auto-fix
cargo clippy --fix

# Clippy with enterprise features
cargo clippy --features enterprise
```

### Project-Specific Clippy Configuration

In `clippy.toml`:

```toml
# Maximum cognitive complexity per function
cognitive-complexity-threshold = 25

# Allowed wildcard dependencies
allowed-wildcard-imports = []

# Minimum line count for "too large function"
too-many-lines-threshold = 100
```

In `Cargo.toml` (workspace root):

```toml
[workspace.lints.clippy]
all = "warn"
pedantic = "warn"
# Allowed because necessary:
module_name_repetitions = "allow"
must_use_candidate = "allow"
missing_errors_doc = "allow"
```

## Logging

AegisFrame uses `tracing` with structured logging.

### Configuration via Environment Variables

```bash
# Standard
RUST_LOG=info cargo run

# Verbose (all modules)
RUST_LOG=debug cargo run

# AegisFrame modules only
RUST_LOG=aegisframe=debug,tower_http=info cargo run

# PSCP engine only
RUST_LOG=aegisframe::pscp=trace cargo run

# JSON format (for log aggregation)
AEGISFRAME_LOG_FORMAT=json cargo run
```

### Log Level Overview

| Level | What is logged |
|-------|---------------|
| `error` | Critical errors: TSA timeout, NVML crash, proof verification failed |
| `warn` | Degraded operation: eBPF not available, TSA fallback, GPU not found |
| `info` | Operational: Server start, proof generated, TSA anchor OK |
| `debug` | Development: Request details, snapshot data, hash values |
| `trace` | Everything: Every function call, every /proc read, every byte |

### Example Log Output

```
2026-03-01T12:00:00.000Z  INFO aegisframe::server: AegisFrame Control Tower starting
2026-03-01T12:00:00.001Z  INFO aegisframe::server: Port: 10000
2026-03-01T12:00:00.001Z  INFO aegisframe::pscp: PSCP Proof Engine initialized
2026-03-01T12:00:00.002Z  INFO aegisframe::pscp::gpu: NVML initialized: 1 GPU(s), driver 535.129.03
2026-03-01T12:00:00.002Z  WARN aegisframe::pscp::socket: eBPF not available — using /proc/net fallback
2026-03-01T12:00:00.003Z  INFO aegisframe::pscp::process: Process attestor initialized (sysinfo)
2026-03-01T12:00:05.123Z  INFO aegisframe::pscp: PSCP proof generated: PSCP_000001 → PSCP_BLOCK_VERIFIED
2026-03-01T12:00:05.234Z  INFO aegisframe::tsa: TSA anchor OK: TSA_1740264005_4f2e8a1c
```

## Tests

```bash
# All tests
cargo test

# All tests (parallel, faster)
cargo nextest run

# Core tests only
cargo test -p aegis-core

# TSA tests only (with mock)
cargo test -p aegis-tsa --features tsa-mock

# PSCP tests only
cargo test -p aegis-pscp

# Integration tests
cargo test --test integration

# Tests with output
cargo test -- --nocapture

# Specific test
cargo test test_hash_chain_integrity
```

### Test Categories

```
aegis-core:
  ├── test_evidence_chain_append
  ├── test_evidence_chain_tamper_detection
  ├── test_ecdsa_sign_verify
  ├── test_hash_chain_integrity
  ├── test_risk_classifier_annex_iii
  ├── test_gate_decision_matrix
  └── test_countdown_timeout_auto_deny

aegis-tsa:
  ├── test_tsq_encoding          (tsa-mock)
  ├── test_tsr_decoding          (tsa-mock)
  └── test_live_tsa_anchor       (tsa-live, #[ignore])

aegis-pscp:
  ├── test_gpu_snapshot_stub     (without GPU)
  ├── test_socket_snapshot
  ├── test_process_snapshot
  ├── test_proof_cycle_block
  └── test_proof_cycle_allow

aegis-server:
  ├── test_health_endpoint
  ├── test_status_endpoint
  ├── test_tsa_anchor_valid
  ├── test_tsa_anchor_invalid_hash
  └── test_pscp_prove_endpoint
```

## Troubleshooting

### `error: linker 'cc' not found`

```bash
# Linux
sudo apt install build-essential

# macOS
xcode-select --install
```

### `failed to run custom build command for 'openssl-sys'`

```bash
# Linux
sudo apt install libssl-dev pkg-config

# macOS
brew install openssl
export OPENSSL_DIR=$(brew --prefix openssl)
```

### `NVML not found` (Enterprise Build)

```bash
# NVIDIA driver installed?
nvidia-smi

# CUDA installed?
nvcc --version

# If Docker: nvidia-container-toolkit installed?
nvidia-ctk --version
```

### `eBPF: permission denied`

```bash
# eBPF requires privileges
# Option 1: Docker privileged mode
docker run --privileged ...

# Option 2: CAP_BPF capability
docker run --cap-add BPF --cap-add SYS_ADMIN ...

# Option 3: Host eBPF tools
sudo bpftrace --version
```

### `cargo build` is slow

```bash
# Linker optimization (Linux)
# In .cargo/config.toml:
[target.x86_64-unknown-linux-gnu]
linker = "clang"
rustflags = ["-C", "link-arg=-fuse-ld=mold"]

# Install mold:
sudo apt install mold

# sccache (compile cache)
cargo install sccache
export RUSTC_WRAPPER=sccache
```

### Port 10000 already in use

```bash
# Who is using the port?
lsof -i :10000

# Alternative port:
PORT=8080 cargo run --release
```

### Docker build fails

```bash
# Clear cache
docker builder prune -a

# Build without cache
docker compose build --no-cache

# View logs
docker compose logs -f
```

---

X-Loop³ Labs · Kreuzlingen, Switzerland · Patent Pending
