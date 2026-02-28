<p align="center">
  <img src="https://img.shields.io/badge/Rust-🦀_Edition_2021-dea584?style=for-the-badge&logo=rust&logoColor=white" />
</p>

# 🔧 Building AegisFrame (Rust)

Complete guide to building, running, and developing the Rust version.

---

## Prerequisites

### Required
- **Rust** 1.75+ (Edition 2021) — Install via [rustup](https://rustup.rs/)
- **openssl** — For RFC 3161 TSA requests (`openssl ts`)
- **curl** — For sending TSA requests to freetsa.org

### Optional (Enterprise GPU)
- **NVIDIA CUDA Toolkit** — For GPU attestation (`nvml-wrapper` crate)
- **Docker** + **NVIDIA Container Toolkit** — For containerized deployment
- **bpftrace** — For eBPF kernel socket monitoring

### Install Rust
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
rustc --version  # Should show 1.75+
```

---

## Building

### Full Workspace
```bash
# Debug build (fast compile, slow runtime)
cargo build

# Release build (slow compile, fast runtime)
cargo build --release
```

Binaries are placed in:
```
target/release/aegisframe-render       # Render server
target/release/aegisframe-enterprise   # Enterprise server
```

### Individual Crates
```bash
# Render only
cargo build --release -p aegisframe-render

# Enterprise only
cargo build --release -p aegisframe-enterprise

# Enterprise with GPU support
cargo build --release -p aegisframe-enterprise --features gpu
```

### Check (No Build)
```bash
# Fast type-check without producing binaries
cargo check
```

---

## Running

### Render Server
```bash
# From workspace root
cargo run -p aegisframe-render

# Or from render directory
cd render && cargo run

# With custom port
PORT=8080 cargo run -p aegisframe-render

# With debug logging
RUST_LOG=debug cargo run -p aegisframe-render
```

### Enterprise Server
```bash
# From workspace root
cargo run -p aegisframe-enterprise

# With trace-level logging
RUST_LOG=trace cargo run -p aegisframe-enterprise
```

### Release Mode (Production)
```bash
cargo build --release
cd render && ../target/release/aegisframe-render
# or
cd enterprise && ../target/release/aegisframe-enterprise
```

---

## Docker Build (Enterprise)

### Standard Build
```bash
cd enterprise
docker compose up --build
```

### Manual Docker Build
```bash
# From workspace root
docker build -f enterprise/Dockerfile -t aegisframe-enterprise .
docker run -p 10000:10000 aegisframe-enterprise
```

### With GPU
```bash
cd enterprise
docker compose up --build
# docker-compose.yml already configures:
#   - runtime: nvidia
#   - privileged: true (for eBPF)
#   - GPU device reservation
#   - /proc and /sys mounts
```

---

## Development

### Watch Mode (Auto-Rebuild)
```bash
# Install cargo-watch
cargo install cargo-watch

# Auto-rebuild on file changes
cargo watch -x 'run -p aegisframe-render'

# Auto-check on file changes (faster)
cargo watch -x check
```

### Linting
```bash
# Clippy (Rust linter)
cargo clippy -- -W clippy::all

# Format check
cargo fmt -- --check

# Format fix
cargo fmt
```

### Dependency Audit
```bash
# Install cargo-audit
cargo install cargo-audit

# Check for known vulnerabilities
cargo audit
```

---

## Logging

AegisFrame uses the `tracing` framework with `tracing-subscriber`.
Control verbosity via the `RUST_LOG` environment variable:

```bash
# Only errors
RUST_LOG=error cargo run -p aegisframe-enterprise

# Info level (default)
RUST_LOG=info cargo run -p aegisframe-enterprise

# Debug level
RUST_LOG=debug cargo run -p aegisframe-enterprise

# Trace everything
RUST_LOG=trace cargo run -p aegisframe-enterprise

# Module-specific filtering
RUST_LOG=aegisframe_enterprise=debug,tower_http=info cargo run -p aegisframe-enterprise
```

---

## Feature Flags

| Feature | Crate | Description |
|---------|-------|-------------|
| `gpu` | `aegisframe-enterprise` | Enable NVIDIA NVML GPU attestation |

```bash
# Without GPU (default) — GPU attestor returns "NO_GPU" mode
cargo build --release -p aegisframe-enterprise

# With GPU — requires NVML/CUDA SDK installed
cargo build --release -p aegisframe-enterprise --features gpu
```

When built without the `gpu` feature, the GPU attestor gracefully reports
`"mode": "NO_GPU"` and the proof engine still generates valid proofs
using socket and process attestation.

---

## Project Layout

```
Cargo.toml                      # [workspace] members = ["render", "enterprise"]
Cargo.lock                      # Locked dependency versions (committed)
│
├── render/
│   ├── Cargo.toml              # [package] name = "aegisframe-render"
│   └── src/main.rs             # ~300 lines — complete render server
│
├── enterprise/
│   ├── Cargo.toml              # [package] name = "aegisframe-enterprise"
│   └── src/
│       ├── main.rs             # ~350 lines — enterprise server
│       └── pscp/
│           ├── mod.rs          # pub mod declarations
│           ├── proof_engine.rs # ~250 lines — proof orchestrator
│           ├── gpu_attestor.rs # ~300 lines — NVML attestation
│           ├── socket_monitor.rs # ~250 lines — eBPF/proc monitoring
│           └── process_attestor.rs # ~280 lines — process scanning
│
└── target/                     # Build artifacts (gitignored)
```

---

## Cargo Workspace

The project uses a Cargo workspace. This means:

- **One `Cargo.lock`** — All crates share the same dependency versions
- **Shared `target/`** — Build artifacts are shared, saving disk space
- **Workspace commands** — `cargo build` builds everything, `cargo check` checks everything
- **Individual builds** — Use `-p <crate>` to build a specific crate

```toml
# Root Cargo.toml
[workspace]
members = ["render", "enterprise"]
```

---

## Troubleshooting

### `openssl ts` not found
```bash
# Ubuntu/Debian
sudo apt-get install openssl

# macOS
brew install openssl
```

### `curl` not found
```bash
# Ubuntu/Debian
sudo apt-get install curl
```

### NVML / GPU errors
```bash
# Check if NVIDIA driver is installed
nvidia-smi

# Install CUDA toolkit (Ubuntu)
sudo apt-get install nvidia-cuda-toolkit

# Build without GPU support
cargo build --release -p aegisframe-enterprise  # no --features gpu
```

### Port already in use
```bash
# Use a different port
PORT=8080 cargo run -p aegisframe-render
```

---

<p align="center">
  <strong>X-Loop³ Labs</strong> · Kreuzlingen, Switzerland<br>
  <em>Built with 🦀 Rust</em>
</p>
