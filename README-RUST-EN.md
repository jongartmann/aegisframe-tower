<p align="center">
  <img src="https://img.shields.io/badge/AegisFrame-v1.0.0--rust-0a0e1a?style=for-the-badge&labelColor=12b47a&color=0a0e1a" />
  <img src="https://img.shields.io/badge/Rust-1.78+-dea584?style=for-the-badge&logo=rust" />
  <img src="https://img.shields.io/badge/USPTO-Patent_Pending-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/EU_AI_Act-Runtime_Compliance-purple?style=for-the-badge" />
  <img src="https://img.shields.io/badge/RFC_3161-TSA_LIVE-green?style=for-the-badge" />
</p>

<h1 align="center">AegisFrame AI Governance Engine — Rust Edition</h1>

<p align="center">
  <strong>Runtime compliance for the EU AI Act. Not a checklist — a living proof engine.</strong><br>
  <em>X-Loop³ Labs · Kreuzlingen, Switzerland</em>
</p>

---

## Project Overview

AegisFrame is a **runtime AI governance engine** that enforces compliance at the architectural level — before the AI model ever sees a prompt. The Rust edition is the performant, type-safe reimplementation of the entire stack.

While competitors offer PDF checklists and static audits, AegisFrame provides **live, cryptographically verifiable evidence** that governance decisions are enforced in real-time.

```
┌─────────────────────────────────────────────────────────────┐
│  USER PROMPT                                                 │
│       ↓                                                      │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  AEGISFRAME PRE-SEMANTIC CONTROL PLANE (PSCP)       │    │
│  │  ┌───────────┐  ┌───────────┐  ┌───────────────┐   │    │
│  │  │ 7 Security│  │ 4 Domain  │  │ Risk Tier     │   │    │
│  │  │ Signals   │  │ Signals   │  │ Classifier    │   │    │
│  │  └─────┬─────┘  └─────┬─────┘  └───────┬───────┘   │    │
│  │        ↓              ↓                ↓            │    │
│  │  ┌─────────────────────────────────────────────┐    │    │
│  │  │  Gate Decision: ALLOW / WARN / DEFEND / LOCK │    │    │
│  │  └───────────────────┬─────────────────────────┘    │    │
│  │                      ↓                              │    │
│  │  Evidence → SHA-256 Chain → ECDSA P-256 Signature   │    │
│  └──────────────────────┬──────────────────────────────┘    │
│                         ↓                                    │
│  ┌──────────┐    ┌──────────────┐                           │
│  │ BLOCKED  │ or │ AI MODEL     │                           │
│  │ (proof)  │    │ (monitored)  │                           │
│  └──────────┘    └──────────────┘                           │
└─────────────────────────────────────────────────────────────┘
```

## Project Structure

```
aegisframe-tower/
├── Cargo.toml                  # Workspace Root
├── Cargo.lock
├── README-RUST-EN.md           # ← This file
├── BUILDING.md                 # Build Guide
├── ARCHITECTURE.md             # Technical Architecture
│
├── crates/
│   ├── aegis-core/             # Core Logic: Evidence Chain, ECDSA, Hash Chain
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── evidence.rs     # SHA-256 Evidence Spine
│   │       ├── ecdsa.rs        # ECDSA P-256 Signatures
│   │       ├── hash_chain.rs   # Append-Only Hash Chain
│   │       ├── risk.rs         # Risk Tier Classifier (Annex III)
│   │       ├── gate.rs         # 7-Layer Governance Gates
│   │       ├── countdown.rs    # Countdown-Not-Auto-Stop
│   │       └── trail.rs        # Multi-Trail A/B/C
│   │
│   ├── aegis-pscp/             # PSCP Hardware Proof Engine
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── engine.rs       # Proof Orchestrator
│   │       ├── gpu.rs          # NVML GPU Attestation
│   │       ├── socket.rs       # eBPF Socket Monitor
│   │       └── process.rs      # /proc + cgroups Attestation
│   │
│   ├── aegis-tsa/              # RFC 3161 Timestamp Authority Client
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── client.rs       # TSA Client (freetsa.org)
│   │       └── asn1.rs         # ASN.1 Parsing (no openssl CLI)
│   │
│   └── aegis-server/           # Axum/Tower HTTP Server
│       ├── Cargo.toml
│       └── src/
│           ├── main.rs
│           ├── routes/
│           │   ├── mod.rs
│           │   ├── health.rs
│           │   ├── tsa.rs
│           │   ├── pscp.rs
│           │   └── status.rs
│           ├── state.rs        # App State (Arc<AppState>)
│           └── error.rs        # Unified Error Types
│
├── enterprise/                 # Enterprise GPU Deployment
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── setup_ec2.sh
│
├── render/                     # Render Cloud Deployment
│   └── render.yaml
│
└── static/
    └── index.html              # AegisFrame Tower + Runtime Monitor UI
```

## Rust Stack

| Component | Crate | Description |
|-----------|-------|-------------|
| HTTP Server | [`axum`](https://docs.rs/axum) + [`tower`](https://docs.rs/tower) | Async HTTP with Tower Middleware |
| Async Runtime | [`tokio`](https://docs.rs/tokio) | Multi-threaded async runtime |
| Cryptography | [`ring`](https://docs.rs/ring) | SHA-256, ECDSA P-256, HMAC |
| TSA (RFC 3161) | [`rasn`](https://docs.rs/rasn) + [`reqwest`](https://docs.rs/reqwest) | Native ASN.1 parsing, no openssl CLI |
| GPU (NVML) | [`nvml-wrapper`](https://docs.rs/nvml-wrapper) | Safe NVML bindings |
| Serialization | [`serde`](https://docs.rs/serde) + [`serde_json`](https://docs.rs/serde_json) | Zero-copy JSON |
| Logging | [`tracing`](https://docs.rs/tracing) + [`tracing-subscriber`](https://docs.rs/tracing-subscriber) | Structured logging |
| Error Handling | [`thiserror`](https://docs.rs/thiserror) + [`anyhow`](https://docs.rs/anyhow) | Ergonomic error types |
| Config | [`config`](https://docs.rs/config) | Layered configuration |
| Processes | [`sysinfo`](https://docs.rs/sysinfo) | Cross-platform process info |
| Time | [`chrono`](https://docs.rs/chrono) | ISO 8601 timestamps |
| HTTP Client | [`reqwest`](https://docs.rs/reqwest) | Async HTTP client for TSA |

## Dependencies (Cargo.toml Workspace)

```toml
[workspace]
members = [
    "crates/aegis-core",
    "crates/aegis-pscp",
    "crates/aegis-tsa",
    "crates/aegis-server",
]
resolver = "2"

[workspace.dependencies]
# Async
tokio = { version = "1.37", features = ["full"] }
# Web
axum = { version = "0.7", features = ["json", "tokio"] }
tower = { version = "0.4", features = ["full"] }
tower-http = { version = "0.5", features = ["cors", "fs", "trace"] }
# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
# Cryptography
ring = "0.17"
hex = "0.4"
# HTTP Client
reqwest = { version = "0.12", features = ["json", "rustls-tls"] }
# ASN.1 (RFC 3161)
rasn = "0.16"
rasn-cms = "0.16"
# Logging
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }
# Errors
thiserror = "1.0"
anyhow = "1.0"
# System Information
sysinfo = "0.30"
# Time
chrono = { version = "0.4", features = ["serde"] }
# GPU (optional)
nvml-wrapper = { version = "0.10", optional = true }
# Config
config = "0.14"
```

## Feature Flags

Feature flags control conditional compilation and determine which PSCP modules are included in the binary:

| Flag | Default | Description |
|------|---------|-------------|
| `gpu` | `false` | Enable NVML GPU attestation (requires NVIDIA drivers) |
| `ebpf` | `false` | eBPF kernel socket monitor (requires `CAP_BPF`) |
| `enterprise` | `false` | Enables `gpu` + `ebpf` + full PSCP proof engine |
| `tsa-live` | `true` | Real RFC 3161 TSA calls (freetsa.org) |
| `tsa-mock` | `false` | Mock TSA for tests without network |

```bash
# Standard build (Render / without GPU)
cargo build --release

# Enterprise build (GPU + eBPF)
cargo build --release --features enterprise

# GPU attestation only
cargo build --release --features gpu

# Tests without network
cargo test --features tsa-mock
```

## EU AI Act — Covered Articles

### Basic Mode (mandatory for all AI systems from Aug 2026)

| Article | Topic | Rust Implementation |
|---------|-------|---------------------|
| Art. 9 | Risk Management | 7-Layer Governance Stack (`aegis-core::gate`) |
| Art. 12 | Record-Keeping | SHA-256 Evidence Spine (`aegis-core::evidence`) |
| Art. 13 | Transparency | Pre-Semantic Proof Panel, Proof-Trail API |
| Art. 14 | Human Oversight | Countdown-Not-Auto-Stop (`aegis-core::countdown`) |
| Art. 15 | Robustness | EMA Smoothing, Drift Detection |

### High-Risk Extension (Annex III: Medical, HR, Credit, Infrastructure)

- Art. 6 — Classification Evidence
- Art. 17 — Quality Management
- Conformity Assessment
- ECDSA P-256 Actor Signatures (`aegis-core::ecdsa`)
- Oversight Token Flow (3-phase)
- Multi-Trail A/B/C (`aegis-core::trail`)
- External Audit Verifier
- INTEGRITY_ROOT + RFC 3161 (`aegis-tsa`)

## Python ↔ Rust Comparison

| Aspect | Python (current) | Rust (target) |
|--------|------------------|---------------|
| **Runtime** | Flask + Gunicorn | Axum + Tokio |
| **Latency (TSA Anchor)** | ~200ms (subprocess → openssl → curl) | ~50ms (native reqwest + rasn) |
| **PSCP Proof Cycle** | ~300ms (psutil, /proc parsing) | ~20ms (sysinfo, direct /proc) |
| **Memory** | ~80MB (Python interpreter) | ~8MB (static binary) |
| **Startup** | ~2s (Gunicorn worker fork) | ~50ms (Tokio runtime init) |
| **Concurrency** | GIL-limited, 2 workers | Lock-free, thousands of tasks |
| **Type Safety** | Runtime errors | Compile-time guarantees |
| **TSA Call** | `subprocess.run(["openssl", "ts", ...])` | Native ASN.1 encoder/decoder |
| **GPU (NVML)** | `pynvml` (C FFI wrapper) | `nvml-wrapper` (safe Rust FFI) |
| **Binary Size** | N/A (requires Python + pip) | ~15MB static binary |
| **Docker Image** | ~1.2GB (CUDA + Python + pip) | ~200MB (CUDA + static binary) |
| **Security** | Runtime type errors possible | No `unsafe` in application code |

### Migration Strategy

```
Phase 1: aegis-core     → Evidence Chain, ECDSA, Hash Chain
Phase 2: aegis-tsa      → Native RFC 3161 Client (no openssl CLI)
Phase 3: aegis-pscp     → GPU, Socket, Process Attestation
Phase 4: aegis-server   → Axum HTTP Server with all endpoints
Phase 5: Integration    → Docker, Render, Enterprise Deployment
```

## API Endpoints (identical to Python)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | AegisFrame UI (Tower + Monitor) |
| `GET` | `/health` | Health Check |
| `GET` | `/api/v1/status` | System Capabilities |
| `POST` | `/api/v1/tsa/anchor` | RFC 3161 Timestamp Anchoring |
| `POST` | `/api/v1/pscp/prove` | PSCP Hardware Proof (Enterprise) |
| `POST` | `/api/v1/pscp/prove/full` | PSCP Proof + TSA Anchor (Enterprise) |
| `GET` | `/api/v1/pscp/status` | PSCP Engine Capabilities (Enterprise) |
| `GET` | `/api/v1/pscp/trail` | Append-Only Proof Trail (Enterprise) |

## Quick Start

```bash
# Clone
git clone https://github.com/XLOOP3/aegisframe-tower.git
cd aegisframe-tower

# Standard build (without GPU)
cargo run --release

# Enterprise build (with GPU + eBPF)
cargo run --release --features enterprise

# Start server (Port 10000)
# → http://localhost:10000
```

## Patents

| # | Title | Filing | Status |
|---|-------|--------|--------|
| 1 | SIREN — Predictive Maintenance for Agricultural Robotics | 63/983,192 | Filed |
| 2 | PSCP — Pre-Semantic Structural Control Plane | 63/983,493 | Filed |
| 3 | MilkMind — Dairy Intelligence Platform | 63/986,414 | Filed |
| 4 | Electric Translator — Pre-Semantic Bidirectional Translation | — | Ready |
| 6 | AegisFrame — Risk-Adaptive AI Governance Engine | — | Ready |

## License

Proprietary · © 2026 X-Loop³ Labs Ltd. · All rights reserved.

---

<p align="center">
  <strong>X-Loop³ Labs</strong><br>
  Kreuzlingen, Switzerland<br>
  <em>Pre-Semantic AI Infrastructure</em>
</p>
