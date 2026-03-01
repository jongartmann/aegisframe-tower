# AegisFrame — Build Guide (Rust)

Vollständige Anleitung zum Bauen, Testen und Deployen der Rust-Edition.

---

## Prerequisites

### Minimal (Standard-Build)

| Tool | Version | Installation |
|------|---------|-------------|
| Rust | 1.78+ | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` |
| cargo | (mit Rust) | Automatisch mit rustup |
| pkg-config | any | `apt install pkg-config` / `brew install pkg-config` |
| OpenSSL dev | 3.x | `apt install libssl-dev` / `brew install openssl` |

### Enterprise-Build (GPU + eBPF)

| Tool | Version | Installation |
|------|---------|-------------|
| NVIDIA Treiber | 535+ | `apt install nvidia-driver-535` |
| CUDA Toolkit | 12.2+ | NVIDIA CUDA Repository |
| bpftrace | 0.19+ | `apt install bpftrace` |
| bpfcc-tools | any | `apt install bpfcc-tools` |
| Linux Headers | matching kernel | `apt install linux-headers-$(uname -r)` |
| Docker | 24+ | [docker.com](https://docs.docker.com/engine/install/) |
| nvidia-container-toolkit | 1.14+ | [NVIDIA Container Toolkit](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/) |

### Empfohlene Dev-Tools

```bash
# cargo-watch — Auto-Rebuild bei Änderungen
cargo install cargo-watch

# cargo-nextest — Schnellerer Test-Runner
cargo install cargo-nextest

# cargo-deny — License + Dependency Auditing
cargo install cargo-deny

# cargo-machete — Ungenutzte Dependencies finden
cargo install cargo-machete
```

## Workspace-Struktur

AegisFrame nutzt ein Cargo Workspace mit vier Crates:

```
Cargo.toml (workspace root)
├── crates/aegis-core/     # Kernlogik: Evidence, ECDSA, Hash Chain, Gates
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

`aegis-core` hat keine Abhängigkeit auf die anderen Crates — es ist die Basis-Schicht.

## Build-Befehle

### Standard-Build (Render / ohne GPU)

```bash
# Debug-Build
cargo build

# Release-Build (optimiert)
cargo build --release

# Binary liegt in:
# target/release/aegis-server
```

### Enterprise-Build (GPU + eBPF)

```bash
# Alle Enterprise-Features aktivieren
cargo build --release --features enterprise

# Nur GPU
cargo build --release --features gpu

# Nur eBPF
cargo build --release --features ebpf
```

### Einzelne Crates bauen

```bash
# Nur den Core
cargo build -p aegis-core

# Nur den TSA Client
cargo build -p aegis-tsa

# Nur die PSCP Engine (ohne GPU)
cargo build -p aegis-pscp

# PSCP Engine mit GPU
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

### Feature-Kombinationen

| Szenario | Befehl |
|----------|--------|
| Render (Standard) | `cargo build --release` |
| Enterprise (voll) | `cargo build --release --features enterprise` |
| Nur GPU-Tests | `cargo build --release --features gpu` |
| CI/CD (kein Netz) | `cargo build --release --features tsa-mock` |
| Alles aus | `cargo build --release --no-default-features` |

### Feature-Erkennung im Code

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

### Multi-Stage Build Erklärt

```
Stage 1: rust:1.78-bookworm (Builder)
  - Kompiliert Source zu statischem Binary
  - ~2 GB Image (nur für Build)
  - Wird NICHT ausgeliefert

Stage 2: debian:bookworm-slim (Runtime)
  - Nur das Binary + ca-certificates
  - ~30 MB (Standard) / ~200 MB (Enterprise mit CUDA)
  - Kein Rust Compiler, kein Source Code
```

## Development mit cargo-watch

Auto-Rebuild und Restart bei Code-Änderungen:

```bash
# Server bei jeder Änderung neu starten
cargo watch -x 'run --release'

# Mit Enterprise Features
cargo watch -x 'run --release --features enterprise'

# Nur Tests laufen lassen
cargo watch -x test

# Tests + Clippy bei jeder Änderung
cargo watch -x 'clippy -- -W clippy::all' -x test
```

## Clippy (Linting)

```bash
# Standard Clippy
cargo clippy

# Strenger Modus (empfohlen für CI)
cargo clippy -- -W clippy::all -W clippy::pedantic -W clippy::nursery

# Fix automatisch
cargo clippy --fix

# Clippy mit Enterprise Features
cargo clippy --features enterprise
```

### Projekt-spezifische Clippy Konfiguration

In `clippy.toml`:

```toml
# Maximale kognitive Komplexität pro Funktion
cognitive-complexity-threshold = 25

# Erlaubte Wildcard-Dependencies
allowed-wildcard-imports = []

# Mindest-Anzahl Zeilen für "zu grosse Funktion"
too-many-lines-threshold = 100
```

In `Cargo.toml` (workspace root):

```toml
[workspace.lints.clippy]
all = "warn"
pedantic = "warn"
# Erlaubt weil nötig:
module_name_repetitions = "allow"
must_use_candidate = "allow"
missing_errors_doc = "allow"
```

## Logging

AegisFrame nutzt `tracing` mit strukturiertem Logging.

### Konfiguration via Umgebungsvariablen

```bash
# Standard
RUST_LOG=info cargo run

# Verbose (alle Module)
RUST_LOG=debug cargo run

# Nur AegisFrame Module
RUST_LOG=aegisframe=debug,tower_http=info cargo run

# Nur PSCP Engine
RUST_LOG=aegisframe::pscp=trace cargo run

# JSON-Format (für Log-Aggregation)
AEGISFRAME_LOG_FORMAT=json cargo run
```

### Log-Level Übersicht

| Level | Was wird geloggt |
|-------|-----------------|
| `error` | Kritische Fehler: TSA Timeout, NVML Crash, Proof Verification Failed |
| `warn` | Degradierter Betrieb: eBPF nicht verfügbar, TSA Fallback, GPU nicht gefunden |
| `info` | Operationell: Server Start, Proof generiert, TSA Anchor OK |
| `debug` | Entwicklung: Request Details, Snapshot Daten, Hash-Werte |
| `trace` | Alles: Jeder Funktionsaufruf, jeder /proc Read, jeder Byte |

### Beispiel Log-Output

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
# Alle Tests
cargo test

# Alle Tests (parallel, schneller)
cargo nextest run

# Nur Core Tests
cargo test -p aegis-core

# Nur TSA Tests (mit Mock)
cargo test -p aegis-tsa --features tsa-mock

# Nur PSCP Tests
cargo test -p aegis-pscp

# Integration Tests
cargo test --test integration

# Tests mit Output
cargo test -- --nocapture

# Bestimmter Test
cargo test test_hash_chain_integrity
```

### Test-Kategorien

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
  ├── test_gpu_snapshot_stub     (ohne GPU)
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
# NVIDIA Treiber installiert?
nvidia-smi

# CUDA installiert?
nvcc --version

# Falls Docker: nvidia-container-toolkit installiert?
nvidia-ctk --version
```

### `eBPF: permission denied`

```bash
# eBPF braucht Privilegien
# Option 1: Docker privileged mode
docker run --privileged ...

# Option 2: CAP_BPF Capability
docker run --cap-add BPF --cap-add SYS_ADMIN ...

# Option 3: Host eBPF Tools
sudo bpftrace --version
```

### `cargo build` ist langsam

```bash
# Linker-Optimierung (Linux)
# In .cargo/config.toml:
[target.x86_64-unknown-linux-gnu]
linker = "clang"
rustflags = ["-C", "link-arg=-fuse-ld=mold"]

# mold installieren:
sudo apt install mold

# sccache (Compile Cache)
cargo install sccache
export RUSTC_WRAPPER=sccache
```

### Port 10000 bereits belegt

```bash
# Wer benutzt den Port?
lsof -i :10000

# Alternativen Port:
PORT=8080 cargo run --release
```

### Docker Build schlägt fehl

```bash
# Cache leeren
docker builder prune -a

# Ohne Cache bauen
docker compose build --no-cache

# Logs sehen
docker compose logs -f
```

---

X-Loop³ Labs · Kreuzlingen, Switzerland · Patent Pending
