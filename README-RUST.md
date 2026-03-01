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

## Projekt-Überblick

AegisFrame ist eine **Runtime AI Governance Engine**, die Compliance auf Architektur-Ebene durchsetzt — bevor das AI-Model jemals einen Prompt sieht. Die Rust-Edition ist die performante, type-safe Neuimplementierung des gesamten Stacks.

Während Konkurrenten PDF-Checklisten und statische Audits anbieten, liefert AegisFrame **live, kryptographisch verifizierbare Beweise**, dass Governance-Entscheidungen in Echtzeit durchgesetzt werden.

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

## Projekt-Struktur

```
aegisframe-tower/
├── Cargo.toml                  # Workspace Root
├── Cargo.lock
├── README-RUST.md              # ← Diese Datei
├── BUILDING.md                 # Build-Guide
├── ARCHITECTURE.md             # Technische Architektur
│
├── crates/
│   ├── aegis-core/             # Kernlogik: Evidence Chain, ECDSA, Hash Chain
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── evidence.rs     # SHA-256 Evidence Spine
│   │       ├── ecdsa.rs        # ECDSA P-256 Signaturen
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
│   │       └── asn1.rs         # ASN.1 Parsing (kein openssl CLI)
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

## Rust-Stack

| Komponente | Crate | Beschreibung |
|-----------|-------|--------------|
| HTTP Server | [`axum`](https://docs.rs/axum) + [`tower`](https://docs.rs/tower) | Async HTTP mit Tower Middleware |
| Async Runtime | [`tokio`](https://docs.rs/tokio) | Multi-threaded async Runtime |
| Kryptographie | [`ring`](https://docs.rs/ring) | SHA-256, ECDSA P-256, HMAC |
| TSA (RFC 3161) | [`rasn`](https://docs.rs/rasn) + [`reqwest`](https://docs.rs/reqwest) | Native ASN.1 Parsing, kein openssl CLI |
| GPU (NVML) | [`nvml-wrapper`](https://docs.rs/nvml-wrapper) | Safe NVML Bindings |
| Serialisierung | [`serde`](https://docs.rs/serde) + [`serde_json`](https://docs.rs/serde_json) | Zero-Copy JSON |
| Logging | [`tracing`](https://docs.rs/tracing) + [`tracing-subscriber`](https://docs.rs/tracing-subscriber) | Structured Logging |
| Fehlerbehandlung | [`thiserror`](https://docs.rs/thiserror) + [`anyhow`](https://docs.rs/anyhow) | Ergonomische Fehlertypen |
| Config | [`config`](https://docs.rs/config) | Layered Configuration |
| Prozesse | [`sysinfo`](https://docs.rs/sysinfo) | Cross-platform Prozess-Info |
| Zeit | [`chrono`](https://docs.rs/chrono) | ISO 8601 Timestamps |
| HTTP Client | [`reqwest`](https://docs.rs/reqwest) | Async HTTP Client für TSA |

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
# Serialisierung
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
# Kryptographie
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
# Fehler
thiserror = "1.0"
anyhow = "1.0"
# Systeminformation
sysinfo = "0.30"
# Zeit
chrono = { version = "0.4", features = ["serde"] }
# GPU (optional)
nvml-wrapper = { version = "0.10", optional = true }
# Config
config = "0.14"
```

## Feature Flags

Feature Flags steuern die bedingte Kompilierung und bestimmen, welche PSCP-Module im Binary enthalten sind:

| Flag | Default | Beschreibung |
|------|---------|--------------|
| `gpu` | `false` | NVML GPU Attestation aktivieren (benötigt NVIDIA Treiber) |
| `ebpf` | `false` | eBPF Kernel Socket Monitor (benötigt `CAP_BPF`) |
| `enterprise` | `false` | Aktiviert `gpu` + `ebpf` + vollständige PSCP Proof Engine |
| `tsa-live` | `true` | Echte RFC 3161 TSA Aufrufe (freetsa.org) |
| `tsa-mock` | `false` | Mock-TSA für Tests ohne Netzwerk |

```bash
# Standard-Build (Render / ohne GPU)
cargo build --release

# Enterprise-Build (GPU + eBPF)
cargo build --release --features enterprise

# Nur GPU-Attestation
cargo build --release --features gpu

# Tests ohne Netzwerk
cargo test --features tsa-mock
```

## EU AI Act — Abgedeckte Artikel

### Basis-Modus (verpflichtend für alle AI-Systeme ab Aug 2026)

| Artikel | Thema | Umsetzung in Rust |
|---------|-------|--------------------|
| Art. 9 | Risikomanagement | 7-Layer Governance Stack (`aegis-core::gate`) |
| Art. 12 | Aufzeichnungspflicht | SHA-256 Evidence Spine (`aegis-core::evidence`) |
| Art. 13 | Transparenz | Pre-Semantic Proof Panel, Proof-Trail API |
| Art. 14 | Menschliche Aufsicht | Countdown-Not-Auto-Stop (`aegis-core::countdown`) |
| Art. 15 | Robustheit | EMA Smoothing, Drift Detection |

### High-Risk-Erweiterung (Annex III: Medizin, HR, Kredit, Infrastruktur)

- Art. 6 — Klassifikationsnachweis
- Art. 17 — Qualitätsmanagement
- Konformitätsbewertung
- ECDSA P-256 Akteur-Signaturen (`aegis-core::ecdsa`)
- Oversight Token Flow (3-phasig)
- Multi-Trail A/B/C (`aegis-core::trail`)
- Externer Audit-Verifier
- INTEGRITY_ROOT + RFC 3161 (`aegis-tsa`)

## Python ↔ Rust Vergleich

| Aspekt | Python (aktuell) | Rust (Ziel) |
|--------|------------------|-------------|
| **Runtime** | Flask + Gunicorn | Axum + Tokio |
| **Latenz (TSA Anchor)** | ~200ms (subprocess → openssl → curl) | ~50ms (nativer reqwest + rasn) |
| **PSCP Proof Cycle** | ~300ms (psutil, /proc Parsing) | ~20ms (sysinfo, direktes /proc) |
| **Memory** | ~80MB (Python Interpreter) | ~8MB (statisches Binary) |
| **Startup** | ~2s (Gunicorn Worker Fork) | ~50ms (Tokio Runtime Init) |
| **Concurrency** | GIL-begrenzt, 2 Workers | Lock-free, tausende Tasks |
| **Type Safety** | Runtime Errors | Compile-Time Garantien |
| **TSA-Aufruf** | `subprocess.run(["openssl", "ts", ...])` | Nativer ASN.1 Encoder/Decoder |
| **GPU (NVML)** | `pynvml` (C FFI Wrapper) | `nvml-wrapper` (Safe Rust FFI) |
| **Binary Size** | N/A (benötigt Python + pip) | ~15MB statisches Binary |
| **Docker Image** | ~1.2GB (CUDA + Python + pip) | ~200MB (CUDA + Static Binary) |
| **Sicherheit** | Runtime Type Errors möglich | Kein `unsafe` im Anwendungscode |

### Migrationsstrategie

```
Phase 1: aegis-core     → Evidence Chain, ECDSA, Hash Chain
Phase 2: aegis-tsa      → Nativer RFC 3161 Client (kein openssl CLI)
Phase 3: aegis-pscp     → GPU, Socket, Process Attestation
Phase 4: aegis-server   → Axum HTTP Server mit allen Endpoints
Phase 5: Integration    → Docker, Render, Enterprise Deployment
```

## API-Endpoints (identisch zu Python)

| Method | Endpoint | Beschreibung |
|--------|----------|--------------|
| `GET` | `/` | AegisFrame UI (Tower + Monitor) |
| `GET` | `/health` | Health Check |
| `GET` | `/api/v1/status` | System-Capabilities |
| `POST` | `/api/v1/tsa/anchor` | RFC 3161 Timestamp Anchoring |
| `POST` | `/api/v1/pscp/prove` | PSCP Hardware Proof (Enterprise) |
| `POST` | `/api/v1/pscp/prove/full` | PSCP Proof + TSA Anchor (Enterprise) |
| `GET` | `/api/v1/pscp/status` | PSCP Engine Capabilities (Enterprise) |
| `GET` | `/api/v1/pscp/trail` | Append-Only Proof Trail (Enterprise) |

## Quick Start

```bash
# Klonen
git clone https://github.com/XLOOP3/aegisframe-tower.git
cd aegisframe-tower

# Standard-Build (ohne GPU)
cargo run --release

# Enterprise-Build (mit GPU + eBPF)
cargo run --release --features enterprise

# Server starten (Port 10000)
# → http://localhost:10000
```

## Patente

| # | Titel | Filing | Status |
|---|-------|--------|--------|
| 1 | SIREN — Predictive Maintenance for Agricultural Robotics | 63/983,192 | Filed |
| 2 | PSCP — Pre-Semantic Structural Control Plane | 63/983,493 | Filed |
| 3 | MilkMind — Dairy Intelligence Platform | 63/986,414 | Filed |
| 4 | Electric Translator — Pre-Semantic Bidirectional Translation | — | Ready |
| 6 | AegisFrame — Risk-Adaptive AI Governance Engine | — | Ready |

## Lizenz

Proprietary · © 2026 X-Loop³ Labs Ltd. · All rights reserved.

---

<p align="center">
  <strong>X-Loop³ Labs</strong><br>
  Kreuzlingen, Switzerland<br>
  <em>Pre-Semantic AI Infrastructure</em>
</p>
