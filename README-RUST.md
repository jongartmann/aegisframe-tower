<p align="center">
  <img src="https://img.shields.io/badge/AegisFrame-v0.7.0--rust-0a0e1a?style=for-the-badge&labelColor=12b47a&color=0a0e1a" />
  <img src="https://img.shields.io/badge/Rust-🦀_Edition_2021-dea584?style=for-the-badge&logo=rust&logoColor=white" />
  <img src="https://img.shields.io/badge/USPTO-Patent_Pending-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/EU_AI_Act-Runtime_Compliance-purple?style=for-the-badge" />
  <img src="https://img.shields.io/badge/RFC_3161-TSA_LIVE-green?style=for-the-badge" />
</p>

<h1 align="center">🛡 AegisFrame AI Governance Engine — Rust Edition</h1>

<p align="center">
  <strong>Runtime compliance for the EU AI Act. Not a checklist — a living proof engine.</strong><br>
  <em>Rewritten in Rust for maximum safety, performance, and zero-cost abstractions.</em><br>
  <em>X-Loop³ Labs · Kreuzlingen, Switzerland</em>
</p>

---

## Why Rust?

AegisFrame is a **governance engine that must never fail**. Rust was the natural choice:

| Property | Why it matters for AegisFrame |
|----------|-------------------------------|
| **Memory Safety** | No buffer overflows, no use-after-free — critical for a security-grade proof engine |
| **Zero-Cost Abstractions** | SHA-256 chaining, ECDSA signing, and snapshot diffing at native speed |
| **Fearless Concurrency** | Multi-trail evidence processing without data races |
| **No GC Pauses** | Deterministic latency for countdown-critical governance decisions |
| **Type System** | Gate verdicts, proof states, and attestation levels enforced at compile time |
| **Single Binary** | One statically linked executable — no Python interpreter, no virtualenv, no dependency hell |

---

## What is AegisFrame?

AegisFrame is a **runtime AI governance engine** that enforces compliance at the architectural level — before the AI model ever sees a prompt. While competitors offer PDF checklists and static audits, AegisFrame provides **live, cryptographically verifiable evidence** that governance decisions are enforced in real-time.

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

---

## Rust Project Structure

AegisFrame is organized as a **Cargo workspace** with two independent binaries:

```
aegisframe-tower/
├── Cargo.toml                  # Workspace root
├── Cargo.lock                  # Locked dependency versions
│
├── render/                     # 🌐 Standard deployment (Render Cloud)
│   ├── Cargo.toml              # Dependencies: axum, tokio, sha2, chrono
│   ├── src/
│   │   └── main.rs             # Axum server + RFC 3161 TSA endpoint
│   ├── static/
│   │   └── index.html          # AegisFrame Tower + Runtime Monitor UI
│   └── render.yaml             # Render auto-deploy config
│
├── enterprise/                 # 🏢 Enterprise GPU deployment (AWS EC2)
│   ├── Cargo.toml              # Dependencies: axum, tokio, sha2, nvml-wrapper
│   ├── src/
│   │   ├── main.rs             # Axum server + TSA + PSCP endpoints
│   │   └── pscp/               # PSCP Hardware Proof Engine
│   │       ├── mod.rs           # Module declarations
│   │       ├── proof_engine.rs  # Orchestrator: 3-layer proof assembly
│   │       ├── gpu_attestor.rs  # NVIDIA NVML hardware counter attestation
│   │       ├── socket_monitor.rs # eBPF kernel socket monitoring
│   │       └── process_attestor.rs # /proc + cgroup process attestation
│   ├── static/
│   │   └── index.html          # AegisFrame Tower + Runtime Monitor UI
│   ├── Dockerfile              # Multi-stage: Rust build → NVIDIA CUDA runtime
│   ├── docker-compose.yml      # --gpus all + privileged + eBPF mounts
│   └── setup_ec2.sh            # One-shot EC2 g5.xlarge provisioning
│
└── docs/                       # 📚 Additional documentation
```

---

## Two Products, One Engine

AegisFrame ships as two complementary layers — licensable together or separately:

| Layer | For Whom | What It Does |
|-------|----------|--------------|
| **🛡 Control Tower** | Developers / Integrators | Per-prompt governance. User types a prompt → sees gates fire, risk scores, mitigations, evidence export in real-time |
| **📊 Runtime Monitor** | Compliance Officers / Auditors | Fleet surveillance. Seismograph, EKG vitals, drift detection, countdown oversight, multi-trail verification |

Both layers share the same evidence spine, the same SHA-256 chain, and the same ECDSA-signed proof trail.

---

## Architecture

### 7-Layer Governance Stack
```
Layer 7 │ Autonomy Gradient (L0–L5)
Layer 6 │ Proportionality Guarantee
Layer 5 │ Countdown-Not-Auto-Stop (Waymo Paradigm)
Layer 4 │ Risk Tier Classifier (Annex III)
Layer 3 │ Domain Authority Gate (4 independent signals)
Layer 2 │ Security Gate (7 independent signals)
Layer 1 │ Pre-Semantic Structural Control Plane (PSCP)
```

### Evidence Infrastructure
- **SHA-256 Evidence Spine** — Every gate decision, state transition, and oversight action is hashed and chained
- **ECDSA P-256 Actor Signatures** — Three oversight actors with individual key pairs
- **Multi-Trail Architecture** — Trail A (Governance), Trail B (Invocation), Trail C (Auditor)
- **RFC 3161 Timestamp Authority** — Real TSA anchoring via freetsa.org (not simulated)
- **INTEGRITY_ROOT** — Single anchored object binding all trails + policy spec hash

### Countdown-Not-Auto-Stop
The Waymo Paradigm: When risk exceeds threshold, a countdown starts. A human must actively decide (APPROVE or DENY) within the window. If no human acts → **auto-DENY**. The system never auto-allows in high-risk situations. Zero liability.

### Escalation Chain
When oversight is required, alerts cascade through channels with increasing urgency:
```
0s    → SMS + Email to On-Call Technician
4s    → PagerDuty
6s    → Slack
8s    → WhatsApp
12s   → ServiceNow
60s   → Auto-escalation → Team Lead
120s  → Auto-escalation → CISO
180s  → Auto-escalation → C-Suite Management
```

---

## PSCP Hardware Proof

The Pre-Semantic Structural Control Plane (PSCP) produces **hardware-level proof** that governance decisions are enforced before the model:

| Proof Layer | Rust Module | Source | What It Proves |
|------------|-------------|--------|----------------|
| **GPU Attestation** | `gpu_attestor.rs` | NVIDIA NVML driver | Zero compute processes, zero GPU utilization, zero VRAM delta |
| **Socket Attestation** | `socket_monitor.rs` | eBPF kernel probe + `/proc/net` | Zero bytes sent to any model API endpoint |
| **Process Attestation** | `process_attestor.rs` | `/proc` + cgroups | Zero inference processes spawned, container isolated |

Three independent sources. All hardware/OS level. All saying the same thing: **Pre-Semantic.**

```json
{
  "proof_type": "PSCP_HARDWARE_PROOF",
  "proof_id": "PSCP_000001_1740264000",
  "verdict": "PSCP_BLOCK_VERIFIED",
  "verified": true,
  "attestations": {
    "gpu":     { "verdict": "NO_INFERENCE_CONFIRMED",  "proof_level": "HARDWARE_NVML" },
    "socket":  { "verdict": "NO_OUTBOUND_CONFIRMED",   "proof_level": "KERNEL_EBPF" },
    "process": { "verdict": "NO_PROCESS_CONFIRMED",    "proof_level": "OS_KERNEL" }
  },
  "proof_levels": {
    "gpu": "HARDWARE_NVML",
    "socket": "KERNEL_EBPF",
    "process": "OS_KERNEL"
  },
  "patent_ref": "USPTO PPA 63/983,493"
}
```

---

## API Endpoints

All endpoints are identical between the Python and Rust versions — drop-in compatible.

| Method | Endpoint | Description | Available |
|--------|----------|-------------|-----------|
| `GET` | `/` | AegisFrame UI (Tower + Monitor) | Both |
| `GET` | `/health` | Health check | Both |
| `GET` | `/api/v1/status` | System capabilities + patent refs | Both |
| `POST` | `/api/v1/tsa/anchor` | RFC 3161 timestamp anchoring | Both |
| `POST` | `/api/v1/pscp/prove` | PSCP hardware proof | Enterprise |
| `POST` | `/api/v1/pscp/prove/full` | PSCP proof + TSA anchor | Enterprise |
| `GET` | `/api/v1/pscp/status` | PSCP engine capabilities | Enterprise |
| `POST` | `/api/v1/pscp/snapshot` | Capture hardware state | Enterprise |
| `GET` | `/api/v1/pscp/trail` | Append-only proof trail | Enterprise |

---

## Quick Start

### Render (Standard)
```bash
cd render
cargo run --release
# → http://localhost:10000
```

### Enterprise (GPU Hardware Proof)
```bash
cd enterprise
cargo run --release
# → http://localhost:10000
```

### Enterprise (Docker + NVIDIA GPU)
```bash
cd enterprise
docker compose up --build
# → http://localhost:10000
```

### Build Both
```bash
# From workspace root
cargo build --release
# Binaries at:
#   target/release/aegisframe-render
#   target/release/aegisframe-enterprise
```

---

## Rust Dependencies

### Core Stack
| Crate | Purpose |
|-------|---------|
| `axum` 0.8 | Async web framework (tower-based) |
| `tokio` 1.x | Async runtime (multi-threaded) |
| `tower-http` 0.6 | Static file serving, CORS |
| `serde` / `serde_json` | JSON serialization |

### Cryptography & Evidence
| Crate | Purpose |
|-------|---------|
| `sha2` 0.10 | SHA-256 evidence chain hashing |
| `hex` 0.4 | Hex encoding for proof hashes |
| `chrono` 0.4 | UTC timestamps (ISO 8601) |
| `tempfile` 3 | Temporary files for TSA requests |

### Hardware Attestation (Enterprise)
| Crate | Purpose |
|-------|---------|
| `nvml-wrapper` 0.10 | NVIDIA NVML GPU driver bindings (optional `gpu` feature) |

### Observability
| Crate | Purpose |
|-------|---------|
| `tracing` 0.1 | Structured logging |
| `tracing-subscriber` 0.3 | Log output + env filter (`RUST_LOG`) |

---

## Feature Flags

```bash
# Standard build (no GPU)
cargo build --release -p aegisframe-enterprise

# With NVIDIA GPU support (requires NVML/CUDA)
cargo build --release -p aegisframe-enterprise --features gpu
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `10000` | Server listen port |
| `RUST_LOG` | `info` | Log level (`trace`, `debug`, `info`, `warn`, `error`) |

---

## EU AI Act Coverage

### Basic Mode (mandatory for all AI systems from Aug 2026)
- ✅ Art. 9 — Risk Management (7-Layer Stack)
- ✅ Art. 12 — Record-Keeping (SHA-256 Evidence Spine)
- ✅ Art. 13 — Transparency (Pre-Semantic Proof Panel)
- ✅ Art. 14 — Human Oversight (Countdown-Not-Auto-Stop)
- ✅ Art. 15 — Robustness (EMA Smoothing, Drift Detection)

### High-Risk Extension (Annex III: Medical, HR, Credit, Infrastructure)
- ✅ Art. 6 — Classification Evidence
- ✅ Art. 17 — Quality Management
- ✅ Conformity Assessment
- ✅ ECDSA P-256 Actor Signatures
- ✅ Oversight Token Flow (3-phase)
- ✅ Multi-Trail A/B/C
- ✅ External Audit Verifier
- ✅ Model Adapter Invariants
- ✅ INTEGRITY_ROOT + RFC 3161

---

## Patents

| # | Title | Filing | Status |
|---|-------|--------|--------|
| 1 | SIREN — Predictive Maintenance for Agricultural Robotics | 63/983,192 | Filed |
| 2 | PSCP — Pre-Semantic Structural Control Plane | 63/983,493 | Filed |
| 3 | MilkMind — Dairy Intelligence Platform | 63/986,414 | Filed |
| 4 | Electric Translator — Pre-Semantic Bidirectional Translation | — | Ready |
| 5 | AegisFrame — Risk-Adaptive AI Governance Engine | — | Ready |

---

## Python ↔ Rust Comparison

Both versions coexist in this repository. The Rust version is a **1:1 port** with identical API contracts.

| | Python | Rust |
|-|--------|------|
| **Framework** | Flask + Gunicorn | Axum + Tokio |
| **Server file** | `server.py` | `src/main.rs` |
| **PSCP Engine** | `api/pscp_proof.py` | `src/pscp/proof_engine.rs` |
| **GPU** | `pynvml` | `nvml-wrapper` (feature-gated) |
| **Socket** | `bcc` + `/proc/net` | `/proc/net` + eBPF subprocess |
| **Process** | `psutil` + `/proc` | `/proc` direct read |
| **Hashing** | `hashlib` | `sha2` crate |
| **JSON** | `flask.jsonify` | `serde_json` |
| **Startup** | `python server.py` | `cargo run --release` |
| **Binary** | Interpreter required | Single static binary |
| **Memory Safety** | Runtime (GC) | Compile-time (borrow checker) |

---

## License

Proprietary · © 2026 X-Loop³ Labs Ltd. · All rights reserved.

---

<p align="center">
  <strong>X-Loop³ Labs</strong><br>
  Kreuzlingen, Switzerland<br>
  <em>Pre-Semantic AI Infrastructure · Built with 🦀 Rust</em>
</p>
