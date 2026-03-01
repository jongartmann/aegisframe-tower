# AegisFrame — Enterprise GPU Deployment (Rust)

Hardware-attested PSCP Proof Stack auf AWS EC2 mit NVIDIA GPU — Rust Edition.

---

## Was dieser Stack beweist

Wenn AegisFrame einen Prompt blockiert, liefert dieser Stack **drei unabhängige Hardware/OS-Level Beweise**, dass keine AI-Inferenz stattgefunden hat:

| Proof | Quelle | Level | Rust-Modul |
|-------|--------|-------|------------|
| GPU Counter | NVIDIA NVML | Hardware Driver | `aegis-pscp::gpu` |
| Socket Monitor | eBPF / /proc/net | Linux Kernel | `aegis-pscp::socket` |
| Process Check | /proc + cgroups | OS Kernel | `aegis-pscp::process` |

Dies ist **Patent 2 (PSCP, USPTO 63/983,493)** in Aktion.

## Modul-Architektur

```
aegis-pscp/
├── src/
│   ├── lib.rs              # Public API: PSCPEngine
│   ├── engine.rs           # Proof-Orchestrator
│   │   ├── capture_before()   → Snapshot aller 3 Quellen
│   │   ├── capture_after()    → Snapshot nach Entscheidung
│   │   ├── produce_proof()    → Kombinierter PSCP_PROOF
│   │   └── get_proof_trail()  → Append-Only Trail
│   │
│   ├── gpu.rs              # GPU Attestation [feature = "gpu"]
│   │   ├── GpuAttestor::new()       → NVML Init + Device Discovery
│   │   ├── GpuAttestor::snapshot()  → Utilization, Memory, PIDs, Temp, Clocks
│   │   └── GpuAttestor::attest()    → Delta-Vergleich → Verdict
│   │
│   ├── socket.rs           # Socket Monitor [feature = "ebpf"]
│   │   ├── SocketMonitor::new()              → eBPF Verfügbarkeit prüfen
│   │   ├── SocketMonitor::snapshot()         → /proc/net/tcp + eBPF Trace
│   │   └── SocketMonitor::attest_no_outbound() → Verbindungs-Delta
│   │
│   └── process.rs          # Process Attestation
│       ├── ProcessAttestor::new()       → /proc oder sysinfo Init
│       ├── ProcessAttestor::snapshot()  → Inference-Signaturen scannen
│       └── ProcessAttestor::attest()    → Prozess-Delta → Verdict
```

### Bedingte Kompilierung

```rust
// gpu.rs — nur kompiliert mit --features gpu
#[cfg(feature = "gpu")]
pub struct GpuAttestor {
    nvml: nvml_wrapper::Nvml,
    device: nvml_wrapper::Device,
}

#[cfg(not(feature = "gpu"))]
pub struct GpuAttestor;  // Stub: immer "UNAVAILABLE"
```

## Docker Setup (Rust)

### Dockerfile

```dockerfile
# ── Stage 1: Build ──────────────────────────────────
FROM rust:1.78-bookworm AS builder

RUN apt-get update && apt-get install -y \
    pkg-config libssl-dev

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

# Enterprise-Build mit GPU + eBPF
RUN cargo build --release --features enterprise

# ── Stage 2: Runtime ────────────────────────────────
FROM nvidia/cuda:12.2.0-base-ubuntu22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    bpfcc-tools bpftrace linux-headers-generic \
    ca-certificates curl procps iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/aegis-server /usr/local/bin/aegisframe
COPY static/ /app/static/

WORKDIR /app
EXPOSE 10000

CMD ["aegisframe"]
```

### docker-compose.yml

```yaml
services:
  aegisframe:
    build: .
    runtime: nvidia
    privileged: true
    ports:
      - "10000:10000"
    environment:
      - NVIDIA_VISIBLE_DEVICES=all
      - NVIDIA_DRIVER_CAPABILITIES=compute,utility
      - AEGISFRAME_MODE=HARDWARE_PROOF
      - AEGISFRAME_LOG=info
      - RUST_LOG=aegisframe=info,tower_http=info
    volumes:
      - /sys/kernel/debug:/sys/kernel/debug:ro
      - /proc:/host/proc:ro
      - /sys/fs/cgroup:/host/cgroup:ro
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: 1
              capabilities: [gpu]
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:10000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
```

### Vorteile vs. Python Docker

| Aspekt | Python Image | Rust Image |
|--------|-------------|------------|
| Image Size | ~1.2 GB | ~200 MB |
| Startup | ~2s (Gunicorn Fork) | ~50ms |
| Memory | ~80 MB | ~8 MB |
| Layers | 6 (CUDA + Python + pip + code) | 3 (CUDA + binary + static) |
| Angriffsfläche | Python + pip + alle Deps | Statisches Binary |

## EC2 Setup

### 1. Launch EC2 Instance

- **Instance:** g5.xlarge (1x NVIDIA A10G, 24 GB VRAM)
- **AMI:** Ubuntu 22.04 LTS
- **Storage:** 50 GB gp3
- **Security Group:** Port 10000 öffnen

### 2. Install

```bash
ssh -i your-key.pem ubuntu@<EC2-IP>
git clone https://github.com/XLOOP3/aegisframe-tower.git
cd aegisframe-tower/enterprise
chmod +x setup_ec2.sh
sudo ./setup_ec2.sh
```

### 3. Build & Run

```bash
docker compose up --build
```

### 4. Access

```
http://<EC2-IP>:10000
```

## API-Endpoints

| Method | Endpoint | Beschreibung |
|--------|----------|--------------|
| `POST` | `/api/v1/pscp/prove` | Hardware Proof generieren |
| `POST` | `/api/v1/pscp/prove/full` | Proof + RFC 3161 TSA Anchor |
| `GET` | `/api/v1/pscp/status` | Engine Capabilities |
| `GET` | `/api/v1/pscp/trail` | Append-Only Proof Trail |
| `POST` | `/api/v1/tsa/anchor` | RFC 3161 Timestamp |
| `GET` | `/health` | Health Check |
| `GET` | `/api/v1/status` | System-Status |

## API-Beispiele mit curl + JSON

### PSCP Hardware Proof generieren

```bash
curl -X POST http://localhost:10000/api/v1/pscp/prove \
  -H "Content-Type: application/json" \
  -d '{
    "request_hash": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    "decision": "BLOCK"
  }'
```

**Response:**

```json
{
  "proof_type": "PSCP_HARDWARE_PROOF",
  "proof_id": "PSCP_000001_1740264000",
  "verdict": "PSCP_BLOCK_VERIFIED",
  "verified": true,
  "decision": "BLOCK",
  "request_hash": "a1b2c3d4...",
  "attestations": {
    "gpu": {
      "proof_type": "GPU_NO_INFERENCE_ATTESTATION",
      "proof_level": "HARDWARE_NVML",
      "verdict": "NO_INFERENCE_CONFIRMED",
      "deltas": {
        "gpu_util_delta_percent": 0,
        "memory_delta_bytes": 0,
        "new_compute_pids": []
      }
    },
    "socket": {
      "proof_type": "SOCKET_NO_OUTBOUND_ATTESTATION",
      "proof_level": "KERNEL_EBPF",
      "verdict": "NO_OUTBOUND_CONFIRMED",
      "deltas": {
        "new_model_api_connections": 0,
        "ebpf_bytes_sent": 0,
        "ebpf_connect_calls": 0
      }
    },
    "process": {
      "proof_type": "PROCESS_NO_INFERENCE_ATTESTATION",
      "proof_level": "OS_KERNEL",
      "verdict": "NO_PROCESS_CONFIRMED",
      "deltas": {
        "new_inference_processes": 0,
        "new_inference_ports": 0
      }
    }
  },
  "proof_hash": "8f3a2b...",
  "patent_ref": "USPTO PPA 63/983,493",
  "vendor": "X-Loop³ Labs"
}
```

### PSCP Full Proof (+ TSA Anchor)

```bash
curl -X POST http://localhost:10000/api/v1/pscp/prove/full \
  -H "Content-Type: application/json" \
  -d '{
    "request_hash": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    "decision": "BLOCK"
  }'
```

**Response enthält zusätzlich:**

```json
{
  "...": "... (wie oben) ...",
  "tsa_anchor": {
    "anchored": true,
    "tsa_provider": "freetsa.org",
    "tsa_protocol": "RFC 3161",
    "proof_hash_anchored": "8f3a2b...",
    "tsa_receipt_id": "TSA_1740264001_4f2e8a1c",
    "tsa_timestamp": "Mar  1 12:00:00 2026 GMT"
  }
}
```

### TSA Anchor (RFC 3161)

```bash
curl -X POST http://localhost:10000/api/v1/tsa/anchor \
  -H "Content-Type: application/json" \
  -d '{
    "hash": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    "timestamp": "2026-03-01T12:00:00Z"
  }'
```

**Response:**

```json
{
  "status": "ANCHORED",
  "tsa_provider": "freetsa.org",
  "tsa_protocol": "RFC 3161",
  "tsa_mode": "LIVE",
  "anchored_hash": "a1b2c3d4...",
  "tsa_token": "c7d8e9f0...",
  "receipt_id": "TSA_1740264000_c7d8e9f0",
  "tsa_response_size": 3247,
  "verified": true
}
```

### PSCP Status

```bash
curl http://localhost:10000/api/v1/pscp/status
```

```json
{
  "engine": "PSCP Hardware Proof Engine",
  "proofs_generated": 42,
  "capabilities": {
    "gpu_nvml": true,
    "gpu_device": 1,
    "gpu_driver": "535.129.03",
    "ebpf": true,
    "process_monitor": true
  },
  "patent_ref": "USPTO PPA 63/983,493"
}
```

### Proof Trail

```bash
curl http://localhost:10000/api/v1/pscp/trail
```

```json
{
  "trail": [
    {
      "proof_id": "PSCP_000001_1740264000",
      "proof_hash": "8f3a2b...",
      "verdict": "PSCP_BLOCK_VERIFIED",
      "timestamp": "2026-03-01T12:00:00Z"
    }
  ],
  "count": 1
}
```

## Monitored Endpoints

Der Socket Monitor überwacht diese bekannten Model-Inference API-Endpoints:

| Endpoint | Anbieter |
|----------|----------|
| `api.anthropic.com` | Anthropic (Claude) |
| `api.openai.com` | OpenAI (GPT) |
| `generativelanguage.googleapis.com` | Google (Gemini) |
| `api.mistral.ai` | Mistral AI |
| `api.cohere.ai` | Cohere |
| `api-inference.huggingface.co` | Hugging Face |
| `api.together.xyz` | Together AI |
| `api.fireworks.ai` | Fireworks AI |
| `api.replicate.com` | Replicate |
| `localhost:11434` | Ollama (lokal) |
| `localhost:8080` | vLLM (lokal) |
| `localhost:3000` | LM Studio (lokal) |

Jede ausgehende Verbindung zu diesen Endpoints während eines PSCP-BLOCK würde das Verdict auf `OUTBOUND_DETECTED` setzen.

## EC2 Kosten

| Modus | Instance | Kosten |
|-------|----------|--------|
| Demo (2h) | g5.xlarge Spot | ~$0.60 |
| Monatlich (10h) | g5.xlarge Spot | ~$3.00 |
| Always-on | g5.xlarge Reserved 1yr | ~$360/yr |

**Empfehlung:** Spot Instances verwenden, nur für Demos und Kundentermine hochfahren.

---

X-Loop³ Labs · Kreuzlingen, Switzerland · Patent Pending · USPTO 63/983,493
