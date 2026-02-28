<p align="center">
  <img src="https://img.shields.io/badge/AegisFrame-Enterprise_Rust-0a0e1a?style=for-the-badge&labelColor=12b47a&color=0a0e1a" />
  <img src="https://img.shields.io/badge/Rust-🦀-dea584?style=for-the-badge&logo=rust&logoColor=white" />
  <img src="https://img.shields.io/badge/PSCP-Hardware_Proof-red?style=for-the-badge" />
  <img src="https://img.shields.io/badge/NVIDIA-NVML_Attested-76B900?style=for-the-badge&logo=nvidia" />
</p>

# ⚡ AegisFrame Enterprise — Rust GPU Deployment

Hardware-attested PSCP proof stack on AWS EC2 with NVIDIA GPU.
Rewritten in Rust for compile-time safety and zero-overhead attestation.

---

## What This Proves

When AegisFrame blocks a prompt, this stack provides **three independent
hardware/OS-level proofs** that no AI inference occurred:

| Proof | Rust Module | Source | Level |
|-------|-------------|--------|-------|
| GPU Counter | `gpu_attestor.rs` | NVIDIA NVML | Hardware driver |
| Socket Monitor | `socket_monitor.rs` | eBPF + `/proc/net` | Linux kernel |
| Process Check | `process_attestor.rs` | `/proc` + cgroups | OS kernel |

This is **Patent 2 (PSCP, USPTO 63/983,493)** in action.

---

## Rust Module Architecture

```
enterprise/src/
├── main.rs                     # Axum HTTP server
│   ├── GET  /health            # Health check
│   ├── GET  /api/v1/status     # Capabilities + patent refs
│   ├── POST /api/v1/tsa/anchor # RFC 3161 TSA (freetsa.org)
│   ├── GET  /api/v1/pscp/status    # PSCP engine status
│   ├── POST /api/v1/pscp/snapshot  # Hardware state capture
│   ├── POST /api/v1/pscp/prove     # Full PSCP proof cycle
│   ├── POST /api/v1/pscp/prove/full # PSCP + TSA anchor
│   └── GET  /api/v1/pscp/trail     # Append-only proof trail
│
└── pscp/
    ├── mod.rs                  # Module declarations
    ├── proof_engine.rs         # PSCPProofEngine struct
    │   ├── capture_before()    # Pre-decision hardware snapshot
    │   ├── capture_after()     # Post-decision hardware snapshot
    │   ├── produce_proof()     # 3-layer attestation assembly
    │   ├── get_proof_trail()   # Append-only trail
    │   └── get_status()        # Engine capabilities
    │
    ├── gpu_attestor.rs         # GpuAttestor struct
    │   ├── snapshot()          # NVML hardware counter read
    │   └── attest_no_inference() # Before/after delta analysis
    │
    ├── socket_monitor.rs       # SocketMonitor struct
    │   ├── snapshot_connections() # /proc/net/tcp + eBPF
    │   └── attest_no_outbound()   # Connection delta analysis
    │
    └── process_attestor.rs     # ProcessAttestor struct
        ├── snapshot()          # /proc/[pid]/cmdline scan
        └── attest_no_inference_process() # Process delta analysis
```

---

## Setup

### Option A: Docker (Recommended)

#### 1. Launch EC2 Instance

- **Instance:** g5.xlarge (1x NVIDIA A10G, 24GB VRAM)
- **AMI:** Ubuntu 22.04 LTS
- **Storage:** 50 GB gp3
- **Security Group:** Open port 10000

#### 2. Install

```bash
ssh -i your-key.pem ubuntu@<EC2-IP>
git clone https://github.com/YOUR_USER/aegisframe-tower.git
cd aegisframe-tower/enterprise
chmod +x setup_ec2.sh
sudo ./setup_ec2.sh
```

#### 3. Run

```bash
docker compose up --build
```

The multi-stage Dockerfile handles the Rust build automatically:
1. **Build stage:** `rust:1.83-bookworm` compiles the binary
2. **Runtime stage:** `nvidia/cuda:12.2.0-base-ubuntu22.04` runs it with GPU + eBPF

#### 4. Access

Open `http://<EC2-IP>:10000`

---

### Option B: Native Build (Development)

```bash
# Install Rust (if not installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build enterprise binary
cd aegisframe-tower
cargo build --release -p aegisframe-enterprise

# Run
cd enterprise
../target/release/aegisframe-enterprise
```

#### With GPU Support

```bash
# Requires: NVIDIA CUDA Toolkit + NVML headers
cargo build --release -p aegisframe-enterprise --features gpu
```

---

## API

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check (JSON) |
| `GET` | `/api/v1/status` | Full system capabilities |
| `POST` | `/api/v1/tsa/anchor` | RFC 3161 timestamp (freetsa.org) |
| `GET` | `/api/v1/pscp/status` | PSCP engine capabilities |
| `POST` | `/api/v1/pscp/snapshot?phase=before` | Capture hardware state |
| `POST` | `/api/v1/pscp/prove` | Generate PSCP hardware proof |
| `POST` | `/api/v1/pscp/prove/full` | PSCP proof + RFC 3161 TSA anchor |
| `GET` | `/api/v1/pscp/trail` | Append-only proof trail |

---

## Example: Generate a Proof

### Request
```bash
curl -X POST http://localhost:10000/api/v1/pscp/prove \
  -H "Content-Type: application/json" \
  -d '{
    "request_hash": "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
    "decision": "BLOCK"
  }'
```

### Response
```json
{
  "proof_type": "PSCP_HARDWARE_PROOF",
  "proof_id": "PSCP_000001_1740264000",
  "patent_ref": "USPTO PPA 63/983,493",
  "vendor": "X-Loop³ Labs",
  "version": "v0.7.0",
  "decision": "BLOCK",
  "verdict": "PSCP_BLOCK_VERIFIED",
  "verified": true,
  "attestations": {
    "gpu": {
      "proof_type": "GPU_NO_INFERENCE_ATTESTATION",
      "proof_level": "HARDWARE_NVML",
      "verdict": "NO_INFERENCE_CONFIRMED",
      "checks": {
        "no_new_compute_processes": true,
        "gpu_util_stable": true,
        "memory_stable": true
      },
      "deltas": {
        "gpu_util_delta_percent": 0,
        "memory_delta_bytes": 0,
        "memory_delta_mb": 0.0,
        "new_compute_pids": []
      }
    },
    "socket": {
      "proof_type": "SOCKET_NO_OUTBOUND_ATTESTATION",
      "proof_level": "KERNEL_EBPF",
      "verdict": "NO_OUTBOUND_CONFIRMED",
      "checks": {
        "no_new_model_connections": true,
        "proc_net_clean": true
      },
      "monitored_endpoints": [
        "api.anthropic.com",
        "api.openai.com",
        "generativelanguage.googleapis.com",
        "api.mistral.ai"
      ]
    },
    "process": {
      "proof_type": "PROCESS_NO_INFERENCE_ATTESTATION",
      "proof_level": "OS_KERNEL",
      "verdict": "NO_PROCESS_CONFIRMED",
      "checks": {
        "no_new_inference_processes": true,
        "no_new_inference_ports": true,
        "zero_inference_at_end": true,
        "container_isolated": true
      }
    }
  },
  "proof_levels": {
    "gpu": "HARDWARE_NVML",
    "socket": "KERNEL_EBPF",
    "process": "OS_KERNEL"
  },
  "timing": {
    "before_captured": "2026-02-28T10:00:00.000Z",
    "after_captured": "2026-02-28T10:00:00.100Z",
    "proof_generated": "2026-02-28T10:00:00.101Z"
  },
  "proof_hash": "e3b0c44298fc1c149afbf4c8996fb924..."
}
```

---

## Example: Full Proof + TSA Anchor

```bash
curl -X POST http://localhost:10000/api/v1/pscp/prove/full \
  -H "Content-Type: application/json" \
  -d '{"decision": "BLOCK"}'
```

Returns the same proof object plus a `tsa_anchor` block:

```json
{
  "...proof fields...",
  "tsa_anchor": {
    "anchored": true,
    "tsa_provider": "freetsa.org",
    "tsa_protocol": "RFC 3161",
    "proof_hash_anchored": "e3b0c44298fc1c149afbf4c8996fb924...",
    "tsa_receipt_id": "TSA_1740264001_a1b2c3d4",
    "tsa_timestamp": "Feb 28 10:00:01 2026 GMT"
  }
}
```

---

## Docker Architecture

```
┌─────────────────────────────────────────────────────┐
│  Build Stage (rust:1.83-bookworm)                   │
│  ├── cargo build --release -p aegisframe-enterprise │
│  └── Output: /build/target/release/aegisframe-...   │
└──────────────────────┬──────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────┐
│  Runtime Stage (nvidia/cuda:12.2.0-base-ubuntu22.04)│
│  ├── BINARY: /app/aegisframe-enterprise             │
│  ├── STATIC: /app/static/index.html                 │
│  ├── TOOLS:  openssl, curl, bpftrace, procps        │
│  ├── MOUNT:  /proc → /host/proc (read-only)         │
│  ├── MOUNT:  /sys/kernel/debug (eBPF)               │
│  └── GPU:    NVIDIA runtime + --gpus all             │
└─────────────────────────────────────────────────────┘
```

---

## Monitored Inference Endpoints

The socket attestor watches for connections to these model API endpoints:

| Endpoint | Service |
|----------|---------|
| `api.anthropic.com` | Anthropic Claude |
| `api.openai.com` | OpenAI GPT |
| `generativelanguage.googleapis.com` | Google Gemini |
| `api.mistral.ai` | Mistral |
| `api.cohere.ai` | Cohere |
| `api-inference.huggingface.co` | Hugging Face |
| `api.together.xyz` | Together AI |
| `api.fireworks.ai` | Fireworks AI |
| `api.replicate.com` | Replicate |
| `localhost:11434` | Ollama (local) |
| `localhost:8080` | vLLM (local) |
| `localhost:3000` | LM Studio (local) |

---

## Inference Process Signatures

The process attestor scans `/proc` for these framework signatures:

| Signature | Framework |
|-----------|-----------|
| `transformers` | Hugging Face Transformers |
| `vllm` | vLLM inference server |
| `torch` | PyTorch |
| `tensorflow` | TensorFlow |
| `tritonserver` | NVIDIA Triton |
| `text-generation-launcher` | TGI |
| `ollama` | Ollama |
| `llama.cpp` / `llama-server` | llama.cpp |
| `koboldcpp` | KoboldCpp |
| `ggml` | GGML |
| `onnxruntime` | ONNX Runtime |
| `trtllm` | TensorRT-LLM |
| `deepspeed` | DeepSpeed |
| `accelerate` | HF Accelerate |

---

## Cost (AWS EC2)

| Mode | Instance | Cost |
|------|----------|------|
| Demo (2h) | g5.xlarge Spot | ~$0.60 |
| Monthly (10h) | g5.xlarge Spot | ~$3.00 |
| Always-on | g5.xlarge Reserved 1yr | ~$360/yr |

Recommendation: Use Spot instances, spin up for demos and customer calls only.

---

<p align="center">
  <strong>X-Loop³ Labs</strong> · Kreuzlingen, Switzerland<br>
  Patent Pending · USPTO 63/983,493<br>
  <em>Built with 🦀 Rust</em>
</p>
