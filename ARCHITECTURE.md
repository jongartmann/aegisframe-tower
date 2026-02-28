<p align="center">
  <img src="https://img.shields.io/badge/AegisFrame-Architecture-0a0e1a?style=for-the-badge&labelColor=12b47a&color=0a0e1a" />
  <img src="https://img.shields.io/badge/Rust-🦀-dea584?style=for-the-badge&logo=rust&logoColor=white" />
</p>

# 🏗 AegisFrame Rust Architecture

Deep dive into the Rust implementation — types, data flow, and design decisions.

---

## System Overview

```
                    ┌─────────────────────────────────┐
                    │         Browser / Client          │
                    └────────────────┬────────────────┘
                                     │ HTTP
                                     ↓
┌────────────────────────────────────────────────────────────────────┐
│                        Axum + Tokio Runtime                        │
│                                                                    │
│  ┌──────────┐  ┌──────────────┐  ┌────────────────────────────┐  │
│  │  Static  │  │  TSA Anchor  │  │  PSCP Hardware Proof       │  │
│  │  Files   │  │  (RFC 3161)  │  │  ┌────────────────────┐   │  │
│  │          │  │              │  │  │  PSCPProofEngine    │   │  │
│  │ ServeDir │  │  openssl ts  │  │  │  ┌──────────────┐  │   │  │
│  │          │  │     ↓        │  │  │  │ GpuAttestor  │  │   │  │
│  │          │  │  curl POST   │  │  │  │ (NVML)       │  │   │  │
│  │          │  │     ↓        │  │  │  ├──────────────┤  │   │  │
│  │          │  │  freetsa.org │  │  │  │ SocketMonitor│  │   │  │
│  │          │  │              │  │  │  │ (eBPF/proc)  │  │   │  │
│  │          │  │              │  │  │  ├──────────────┤  │   │  │
│  │          │  │              │  │  │  │ ProcessAttest│  │   │  │
│  │          │  │              │  │  │  │ (/proc scan) │  │   │  │
│  │          │  │              │  │  │  └──────────────┘  │   │  │
│  │          │  │              │  │  └────────────────────┘   │  │
│  └──────────┘  └──────────────┘  └────────────────────────────┘  │
│                                                                    │
│  State: Arc<AppState> { pscp_engine: PSCPProofEngine }            │
└────────────────────────────────────────────────────────────────────┘
```

---

## Type System

### Core Proof Types

The Rust type system enforces correctness at compile time. Every proof, attestation,
and snapshot is a concrete struct — not a loose `dict` or `JSON.parse()` result.

```
PscpProof
├── proof_type: String              "PSCP_HARDWARE_PROOF"
├── proof_id: String                "PSCP_000001_1740264000"
├── patent_ref: String              "USPTO PPA 63/983,493"
├── vendor: String                  "X-Loop³ Labs"
├── version: String                 "v0.7.0"
├── decision: String                "BLOCK" | "ALLOW"
├── request_hash: String            SHA-256 of the governed request
├── verdict: String                 "PSCP_BLOCK_VERIFIED" | "PSCP_BLOCK_VIOLATION" | "PSCP_ALLOW_RECORDED"
├── verified: bool
├── attestations: PscpAttestations
│   ├── gpu: GpuAttestation
│   ├── socket: SocketAttestation
│   └── process: ProcessAttestation
├── proof_levels: PscpProofLevels
│   ├── gpu: String                 "HARDWARE_NVML" | "UNAVAILABLE"
│   ├── socket: String              "KERNEL_EBPF" | "PROC_NET"
│   └── process: String             "OS_KERNEL"
├── timing: PscpTiming
│   ├── before_captured: String
│   ├── after_captured: String
│   └── proof_generated: String
├── timestamp: String
├── proof_hash: String              SHA-256 of entire proof object
└── tsa_anchor: Option<Value>       Present only on /prove/full
```

### Snapshot Types

Each attestor captures a typed snapshot before and after the governance decision:

```
HardwareState
├── gpu: GpuSnapshot
│   ├── available: bool
│   ├── mode: String                "NVML_HARDWARE" | "NO_GPU"
│   ├── device: Option<GpuDevice>
│   │   ├── index: u32
│   │   ├── name: String
│   │   ├── uuid: String
│   │   └── driver_version: Option<String>
│   ├── utilization: Option<GpuUtilization>
│   │   ├── gpu_percent: u32
│   │   └── memory_percent: u32
│   ├── memory: Option<GpuMemory>
│   │   ├── total_bytes: u64
│   │   ├── used_bytes: u64
│   │   └── free_bytes: u64
│   ├── processes: Option<GpuProcesses>
│   │   ├── compute_count: usize
│   │   ├── compute_pids: Vec<u32>
│   │   ├── graphics_count: usize
│   │   └── graphics_pids: Vec<u32>
│   ├── thermal: Option<GpuThermal>
│   └── snapshot_hash: Option<String>
│
├── socket: SocketSnapshot
│   ├── mode: String                "EBPF_KERNEL" | "PROC_NET"
│   ├── connections: SocketConnections
│   │   ├── total_established: usize
│   │   ├── total_listen: usize
│   │   ├── outbound_to_model_apis: usize
│   │   └── model_api_details: Vec<ConnectionDetail>
│   ├── socket_count: usize
│   └── snapshot_hash: Option<String>
│
├── process: ProcessSnapshot
│   ├── mode: String                "PROC_DIRECT"
│   ├── total_processes: usize
│   ├── inference_processes: InferenceProcessInfo
│   │   ├── count: usize
│   │   └── details: Vec<ProcessDetail>
│   ├── inference_ports: InferencePortInfo
│   ├── container: ContainerInfo
│   │   ├── isolated: bool
│   │   ├── container_id: Option<String>
│   │   └── runtime: Option<String>
│   ├── signatures_checked: usize
│   └── snapshot_hash: Option<String>
│
└── captured_at: String
```

---

## Data Flow

### PSCP Proof Cycle (`POST /api/v1/pscp/prove`)

```
1. HTTP Request
   { "request_hash": "abc...", "decision": "BLOCK" }
        │
        ↓
2. capture_before() ─────────────────────────┐
   ├── gpu_attestor.snapshot(0)              │
   │   └── NVML: read GPU counters          │
   ├── socket_monitor.snapshot_connections() │ HardwareState
   │   └── read /proc/net/tcp               │  (before)
   └── process_attestor.snapshot()           │
       └── scan /proc/[pid]/cmdline         │
                                             ↓
3. tokio::time::sleep(100ms)    ← governance decision window
                                             ↓
4. capture_after() ──────────────────────────┐
   ├── gpu_attestor.snapshot(0)              │ HardwareState
   ├── socket_monitor.snapshot_connections() │  (after)
   └── process_attestor.snapshot()           │
                                             ↓
5. produce_proof(before, after, decision, hash) ──────────┐
   │                                                       │
   ├── gpu_attestor.attest_no_inference(before, after)    │
   │   ├── Compare GPU utilization deltas                 │
   │   ├── Check for new compute PIDs                     │
   │   └── Verdict: NO_INFERENCE_CONFIRMED               │
   │                                                       │
   ├── socket_monitor.attest_no_outbound(before, after)   │
   │   ├── Compare connection counts                      │
   │   ├── Check for new model API connections            │
   │   └── Verdict: NO_OUTBOUND_CONFIRMED                │
   │                                                       │
   ├── process_attestor.attest_no_inference_process(...)  │
   │   ├── Compare process lists                          │
   │   ├── Check for new inference signatures             │
   │   └── Verdict: NO_PROCESS_CONFIRMED                 │
   │                                                       │
   ├── Combined verdict logic:                            │
   │   if BLOCK:                                          │
   │     gpu_ok && socket_ok && process_ok               │
   │     → PSCP_BLOCK_VERIFIED                           │
   │   if ALLOW:                                          │
   │     → PSCP_ALLOW_RECORDED                           │
   │                                                       │
   ├── SHA-256 hash of entire proof                       │
   └── Append to proof trail (Mutex<Vec>)                 │
                                                           ↓
6. HTTP Response: PscpProof (JSON)
```

### TSA Anchor Flow (`POST /api/v1/tsa/anchor`)

```
1. HTTP Request
   { "hash": "e3b0c44298fc1c149afb..." }
        │
        ↓
2. Validate: hash.len() == 64
        │
        ↓
3. call_rfc3161_tsa(hash_hex)
   │
   ├── TempDir::new()              ← tempfile crate (auto-cleanup)
   │
   ├── fs::write(hash_file, hash)
   │
   ├── Command::new("openssl")     ← subprocess
   │   .args(["ts", "-query", "-data", hash_file,
   │          "-no_nonce", "-sha256", "-out", tsq_file])
   │
   ├── Command::new("curl")        ← subprocess
   │   .args(["-s", "-S", "-H", "Content-Type: ...",
   │          "--data-binary", "@request.tsq",
   │          "-o", "response.tsr",
   │          "https://freetsa.org/tsr"])
   │
   ├── fs::read(tsr_file)          ← read TSA response bytes
   │
   ├── SHA-256(response_bytes)     ← token_hash
   │
   └── Command::new("openssl")     ← parse timestamp
       .args(["ts", "-reply", "-in", tsr_file, "-text"])
        │
        ↓
4. TsaResult { success, token_hash, receipt_hex, receipt_id, ... }
        │
        ↓
5. HTTP Response: TsaResponse (JSON)
   └── On failure: FALLBACK with deterministic hash
```

---

## Thread Safety Model

```
Arc<AppState>
└── PSCPProofEngine
    ├── GpuAttestor          ← immutable after init (no Mutex needed)
    │   └── nvml: Option<Nvml>   (NVML handles are thread-safe)
    │
    ├── SocketMonitor        ← immutable after init
    │   └── available: bool
    │
    ├── ProcessAttestor      ← immutable after init
    │   └── proc_path: String
    │
    ├── proof_counter: Mutex<u64>    ← atomic increment
    └── proofs: Mutex<Vec<ProofTrailEntry>>  ← append-only trail
```

- **`Arc<AppState>`** — Shared state across all Axum handler tasks
- **`Mutex<u64>`** — Proof counter, contention-free (held < 1μs)
- **`Mutex<Vec<...>>`** — Proof trail, append-only (held < 1μs)
- **Attestors** — Read-only after construction, safe to share without locking

---

## Conditional Compilation

GPU support is feature-gated to avoid requiring NVML/CUDA on all build targets:

```rust
// Cargo.toml
[features]
default = []
gpu = ["nvml-wrapper"]

// gpu_attestor.rs
#[cfg(feature = "gpu")]
use nvml_wrapper::Nvml;

#[cfg(feature = "gpu")]
fn snapshot_nvml(&self, ...) -> GpuSnapshot { ... }

#[cfg(not(feature = "gpu"))]
fn snapshot(&self, ...) -> GpuSnapshot {
    GpuSnapshot { available: false, mode: "NO_GPU", ... }
}
```

Without the `gpu` feature:
- `GpuAttestor::new()` returns `initialized: false`
- `snapshot()` returns `mode: "NO_GPU"`
- `attest_no_inference()` returns `verdict: "UNAVAILABLE"`
- The combined PSCP verdict still works — GPU is treated as "N/A"

---

## Hash Chain Integrity

Every object in the evidence chain is self-hashing:

```
GpuSnapshot
  → serde_json::to_string(&snap)
  → SHA-256
  → snap.snapshot_hash = hex(hash)

SocketSnapshot
  → serde_json::to_string(&snap)
  → SHA-256
  → snap.snapshot_hash = hex(hash)

ProcessSnapshot
  → serde_json::to_string(&snap)
  → SHA-256
  → snap.snapshot_hash = hex(hash)

GpuAttestation
  → serde_json::to_string(&{proof_type, proof_level, verdict, checks, deltas})
  → SHA-256
  → attestation.attestation_hash = hex(hash)

PscpProof
  → serde_json::to_string(&{...all fields except proof_hash...})
  → SHA-256
  → proof.proof_hash = hex(hash)
```

This creates a tamper-evident chain: modifying any field invalidates the hash.

---

## Serialization Strategy

All types derive `Serialize` + `Deserialize` via serde:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuSnapshot {
    pub available: bool,
    pub mode: String,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<GpuDevice>,
    // ...
}
```

Key patterns:
- **`#[serde(skip_serializing_if = "Option::is_none")]`** — Omit null fields from JSON
- **`Option<T>`** — Fields that may not be present (e.g., GPU data when no GPU)
- **`serde_json::json!{}`** — Used for dynamic JSON in status responses
- **`serde_json::Value`** — Used for `tsa_anchor` (flexible schema)

---

## Error Handling Strategy

| Layer | Strategy |
|-------|----------|
| HTTP handlers | `Result<impl IntoResponse, (StatusCode, Json<Value>)>` |
| TSA calls | `TsaResult { success: bool, error: Option<String> }` with FALLBACK |
| Subprocess | `Command::new().output()` with `match` on `Ok`/`Err` |
| File I/O | Early return with error message on failure |
| NVML | Feature-gated; graceful `"NO_GPU"` fallback |
| eBPF | Availability check at startup; `/proc/net` fallback |

The system **never panics** on external failures. Every hardware probe gracefully
degrades to a fallback mode that still produces valid (if less complete) proofs.

---

<p align="center">
  <strong>X-Loop³ Labs</strong> · Kreuzlingen, Switzerland<br>
  Patent Pending · USPTO<br>
  <em>Built with 🦀 Rust</em>
</p>
