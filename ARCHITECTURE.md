# AegisFrame — Architektur (Rust)

Technische Tiefe: Type System, PSCP Data Flow, Thread Safety, Hash Chain, Conditional Compilation, Error Handling.

---

## Inhaltsverzeichnis

1. [Type System](#type-system)
2. [PSCP Data Flow](#pscp-data-flow)
3. [Thread Safety Model](#thread-safety-model)
4. [Hash Chain (Evidence Spine)](#hash-chain-evidence-spine)
5. [Conditional Compilation](#conditional-compilation)
6. [Error Handling](#error-handling)

---

## Type System

### Kern-Typen (`aegis-core`)

```rust
/// Governance-Entscheidung eines Gates
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum GateDecision {
    Allow,
    Warn { reason: String },
    Defend { mitigation: String },
    Lock { evidence_hash: String },
}

/// Risk Tier nach EU AI Act Annex III
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum RiskTier {
    Minimal,        // Spam-Filter, Spiele
    Limited,        // Chatbots, Empfehlungssysteme
    High,           // Medizin, HR, Kredit, Infrastruktur
    Unacceptable,   // Social Scoring, Massenüberwachung
}

/// Autonomie-Gradient (Layer 7)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum AutonomyLevel {
    L0,  // Kein AI-Einfluss
    L1,  // AI schlägt vor, Mensch entscheidet
    L2,  // AI entscheidet, Mensch überwacht
    L3,  // AI entscheidet autonom, Mensch kann eingreifen
    L4,  // AI entscheidet autonom, Mensch wird informiert
    L5,  // Volle Autonomie (nur Minimal-Risk erlaubt)
}

/// ECDSA P-256 Akteur-Signatur
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorSignature {
    pub actor_id: ActorId,
    pub role: ActorRole,
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
    pub signed_at: chrono::DateTime<chrono::Utc>,
}

/// Akteur-Rollen im 3-Phasen Oversight
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ActorRole {
    Operator,       // Trail A: Governance-Entscheidungen
    Invoker,        // Trail B: Invocation/Prompt-Daten
    Auditor,        // Trail C: Externe Audit-Verifizierung
}

/// Evidence Trail Entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceEntry {
    pub sequence: u64,
    pub trail: TrailId,
    pub event_type: String,
    pub payload_hash: String,
    pub previous_hash: String,
    pub entry_hash: String,
    pub actor_signature: Option<ActorSignature>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Trail-Identifikation
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum TrailId {
    A,  // Governance Trail
    B,  // Invocation Trail
    C,  // Auditor Trail
}
```

### PSCP-Typen (`aegis-pscp`)

```rust
/// PSCP Proof — das zentrale Beweisobjekt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PscpProof {
    pub proof_type: &'static str,    // "PSCP_HARDWARE_PROOF"
    pub proof_id: String,
    pub patent_ref: &'static str,    // "USPTO PPA 63/983,493"
    pub vendor: &'static str,        // "X-Loop³ Labs"
    pub version: &'static str,
    pub decision: Decision,
    pub request_hash: String,
    pub verdict: PscpVerdict,
    pub verified: bool,
    pub attestations: Attestations,
    pub proof_levels: ProofLevels,
    pub timing: ProofTiming,
    pub proof_hash: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// PSCP Verdict
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PscpVerdict {
    BlockVerified,      // BLOCK + alle Attestations bestätigt
    BlockViolation,     // BLOCK aber Inferenz detected!
    AllowRecorded,      // ALLOW entscheidung aufgezeichnet
}

/// Governance-Entscheidung
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Decision {
    Block,
    Allow,
}

/// Die drei unabhängigen Attestations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestations {
    pub gpu: GpuAttestation,
    pub socket: SocketAttestation,
    pub process: ProcessAttestation,
}

/// GPU Snapshot — direkt vom NVML Treiber
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuSnapshot {
    pub available: bool,
    pub mode: GpuMode,
    pub utilization: Option<GpuUtilization>,
    pub memory: Option<GpuMemory>,
    pub processes: Option<GpuProcesses>,
    pub thermal: Option<GpuThermal>,
    pub clocks: Option<GpuClocks>,
    pub device: Option<GpuDevice>,
    pub snapshot_hash: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GpuMode {
    NvmlHardware,   // Echte NVML Daten
    NoGpu,          // Kein GPU verfügbar
    NvmlError,      // GPU da aber NVML Fehler
}
```

### Type System Diagramm

```
                    ┌───────────────────────┐
                    │    aegis-core Types    │
                    ├───────────────────────┤
                    │ GateDecision          │
                    │ RiskTier              │
                    │ AutonomyLevel         │
                    │ ActorSignature        │
                    │ ActorRole             │
                    │ EvidenceEntry         │
                    │ TrailId               │
                    │ HashChain             │
                    │ IntegrityRoot         │
                    └──────────┬────────────┘
                               │
              ┌────────────────┼────────────────┐
              ↓                ↓                ↓
   ┌──────────────────┐ ┌───────────┐ ┌────────────────┐
   │  aegis-pscp Types│ │aegis-tsa  │ │ aegis-server   │
   ├──────────────────┤ │  Types    │ │    Types       │
   │ PscpProof        │ ├───────────┤ ├────────────────┤
   │ PscpVerdict      │ │ TsaReq    │ │ AppState       │
   │ Decision         │ │ TsaResp   │ │ ApiError       │
   │ GpuSnapshot      │ │ TsaAnchor │ │ Route Handlers │
   │ GpuAttestation   │ │ TsaMode   │ └────────────────┘
   │ SocketSnapshot   │ └───────────┘
   │ SocketAttestation│
   │ ProcessSnapshot  │
   │ ProcessAttestation│
   └──────────────────┘
```

---

## PSCP Data Flow

### Vollständiger Proof-Cycle

```
Client POST /api/v1/pscp/prove
    │
    │  { "request_hash": "abc...", "decision": "BLOCK" }
    │
    ↓
┌─────────────────────────────────────────────────────────────┐
│  Axum Handler: pscp_prove()                                  │
│                                                              │
│  1. Parse Request Body → Decision + RequestHash             │
│                                                              │
│  2. BEFORE Snapshot ─────────────────────────────────────   │
│     │                                                        │
│     ├── gpu.snapshot()                                       │
│     │   ├── nvmlDeviceGetUtilizationRates()                 │
│     │   ├── nvmlDeviceGetMemoryInfo()                       │
│     │   ├── nvmlDeviceGetComputeRunningProcesses()          │
│     │   ├── nvmlDeviceGetTemperature()                      │
│     │   └── SHA-256(snapshot) → snapshot_hash               │
│     │                                                        │
│     ├── socket.snapshot()                                    │
│     │   ├── read /proc/net/tcp                              │
│     │   ├── parse hex IPs + ports                           │
│     │   ├── filter model_api_connections                    │
│     │   └── SHA-256(snapshot) → snapshot_hash               │
│     │                                                        │
│     └── process.snapshot()                                   │
│         ├── sysinfo::System::refresh_processes()            │
│         ├── match INFERENCE_SIGNATURES                      │
│         ├── check INFERENCE_PORTS                           │
│         ├── read cgroup info                                │
│         └── SHA-256(snapshot) → snapshot_hash               │
│                                                              │
│  3. ── Governance Decision Window (~100ms) ──               │
│     (In Production: hier passiert die echte Entscheidung)    │
│                                                              │
│  4. AFTER Snapshot (identisch zu #2) ───────────────────    │
│                                                              │
│  5. Produce Proof ──────────────────────────────────────    │
│     │                                                        │
│     ├── gpu.attest(before, after)                           │
│     │   ├── delta gpu_util                                  │
│     │   ├── delta memory_used                               │
│     │   ├── diff compute_pids                               │
│     │   └── → NO_INFERENCE_CONFIRMED / INFERENCE_DETECTED   │
│     │                                                        │
│     ├── socket.attest(before, after)                        │
│     │   ├── delta model_api_connections                     │
│     │   ├── ebpf bytes_sent (wenn verfügbar)               │
│     │   └── → NO_OUTBOUND_CONFIRMED / OUTBOUND_DETECTED    │
│     │                                                        │
│     ├── process.attest(before, after)                       │
│     │   ├── delta inference_processes                       │
│     │   ├── delta inference_ports                           │
│     │   ├── container isolation check                       │
│     │   └── → NO_PROCESS_CONFIRMED / PROCESS_DETECTED      │
│     │                                                        │
│     ├── Combined Verdict                                    │
│     │   if BLOCK && all 3 confirmed:                        │
│     │       → PSCP_BLOCK_VERIFIED                           │
│     │   if BLOCK && any failed:                             │
│     │       → PSCP_BLOCK_VIOLATION                          │
│     │   if ALLOW:                                           │
│     │       → PSCP_ALLOW_RECORDED                           │
│     │                                                        │
│     ├── SHA-256(proof) → proof_hash                         │
│     │                                                        │
│     └── Append to proof_trail                               │
│                                                              │
│  6. Return JSON Proof Object                                │
│                                                              │
└─────────────────────────────────────────────────────────────┘
    │
    ↓
Client receives PscpProof JSON
```

### Full Proof (+ TSA Anchor)

```
POST /api/v1/pscp/prove/full
    │
    ↓
┌──────────────────────────────────┐
│  Steps 1-5 (wie oben)            │
│         ↓                        │
│  proof_hash = SHA-256(proof)     │
│         ↓                        │
│  TSA Anchor:                     │
│  ├── rasn::encode(TimeStampReq)  │
│  ├── reqwest POST freetsa.org    │
│  ├── rasn::decode(TimeStampResp) │
│  └── tsa_anchor in Proof einfügen│
│         ↓                        │
│  Return Proof + TSA Anchor       │
└──────────────────────────────────┘
```

---

## Thread Safety Model

### Shared State Architektur

```rust
/// Application State — geteilt zwischen allen Tokio Tasks
pub struct AppState {
    /// PSCP Proof Engine (Mutable State)
    pscp: Arc<RwLock<PscpEngine>>,

    /// TSA Client (Stateless, Clone-fähig)
    tsa: TsaClient,

    /// Evidence Chain (Append-Only)
    evidence: Arc<RwLock<EvidenceChain>>,

    /// Konfiguration (Read-Only nach Init)
    config: Arc<Config>,
}
```

### Lock-Strategie

```
                ┌──────────────────────────────────────┐
                │           Tokio Runtime               │
                │                                       │
                │  Task 1 ──┐                          │
                │  Task 2 ──┤                          │
                │  Task 3 ──┤                          │
                │  Task N ──┘                          │
                │       ↓                              │
                │  ┌─────────────────────────────┐     │
                │  │     Arc<AppState>            │     │
                │  ├─────────────────────────────┤     │
                │  │                              │     │
                │  │  pscp: Arc<RwLock<...>>      │     │
                │  │  ├── Read:  snapshot()       │     │
                │  │  ├── Read:  get_status()     │     │
                │  │  ├── Read:  get_trail()      │     │
                │  │  └── Write: produce_proof()  │     │
                │  │                              │     │
                │  │  evidence: Arc<RwLock<...>>  │     │
                │  │  ├── Read:  verify()         │     │
                │  │  └── Write: append()         │     │
                │  │                              │     │
                │  │  tsa: TsaClient (Clone)      │     │
                │  │  └── reqwest (async, no lock) │     │
                │  │                              │     │
                │  │  config: Arc<Config>          │     │
                │  │  └── Read-only (no lock)     │     │
                │  │                              │     │
                │  └─────────────────────────────┘     │
                └──────────────────────────────────────┘
```

### Concurrency-Garantien

| Komponente | Typ | Zugriff | Begründung |
|-----------|-----|---------|------------|
| `PscpEngine` | `Arc<RwLock>` | Read-heavy, seltene Writes | Snapshots sind Read, nur `produce_proof` ist Write |
| `EvidenceChain` | `Arc<RwLock>` | Append-Only | Neue Entries werden angehängt, nie geändert |
| `TsaClient` | `Clone` | Stateless | reqwest::Client ist intern `Arc`, lock-free |
| `Config` | `Arc<T>` | Read-Only | Nach Init nie mehr geändert |
| `ProofTrail` | Teil von `PscpEngine` | Via RwLock | Append-only Vec, Write bei neuem Proof |

### Kein `unsafe` im Anwendungscode

```rust
// ✅ So machen wir es:
let state = state.pscp.read().await;
let status = state.get_status();

// ❌ Niemals:
unsafe { /* ... */ }
```

Die einzigen `unsafe`-Blöcke liegen in Dependencies:
- `nvml-wrapper`: FFI zu C NVML Library
- `ring`: Kryptographie-Operationen
- `tokio`: Runtime-Interna

---

## Hash Chain (Evidence Spine)

### Struktur

```
Entry 0 (Genesis)
┌─────────────────────────────────────┐
│ sequence: 0                          │
│ previous_hash: "GENESIS"             │
│ payload_hash: SHA-256(genesis_data)  │
│ entry_hash: SHA-256(                 │
│   sequence + previous + payload      │
│   + trail + timestamp                │
│ )                                    │
└────────────────┬────────────────────┘
                 │
                 ↓ entry_hash wird previous_hash
Entry 1
┌─────────────────────────────────────┐
│ sequence: 1                          │
│ previous_hash: entry_0.entry_hash    │
│ payload_hash: SHA-256(gate_decision) │
│ entry_hash: SHA-256(                 │
│   sequence + previous + payload      │
│   + trail + timestamp                │
│ )                                    │
└────────────────┬────────────────────┘
                 │
                 ↓
Entry 2
┌─────────────────────────────────────┐
│ sequence: 2                          │
│ previous_hash: entry_1.entry_hash    │
│ payload_hash: SHA-256(pscp_proof)    │
│ entry_hash: SHA-256(...)             │
└────────────────┬────────────────────┘
                 │
                 ↓
              ... (append-only)
```

### Rust Implementation

```rust
pub struct HashChain {
    entries: Vec<EvidenceEntry>,
    current_hash: String,
}

impl HashChain {
    pub fn new() -> Self {
        let genesis = EvidenceEntry::genesis();
        Self {
            current_hash: genesis.entry_hash.clone(),
            entries: vec![genesis],
        }
    }

    /// Neuen Entry anhängen — O(1)
    pub fn append(&mut self, trail: TrailId, event_type: &str,
                  payload: &[u8]) -> &EvidenceEntry {
        let sequence = self.entries.len() as u64;
        let payload_hash = sha256_hex(payload);
        let previous_hash = self.current_hash.clone();

        let entry_hash = sha256_hex(
            &format!("{sequence}{previous_hash}{payload_hash}{trail:?}")
        );

        let entry = EvidenceEntry {
            sequence,
            trail,
            event_type: event_type.to_string(),
            payload_hash,
            previous_hash,
            entry_hash: entry_hash.clone(),
            actor_signature: None,
            timestamp: chrono::Utc::now(),
        };

        self.current_hash = entry_hash;
        self.entries.push(entry);
        self.entries.last().unwrap()
    }

    /// Chain-Integrität verifizieren — O(n)
    pub fn verify(&self) -> bool {
        for i in 1..self.entries.len() {
            let prev = &self.entries[i - 1];
            let curr = &self.entries[i];

            // Previous hash muss auf vorherigen Entry zeigen
            if curr.previous_hash != prev.entry_hash {
                return false;
            }

            // Entry hash muss korrekt berechnet sein
            let expected = sha256_hex(&format!(
                "{}{}{}{}",
                curr.sequence, curr.previous_hash,
                curr.payload_hash, format!("{:?}", curr.trail)
            ));
            if curr.entry_hash != expected {
                return false;
            }
        }
        true
    }
}
```

### Tamper Detection

```
Originale Chain:
  [A] → [B] → [C] → [D]
   ↓      ↓      ↓      ↓
  h0     h1     h2     h3
         ↑      ↑      ↑
        h0     h1     h2

Manipulierte Chain (Entry B geändert):
  [A] → [B'] → [C] → [D]
   ↓      ↓       ↓      ↓
  h0     h1'     h2     h3
         ↑       ↑      ↑
        h0      h1     h2     ← h1' ≠ h1 → TAMPER DETECTED
```

### INTEGRITY_ROOT

```rust
/// Bindet alle drei Trails + Policy Spec zusammen
pub struct IntegrityRoot {
    pub trail_a_hash: String,   // Letzter Hash in Governance Trail
    pub trail_b_hash: String,   // Letzter Hash in Invocation Trail
    pub trail_c_hash: String,   // Letzter Hash in Auditor Trail
    pub policy_spec_hash: String, // SHA-256 der Policy-Konfiguration
    pub root_hash: String,      // SHA-256(A + B + C + Policy)
    pub tsa_anchor: Option<TsaAnchor>, // RFC 3161 Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
}
```

---

## Conditional Compilation

### Feature-basierte Module

```rust
// In aegis-pscp/src/lib.rs

// GPU Module — nur mit --features gpu
#[cfg(feature = "gpu")]
pub mod gpu;
#[cfg(feature = "gpu")]
pub use gpu::GpuAttestor;

// Stub wenn kein GPU Feature
#[cfg(not(feature = "gpu"))]
pub mod gpu_stub;
#[cfg(not(feature = "gpu"))]
pub use gpu_stub::GpuAttestor;

// eBPF Module — nur mit --features ebpf
#[cfg(feature = "ebpf")]
pub mod ebpf;

// Socket Monitor wählt Backend automatisch
pub mod socket;  // Nutzt eBPF oder /proc/net Fallback

// Process Monitor — immer verfügbar
pub mod process;
```

### Cargo.toml Feature Deklaration

```toml
# crates/aegis-pscp/Cargo.toml
[features]
default = []
gpu = ["dep:nvml-wrapper"]
ebpf = []
enterprise = ["gpu", "ebpf"]

[dependencies]
aegis-core = { path = "../aegis-core" }
sysinfo = "0.30"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
chrono = { version = "0.4", features = ["serde"] }
tracing = "0.1"

[dependencies.nvml-wrapper]
version = "0.10"
optional = true
```

### Compile-Zeit Verifikation

```rust
// Der Compiler garantiert, dass GPU-Code
// nur mit dem GPU-Feature kompiliert wird:

#[cfg(feature = "gpu")]
fn real_gpu_snapshot() -> GpuSnapshot {
    let nvml = Nvml::init().expect("NVML init");
    let device = nvml.device_by_index(0).expect("GPU 0");
    // ... echte NVML Aufrufe
}

#[cfg(not(feature = "gpu"))]
fn real_gpu_snapshot() -> GpuSnapshot {
    // Kompiliert OHNE nvml-wrapper Dependency
    // Binary ist kleiner, kein NVML nötig
    GpuSnapshot::unavailable()
}
```

### Feature-Matrix

```
                 ┌─────────┬─────────┬─────────┐
                 │ default │   gpu   │enterprise│
├────────────────┼─────────┼─────────┼─────────┤
│ aegis-core     │    ✓    │    ✓    │    ✓    │
│ aegis-tsa      │    ✓    │    ✓    │    ✓    │
│ aegis-pscp     │    ✓    │    ✓    │    ✓    │
│  └ gpu.rs      │    ✗    │    ✓    │    ✓    │
│  └ gpu_stub.rs │    ✓    │    ✗    │    ✗    │
│  └ ebpf.rs     │    ✗    │    ✗    │    ✓    │
│  └ socket.rs   │    ✓    │    ✓    │    ✓    │
│  └ process.rs  │    ✓    │    ✓    │    ✓    │
│ aegis-server   │    ✓    │    ✓    │    ✓    │
│ nvml-wrapper   │    ✗    │    ✓    │    ✓    │
├────────────────┼─────────┼─────────┼─────────┤
│ Binary Size    │  ~10 MB │  ~13 MB │  ~15 MB │
│ Docker Image   │  ~30 MB │  ~180MB │ ~200 MB │
└────────────────┴─────────┴─────────┴─────────┘
```

---

## Error Handling

### Error-Typen Hierarchie

```rust
// ── aegis-core ──────────────────────────────────────
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("Hash chain integrity violation at sequence {0}")]
    ChainIntegrity(u64),

    #[error("ECDSA signature verification failed: {0}")]
    SignatureInvalid(String),

    #[error("Risk tier not classifiable: {0}")]
    RiskClassification(String),

    #[error("Gate evaluation error in layer {layer}: {reason}")]
    GateEvaluation { layer: u8, reason: String },

    #[error("Countdown expired without human response")]
    CountdownExpired,
}

// ── aegis-tsa ───────────────────────────────────────
#[derive(Debug, thiserror::Error)]
pub enum TsaError {
    #[error("TSA request encoding failed: {0}")]
    EncodingFailed(#[from] rasn::error::EncodeError),

    #[error("TSA response decoding failed: {0}")]
    DecodingFailed(#[from] rasn::error::DecodeError),

    #[error("TSA HTTP request failed: {0}")]
    HttpFailed(#[from] reqwest::Error),

    #[error("TSA response invalid: status={0}")]
    InvalidResponse(String),

    #[error("TSA request timed out after {0}s")]
    Timeout(u64),
}

// ── aegis-pscp ──────────────────────────────────────
#[derive(Debug, thiserror::Error)]
pub enum PscpError {
    #[error("GPU attestation failed: {0}")]
    GpuFailed(String),

    #[error("Socket monitoring failed: {0}")]
    SocketFailed(String),

    #[error("Process attestation failed: {0}")]
    ProcessFailed(String),

    #[error("PSCP proof production failed: {0}")]
    ProofFailed(String),

    #[error(transparent)]
    Core(#[from] CoreError),
}

// ── aegis-server ────────────────────────────────────
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("Invalid request: {0}")]
    BadRequest(String),

    #[error("PSCP error: {0}")]
    Pscp(#[from] PscpError),

    #[error("TSA error: {0}")]
    Tsa(#[from] TsaError),

    #[error("Internal error: {0}")]
    Internal(#[from] anyhow::Error),
}
```

### Error → HTTP Response Mapping

```rust
impl axum::response::IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match &self {
            ApiError::BadRequest(msg) => (
                StatusCode::BAD_REQUEST,
                msg.clone()
            ),
            ApiError::Pscp(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                e.to_string()
            ),
            ApiError::Tsa(TsaError::Timeout(_)) => (
                StatusCode::GATEWAY_TIMEOUT,
                self.to_string()
            ),
            ApiError::Tsa(e) => (
                StatusCode::BAD_GATEWAY,
                e.to_string()
            ),
            ApiError::Internal(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                e.to_string()
            ),
        };

        let body = serde_json::json!({
            "error": message,
            "status": status.as_u16()
        });

        (status, axum::Json(body)).into_response()
    }
}
```

### Error Flow Diagramm

```
Client Request
    │
    ↓
Axum Handler
    │
    ├── Parse Error ──→ ApiError::BadRequest(400)
    │
    ├── PSCP Engine
    │   ├── GPU Error ──→ PscpError::GpuFailed
    │   │                      ↓
    │   │                 ApiError::Pscp(500)
    │   │
    │   ├── Socket Error ──→ PscpError::SocketFailed
    │   │
    │   └── Process Error ──→ PscpError::ProcessFailed
    │
    ├── TSA Client
    │   ├── Timeout ──→ TsaError::Timeout
    │   │                    ↓
    │   │               ApiError::Tsa(504)
    │   │
    │   ├── HTTP Error ──→ TsaError::HttpFailed
    │   │                       ↓
    │   │                  ApiError::Tsa(502)
    │   │
    │   └── Parse Error ──→ TsaError::DecodingFailed
    │
    └── Unexpected ──→ anyhow::Error
                            ↓
                       ApiError::Internal(500)
```

### Graceful Degradation

Der Server bleibt immer verfügbar — Features degradieren graceful:

```rust
// GPU nicht verfügbar → Proof enthält "UNAVAILABLE", Server läuft weiter
// eBPF nicht verfügbar → Fallback auf /proc/net, Server läuft weiter
// TSA Timeout → FALLBACK Response mit lokalem Hash, Server läuft weiter
// Kein Netzwerk → TSA FALLBACK, alle anderen Features funktionieren
```

| Fehlerszenario | Verhalten | HTTP Status |
|---------------|-----------|-------------|
| GPU nicht verfügbar | Proof mit `UNAVAILABLE` GPU Attestation | 200 |
| eBPF nicht verfügbar | Fallback auf /proc/net | 200 |
| TSA Timeout | `FALLBACK` statt `ANCHORED` | 200 |
| TSA HTTP Error | `FALLBACK` mit lokaler Hash | 200 |
| Ungültiger Request | Error-Objekt | 400 |
| Interner Fehler | Error-Objekt | 500 |

---

X-Loop³ Labs · Kreuzlingen, Switzerland · Patent Pending
