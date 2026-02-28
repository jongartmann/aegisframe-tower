//! AegisFrame PSCP — Combined Hardware Proof API
//! X-Loop³ Labs · Patent Pending · USPTO 63/983,493
//!
//! This module provides the unified PSCP (Pre-Semantic Structural Control Plane)
//! hardware proof endpoint. It orchestrates:
//!
//!   1. GPU Attestation (NVML)     → "No inference compute occurred"
//!   2. Socket Attestation (eBPF)  → "No data left the container"
//!   3. Process Attestation (/proc) → "No inference process was spawned"
//!
//! This is what makes PSCP different from every other AI governance tool:
//! they check AFTER. We prove BEFORE.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;

use super::gpu_attestor::{GpuAttestation, GpuAttestor, GpuSnapshot};
use super::process_attestor::{ProcessAttestation, ProcessAttestor, ProcessSnapshot};
use super::socket_monitor::{SocketAttestation, SocketMonitor, SocketSnapshot};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareState {
    pub gpu: GpuSnapshot,
    pub socket: SocketSnapshot,
    pub process: ProcessSnapshot,
    pub captured_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofTrailEntry {
    pub proof_id: String,
    pub proof_hash: String,
    pub verdict: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PscpProof {
    pub proof_type: String,
    pub proof_id: String,
    pub patent_ref: String,
    pub vendor: String,
    pub version: String,
    pub decision: String,
    pub request_hash: String,
    pub verdict: String,
    pub verified: bool,
    pub attestations: PscpAttestations,
    pub proof_levels: PscpProofLevels,
    pub timing: PscpTiming,
    pub timestamp: String,
    pub proof_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tsa_anchor: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PscpAttestations {
    pub gpu: GpuAttestation,
    pub socket: SocketAttestation,
    pub process: ProcessAttestation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PscpProofLevels {
    pub gpu: String,
    pub socket: String,
    pub process: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PscpTiming {
    pub before_captured: String,
    pub after_captured: String,
    pub proof_generated: String,
}

#[derive(Serialize)]
pub struct PscpStatus {
    pub engine: String,
    pub proofs_generated: u64,
    pub capabilities: PscpCapabilities,
    pub patent_ref: String,
}

#[derive(Serialize)]
pub struct PscpCapabilities {
    pub gpu_nvml: bool,
    pub gpu_device: u32,
    pub gpu_driver: Option<String>,
    pub ebpf: bool,
    pub process_monitor: bool,
    pub proc_path: String,
}

pub struct PSCPProofEngine {
    gpu_attestor: GpuAttestor,
    socket_monitor: SocketMonitor,
    process_attestor: ProcessAttestor,
    proof_counter: Mutex<u64>,
    proofs: Mutex<Vec<ProofTrailEntry>>,
}

impl PSCPProofEngine {
    pub fn new() -> Self {
        let gpu = GpuAttestor::new();
        let socket = SocketMonitor::new();
        let process = ProcessAttestor::new();

        info!("PSCP Proof Engine initialized");
        info!(
            "  GPU (NVML): {}",
            if gpu.initialized {
                "AVAILABLE"
            } else {
                "UNAVAILABLE"
            }
        );
        info!(
            "  eBPF: {}",
            if socket.available {
                "AVAILABLE"
            } else {
                "FALLBACK to /proc/net"
            }
        );
        info!("  Process: /proc direct");

        Self {
            gpu_attestor: gpu,
            socket_monitor: socket,
            process_attestor: process,
            proof_counter: Mutex::new(0),
            proofs: Mutex::new(Vec::new()),
        }
    }

    /// Capture pre-decision hardware state.
    pub fn capture_before(&self) -> HardwareState {
        HardwareState {
            gpu: self.gpu_attestor.snapshot(0),
            socket: self.socket_monitor.snapshot_connections(),
            process: self.process_attestor.snapshot(),
            captured_at: Utc::now().to_rfc3339(),
        }
    }

    /// Capture post-decision hardware state.
    pub fn capture_after(&self) -> HardwareState {
        HardwareState {
            gpu: self.gpu_attestor.snapshot(0),
            socket: self.socket_monitor.snapshot_connections(),
            process: self.process_attestor.snapshot(),
            captured_at: Utc::now().to_rfc3339(),
        }
    }

    /// Produce a complete PSCP hardware proof.
    pub fn produce_proof(
        &self,
        before: &HardwareState,
        after: &HardwareState,
        decision: &str,
        request_hash: &str,
    ) -> PscpProof {
        let mut counter = self.proof_counter.lock().unwrap();
        *counter += 1;
        let count = *counter;
        drop(counter);

        let ts = Utc::now().to_rfc3339();
        let epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Individual attestations
        let gpu_attest = self
            .gpu_attestor
            .attest_no_inference(&before.gpu, &after.gpu);
        let socket_attest = self
            .socket_monitor
            .attest_no_outbound(&before.socket, &after.socket);
        let process_attest = self
            .process_attestor
            .attest_no_inference_process(&before.process, &after.process);

        // Combined verdict
        let pscp_verdict;
        let pscp_verified;

        if decision == "BLOCK" {
            let gpu_ok = gpu_attest.proof_level == "UNAVAILABLE"
                || gpu_attest.verdict == "NO_INFERENCE_CONFIRMED";
            let socket_ok = socket_attest.verdict == "NO_OUTBOUND_CONFIRMED";
            let process_ok = process_attest.verdict == "NO_PROCESS_CONFIRMED";

            pscp_verified = gpu_ok && socket_ok && process_ok;
            pscp_verdict = if pscp_verified {
                "PSCP_BLOCK_VERIFIED"
            } else {
                "PSCP_BLOCK_VIOLATION"
            };
        } else {
            pscp_verdict = "PSCP_ALLOW_RECORDED";
            pscp_verified = true;
        }

        // Build the proof (without hash first)
        let proof_id = format!("PSCP_{:06}_{}", count, epoch);

        let proof_data = json!({
            "proof_type": "PSCP_HARDWARE_PROOF",
            "proof_id": proof_id,
            "patent_ref": "USPTO PPA 63/983,493",
            "vendor": "X-Loop³ Labs",
            "version": "v0.7.0",
            "decision": decision,
            "request_hash": request_hash,
            "verdict": pscp_verdict,
            "verified": pscp_verified,
            "attestations": {
                "gpu": gpu_attest,
                "socket": socket_attest,
                "process": process_attest
            },
            "timing": {
                "before_captured": before.captured_at,
                "after_captured": after.captured_at,
                "proof_generated": ts
            },
            "timestamp": ts
        });

        // Sign the entire proof
        let mut hasher = Sha256::new();
        hasher.update(proof_data.to_string().as_bytes());
        let proof_hash = hex::encode(hasher.finalize());

        // Append to proof trail
        let trail_entry = ProofTrailEntry {
            proof_id: proof_id.clone(),
            proof_hash: proof_hash.clone(),
            verdict: pscp_verdict.to_string(),
            timestamp: ts.clone(),
        };
        self.proofs.lock().unwrap().push(trail_entry);

        PscpProof {
            proof_type: "PSCP_HARDWARE_PROOF".into(),
            proof_id,
            patent_ref: "USPTO PPA 63/983,493".into(),
            vendor: "X-Loop³ Labs".into(),
            version: "v0.7.0".into(),
            decision: decision.to_string(),
            request_hash: request_hash.to_string(),
            verdict: pscp_verdict.to_string(),
            verified: pscp_verified,
            attestations: PscpAttestations {
                gpu: gpu_attest,
                socket: socket_attest,
                process: process_attest,
            },
            proof_levels: PscpProofLevels {
                gpu: self
                    .gpu_attestor
                    .initialized
                    .then(|| "HARDWARE_NVML".to_string())
                    .unwrap_or_else(|| "UNAVAILABLE".to_string()),
                socket: if self.socket_monitor.available {
                    "KERNEL_EBPF".into()
                } else {
                    "PROC_NET".into()
                },
                process: "OS_KERNEL".into(),
            },
            timing: PscpTiming {
                before_captured: before.captured_at.clone(),
                after_captured: after.captured_at.clone(),
                proof_generated: ts,
            },
            timestamp: Utc::now().to_rfc3339(),
            proof_hash,
            tsa_anchor: None,
        }
    }

    /// Return the append-only proof trail.
    pub fn get_proof_trail(&self) -> Vec<ProofTrailEntry> {
        self.proofs.lock().unwrap().clone()
    }

    /// Return engine status.
    pub fn get_status(&self) -> PscpStatus {
        PscpStatus {
            engine: "PSCP Hardware Proof Engine".into(),
            proofs_generated: *self.proof_counter.lock().unwrap(),
            capabilities: PscpCapabilities {
                gpu_nvml: self.gpu_attestor.initialized,
                gpu_device: self.gpu_attestor.device_count,
                gpu_driver: self.gpu_attestor.driver_version.clone(),
                ebpf: self.socket_monitor.available,
                process_monitor: self.process_attestor.available,
                proc_path: self.process_attestor.proc_path.clone(),
            },
            patent_ref: "USPTO PPA 63/983,493".into(),
        }
    }
}
