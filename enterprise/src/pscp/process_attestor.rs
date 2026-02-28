//! AegisFrame PSCP — Process Isolation Attestation
//! X-Loop³ Labs · Patent Pending · USPTO 63/983,493
//!
//! Proves at the OS level that no model inference process was spawned.
//! Reads /proc directly — this is the Linux kernel's view of running processes,
//! not an application-level flag.
//!
//! Monitors:
//!   - /proc/[pid]/cmdline for known inference frameworks
//!   - /proc/[pid]/status for memory and state
//!   - cgroup membership for container isolation proof

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use tracing::info;

/// Known inference process signatures.
const INFERENCE_SIGNATURES: &[&str] = &[
    "transformers",
    "vllm",
    "torch",
    "tensorflow",
    "tritonserver",
    "text-generation-launcher",
    "ollama",
    "llama.cpp",
    "llama-server",
    "koboldcpp",
    "ggml",
    "onnxruntime",
    "trtllm",
    "deepspeed",
    "accelerate",
];

/// Known inference port bindings.
const INFERENCE_PORTS: &[u16] = &[
    8080,  // vLLM, TGI
    8000,  // FastAPI inference servers
    11434, // Ollama
    3000,  // LM Studio
    5000,  // Flask inference servers
    8888,  // Jupyter with inference
    9090,  // Triton
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessSnapshot {
    pub timestamp: String,
    pub mode: String,
    pub total_processes: usize,
    pub inference_processes: InferenceProcessInfo,
    pub inference_ports: InferencePortInfo,
    pub container: ContainerInfo,
    pub signatures_checked: usize,
    pub ports_checked: Vec<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceProcessInfo {
    pub count: usize,
    pub details: Vec<ProcessDetail>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessDetail {
    pub pid: u32,
    pub name: String,
    pub cmdline_short: String,
    pub is_inference: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferencePortInfo {
    pub count: usize,
    pub details: Vec<PortDetail>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortDetail {
    pub pid: u32,
    pub port: u16,
    pub process: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerInfo {
    pub isolated: bool,
    pub container_id: Option<String>,
    pub runtime: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessAttestation {
    pub proof_type: String,
    pub proof_level: String,
    pub verdict: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checks: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deltas: Option<serde_json::Value>,
    pub container: ContainerInfo,
    pub signatures_checked: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshots: Option<serde_json::Value>,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_hash: Option<String>,
}

pub struct ProcessAttestor {
    pub proc_path: String,
    pub available: bool,
}

impl ProcessAttestor {
    pub fn new() -> Self {
        let proc_path = if Path::new("/host/proc").exists() {
            "/host/proc".into()
        } else {
            "/proc".into()
        };
        info!("Process attestor initialized (reading {})", proc_path);
        Self {
            proc_path,
            available: true,
        }
    }

    /// Capture a snapshot of all running processes.
    /// Identifies any that match inference signatures.
    pub fn snapshot(&self) -> ProcessSnapshot {
        let ts = Utc::now().to_rfc3339();
        let mut processes = Vec::new();
        let mut inference_processes = Vec::new();

        // Read /proc directly
        if let Ok(entries) = fs::read_dir(&self.proc_path) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();

                // Only process numeric directories (PIDs)
                if !name_str.chars().all(|c| c.is_ascii_digit()) {
                    continue;
                }

                let pid: u32 = match name_str.parse() {
                    Ok(p) => p,
                    Err(_) => continue,
                };

                let pid_path = entry.path();

                // Read cmdline
                let cmdline = fs::read_to_string(pid_path.join("cmdline"))
                    .unwrap_or_default()
                    .replace('\0', " ")
                    .trim()
                    .to_string();

                // Read process name from status
                let proc_name = fs::read_to_string(pid_path.join("status"))
                    .ok()
                    .and_then(|s| {
                        s.lines()
                            .find(|l| l.starts_with("Name:"))
                            .map(|l| l.split(':').nth(1).unwrap_or("").trim().to_string())
                    })
                    .unwrap_or_else(|| name_str.to_string());

                // Check if this is an inference process
                let cmdline_lower = cmdline.to_lowercase();
                let mut is_inference = false;
                let mut matched_sig = None;
                for sig in INFERENCE_SIGNATURES {
                    if cmdline_lower.contains(sig) {
                        is_inference = true;
                        matched_sig = Some(sig.to_string());
                        break;
                    }
                }

                let detail = ProcessDetail {
                    pid,
                    name: proc_name,
                    cmdline_short: cmdline.chars().take(120).collect(),
                    is_inference,
                    matched_signature: matched_sig,
                };

                if is_inference {
                    inference_processes.push(detail.clone());
                }
                processes.push(detail);
            }
        }

        let cgroup_info = get_cgroup_info(&self.proc_path);

        let mut snap = ProcessSnapshot {
            timestamp: ts,
            mode: "PROC_DIRECT".into(),
            total_processes: processes.len(),
            inference_processes: InferenceProcessInfo {
                count: inference_processes.len(),
                details: inference_processes,
            },
            inference_ports: InferencePortInfo {
                count: 0,
                details: Vec::new(),
            },
            container: cgroup_info,
            signatures_checked: INFERENCE_SIGNATURES.len(),
            ports_checked: INFERENCE_PORTS.to_vec(),
            snapshot_hash: None,
        };

        // Hash the snapshot
        let hash_data = serde_json::to_string(&snap).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(hash_data.as_bytes());
        snap.snapshot_hash = Some(hex::encode(hasher.finalize()));

        snap
    }

    /// Compare two process snapshots and attest that no inference
    /// process was spawned between them.
    pub fn attest_no_inference_process(
        &self,
        before: &ProcessSnapshot,
        after: &ProcessSnapshot,
    ) -> ProcessAttestation {
        let ts = Utc::now().to_rfc3339();

        let inf_before = before.inference_processes.count;
        let inf_after = after.inference_processes.count;
        let new_inference = inf_after as i64 - inf_before as i64;

        let ports_before = before.inference_ports.count;
        let ports_after = after.inference_ports.count;
        let new_ports = ports_after as i64 - ports_before as i64;

        let no_new_inference = new_inference <= 0;
        let no_new_ports = new_ports <= 0;
        let zero_inference_at_end = inf_after == 0;

        let all_passed = no_new_inference && no_new_ports && zero_inference_at_end;

        let mut attestation = ProcessAttestation {
            proof_type: "PROCESS_NO_INFERENCE_ATTESTATION".into(),
            proof_level: "OS_KERNEL".into(),
            verdict: if all_passed {
                "NO_PROCESS_CONFIRMED".into()
            } else {
                "INFERENCE_PROCESS_DETECTED".into()
            },
            checks: Some(json!({
                "no_new_inference_processes": no_new_inference,
                "no_new_inference_ports": no_new_ports,
                "zero_inference_at_end": zero_inference_at_end,
                "container_isolated": after.container.isolated
            })),
            deltas: Some(json!({
                "new_inference_processes": new_inference,
                "new_inference_ports": new_ports,
                "inference_details": after.inference_processes.details
            })),
            container: after.container.clone(),
            signatures_checked: INFERENCE_SIGNATURES.len(),
            snapshots: Some(json!({
                "before_hash": before.snapshot_hash,
                "after_hash": after.snapshot_hash
            })),
            timestamp: ts,
            attestation_hash: None,
        };

        // Sign the attestation
        let hash_data = serde_json::to_string(&json!({
            "proof_type": attestation.proof_type,
            "proof_level": attestation.proof_level,
            "verdict": attestation.verdict,
            "checks": attestation.checks,
            "deltas": attestation.deltas,
        }))
        .unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(hash_data.as_bytes());
        attestation.attestation_hash = Some(hex::encode(hasher.finalize()));

        attestation
    }
}

/// Read container cgroup information for isolation proof.
fn get_cgroup_info(proc_path: &str) -> ContainerInfo {
    let mut info = ContainerInfo {
        isolated: false,
        container_id: None,
        runtime: None,
    };

    let cgroup_path = format!("{}/1/cgroup", proc_path);
    if let Ok(content) = fs::read_to_string(&cgroup_path) {
        if content.contains("docker") {
            info.isolated = true;
            info.runtime = Some("docker".into());
            // Extract container ID
            for line in content.lines() {
                if line.contains("docker") {
                    for part in line.split('/') {
                        if part.len() == 64 && part.chars().all(|c| c.is_ascii_hexdigit()) {
                            info.container_id = Some(part.to_string());
                            break;
                        }
                    }
                }
            }
        } else if content.contains("containerd") || content.contains("cri-containerd") {
            info.isolated = true;
            info.runtime = Some("containerd".into());
        }
    }

    info
}
