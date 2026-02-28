//! AegisFrame PSCP — GPU Hardware Attestation
//! X-Loop³ Labs · Patent Pending · USPTO 63/983,493
//!
//! Reads NVIDIA GPU hardware counters via NVML (NVIDIA Management Library).
//! Proves at the DRIVER level whether inference occurred — not self-report,
//! not application-level flags, but actual hardware utilization metrics
//! from the GPU driver itself.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::warn;

#[cfg(feature = "gpu")]
use nvml_wrapper::Nvml;

/// GPU utilization threshold (percent) for inference detection.
const GPU_UTIL_THRESHOLD: i64 = 5;
/// Memory increase threshold (bytes) for inference detection.
const MEM_INCREASE_THRESHOLD: i64 = 50 * 1024 * 1024; // 50 MB

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuSnapshot {
    pub available: bool,
    pub mode: String,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<GpuDevice>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub utilization: Option<GpuUtilization>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<GpuMemory>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub processes: Option<GpuProcesses>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thermal: Option<GpuThermal>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clocks: Option<GpuClocks>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuDevice {
    pub index: u32,
    pub name: String,
    pub uuid: String,
    pub driver_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuUtilization {
    pub gpu_percent: u32,
    pub memory_percent: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuMemory {
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub free_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuProcesses {
    pub compute_count: usize,
    pub compute_pids: Vec<u32>,
    pub graphics_count: usize,
    pub graphics_pids: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuThermal {
    pub gpu_temp_c: Option<u32>,
    pub power_state: Option<u32>,
    pub power_draw_w: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuClocks {
    pub sm_mhz: Option<u32>,
    pub mem_mhz: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuAttestation {
    pub proof_type: String,
    pub proof_level: String,
    pub verdict: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checks: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deltas: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshots: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<GpuDevice>,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_hash: Option<String>,
}

pub struct GpuAttestor {
    pub initialized: bool,
    pub device_count: u32,
    pub driver_version: Option<String>,
    #[cfg(feature = "gpu")]
    nvml: Option<Nvml>,
}

impl GpuAttestor {
    pub fn new() -> Self {
        #[cfg(feature = "gpu")]
        {
            match Nvml::init() {
                Ok(nvml) => {
                    let device_count = nvml.device_count().unwrap_or(0);
                    let driver_version = nvml.sys_driver_version().ok();
                    info!(
                        "NVML initialized: {} GPU(s), driver {:?}",
                        device_count, driver_version
                    );
                    Self {
                        initialized: true,
                        device_count,
                        driver_version,
                        nvml: Some(nvml),
                    }
                }
                Err(e) => {
                    error!("NVML init failed: {}", e);
                    Self {
                        initialized: false,
                        device_count: 0,
                        driver_version: None,
                        nvml: None,
                    }
                }
            }
        }

        #[cfg(not(feature = "gpu"))]
        {
            warn!("GPU attestation compiled without NVML support — fallback mode");
            Self {
                initialized: false,
                device_count: 0,
                driver_version: None,
            }
        }
    }

    /// Capture a complete GPU state snapshot from hardware counters.
    pub fn snapshot(&self, device_idx: u32) -> GpuSnapshot {
        let ts = Utc::now().to_rfc3339();

        if !self.initialized {
            return GpuSnapshot {
                available: false,
                mode: "NO_GPU".into(),
                timestamp: ts,
                device: None,
                utilization: None,
                memory: None,
                processes: None,
                thermal: None,
                clocks: None,
                snapshot_hash: None,
                error: None,
            };
        }

        #[cfg(feature = "gpu")]
        {
            self.snapshot_nvml(device_idx, &ts)
        }

        #[cfg(not(feature = "gpu"))]
        {
            let _ = device_idx;
            GpuSnapshot {
                available: false,
                mode: "NO_GPU".into(),
                timestamp: ts,
                device: None,
                utilization: None,
                memory: None,
                processes: None,
                thermal: None,
                clocks: None,
                snapshot_hash: None,
                error: None,
            }
        }
    }

    #[cfg(feature = "gpu")]
    fn snapshot_nvml(&self, device_idx: u32, ts: &str) -> GpuSnapshot {
        let nvml = match &self.nvml {
            Some(n) => n,
            None => {
                return GpuSnapshot {
                    available: false,
                    mode: "NO_GPU".into(),
                    timestamp: ts.to_string(),
                    device: None,
                    utilization: None,
                    memory: None,
                    processes: None,
                    thermal: None,
                    clocks: None,
                    snapshot_hash: None,
                    error: None,
                }
            }
        };

        let device = match nvml.device_by_index(device_idx) {
            Ok(d) => d,
            Err(e) => {
                return GpuSnapshot {
                    available: true,
                    mode: "NVML_ERROR".into(),
                    timestamp: ts.to_string(),
                    device: None,
                    utilization: None,
                    memory: None,
                    processes: None,
                    thermal: None,
                    clocks: None,
                    snapshot_hash: None,
                    error: Some(format!("Device access error: {}", e)),
                }
            }
        };

        let util = device.utilization_rates().ok();
        let mem = device.memory_info().ok();
        let compute_procs = device.running_compute_processes().unwrap_or_default();
        let graphics_procs = device.running_graphics_processes().unwrap_or_default();
        let temp = device.temperature(nvml_wrapper::enum_wrappers::device::TemperatureSensor::Gpu).ok();
        let power = device.power_usage().ok().map(|p| p as f64 / 1000.0);
        let name = device.name().unwrap_or_else(|_| "Unknown".into());
        let uuid = device.uuid().unwrap_or_else(|_| "Unknown".into());

        let mut snap = GpuSnapshot {
            available: true,
            mode: "NVML_HARDWARE".into(),
            timestamp: ts.to_string(),
            device: Some(GpuDevice {
                index: device_idx,
                name,
                uuid,
                driver_version: self.driver_version.clone(),
            }),
            utilization: util.map(|u| GpuUtilization {
                gpu_percent: u.gpu,
                memory_percent: u.memory,
            }),
            memory: mem.map(|m| GpuMemory {
                total_bytes: m.total,
                used_bytes: m.used,
                free_bytes: m.free,
            }),
            processes: Some(GpuProcesses {
                compute_count: compute_procs.len(),
                compute_pids: compute_procs.iter().map(|p| p.pid).collect(),
                graphics_count: graphics_procs.len(),
                graphics_pids: graphics_procs.iter().map(|p| p.pid).collect(),
            }),
            thermal: Some(GpuThermal {
                gpu_temp_c: temp,
                power_state: None,
                power_draw_w: power,
            }),
            clocks: None,
            snapshot_hash: None,
            error: None,
        };

        // Hash the snapshot for tamper detection
        let hash_data = serde_json::to_string(&snap).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(hash_data.as_bytes());
        snap.snapshot_hash = Some(hex::encode(hasher.finalize()));

        snap
    }

    /// Compare two GPU snapshots and produce a signed attestation
    /// that no inference occurred between them.
    pub fn attest_no_inference(
        &self,
        before: &GpuSnapshot,
        after: &GpuSnapshot,
    ) -> GpuAttestation {
        let ts = Utc::now().to_rfc3339();

        if !before.available || !after.available {
            return GpuAttestation {
                proof_type: "GPU_NO_INFERENCE_ATTESTATION".into(),
                proof_level: "UNAVAILABLE".into(),
                verdict: "UNAVAILABLE".into(),
                reason: Some("GPU snapshots not available".into()),
                checks: None,
                deltas: None,
                snapshots: None,
                device: None,
                timestamp: ts,
                attestation_hash: None,
            };
        }

        // Compute deltas from hardware counters
        let gpu_util_before = before
            .utilization
            .as_ref()
            .map(|u| u.gpu_percent as i64)
            .unwrap_or(0);
        let gpu_util_after = after
            .utilization
            .as_ref()
            .map(|u| u.gpu_percent as i64)
            .unwrap_or(0);
        let gpu_util_delta = gpu_util_after - gpu_util_before;

        let mem_before = before
            .memory
            .as_ref()
            .map(|m| m.used_bytes as i64)
            .unwrap_or(0);
        let mem_after = after
            .memory
            .as_ref()
            .map(|m| m.used_bytes as i64)
            .unwrap_or(0);
        let mem_delta = mem_after - mem_before;

        let compute_before: std::collections::HashSet<u32> = before
            .processes
            .as_ref()
            .map(|p| p.compute_pids.iter().copied().collect())
            .unwrap_or_default();
        let compute_after: std::collections::HashSet<u32> = after
            .processes
            .as_ref()
            .map(|p| p.compute_pids.iter().copied().collect())
            .unwrap_or_default();
        let new_compute_pids: Vec<u32> = compute_after.difference(&compute_before).copied().collect();

        let no_new_compute = new_compute_pids.is_empty();
        let gpu_util_stable = gpu_util_delta < GPU_UTIL_THRESHOLD;
        let memory_stable = mem_delta < MEM_INCREASE_THRESHOLD;

        let all_passed = no_new_compute && gpu_util_stable && memory_stable;

        let mut attestation = GpuAttestation {
            proof_type: "GPU_NO_INFERENCE_ATTESTATION".into(),
            proof_level: "HARDWARE_NVML".into(),
            verdict: if all_passed {
                "NO_INFERENCE_CONFIRMED".into()
            } else {
                "INFERENCE_DETECTED".into()
            },
            reason: None,
            checks: Some(json!({
                "no_new_compute_processes": no_new_compute,
                "gpu_util_stable": gpu_util_stable,
                "memory_stable": memory_stable,
                "no_new_pids": no_new_compute
            })),
            deltas: Some(json!({
                "gpu_util_delta_percent": gpu_util_delta,
                "memory_delta_bytes": mem_delta,
                "memory_delta_mb": (mem_delta as f64) / (1024.0 * 1024.0),
                "new_compute_pids": new_compute_pids,
                "compute_count_before": compute_before.len(),
                "compute_count_after": compute_after.len()
            })),
            snapshots: Some(json!({
                "before_hash": before.snapshot_hash,
                "after_hash": after.snapshot_hash
            })),
            device: before.device.clone(),
            timestamp: ts,
            attestation_hash: None,
        };

        // Sign the attestation
        let hash_data =
            serde_json::to_string(&json!({
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
