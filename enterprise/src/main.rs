//! AegisFrame Control Tower — Enterprise Server
//! X-Loop³ Labs · Kreuzlingen, Switzerland
//! Patent Pending · USPTO
//!
//! Features:
//!   - AegisFrame Control Tower + Runtime Monitor UI
//!   - REAL RFC 3161 Timestamp Authority (freetsa.org)
//!   - PSCP Hardware Proof Engine (GPU + eBPF + Process)

mod pscp;

use axum::{
    extract::{Json, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    env,
    net::SocketAddr,
    path::PathBuf,
    process::Command,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tempfile::TempDir;
use tower_http::services::ServeDir;
use tracing::{info, warn};

use pscp::proof_engine::PSCPProofEngine;

// ============================================================
// APP STATE
// ============================================================

struct AppState {
    pscp_engine: PSCPProofEngine,
}

// ============================================================
// DATA TYPES
// ============================================================

#[derive(Deserialize)]
struct TsaRequest {
    hash: String,
    timestamp: Option<String>,
}

#[derive(Serialize)]
struct TsaResponse {
    status: String,
    tsa_provider: String,
    tsa_protocol: String,
    tsa_mode: String,
    anchored_hash: String,
    tsa_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt_hex: Option<String>,
    receipt_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    tsa_response_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tsa_timestamp: Option<String>,
    verified: bool,
    timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    tsa_error: Option<String>,
}

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    service: String,
    version: String,
    vendor: String,
    tsa_enabled: bool,
    pscp_enabled: bool,
    timestamp: String,
}

#[derive(Deserialize)]
struct ProveRequest {
    request_hash: Option<String>,
    decision: Option<String>,
}

#[derive(Deserialize)]
struct SnapshotQuery {
    phase: Option<String>,
}

struct TsaResult {
    success: bool,
    token_hash: Option<String>,
    receipt_hex: Option<String>,
    receipt_id: Option<String>,
    response_size: Option<u64>,
    tsa_timestamp: Option<String>,
    error: Option<String>,
}

// ============================================================
// HANDLERS
// ============================================================

async fn health() -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok".into(),
        service: "AegisFrame Control Tower".into(),
        version: "v0.7.0".into(),
        vendor: "X-Loop³ Labs".into(),
        tsa_enabled: true,
        pscp_enabled: true,
        timestamp: Utc::now().to_rfc3339(),
    })
}

async fn api_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let pscp_stat = state.pscp_engine.get_status();
    Json(serde_json::json!({
        "service": "AegisFrame Control Tower",
        "version": "v0.7.0",
        "vendor": "X-Loop³ Labs",
        "location": "Kreuzlingen, Switzerland",
        "patent_status": {
            "siren": "USPTO PPA 63/983,192",
            "pscp": "USPTO PPA 63/983,493",
            "milkmind": "USPTO PPA 63/986,414",
            "aegisframe": "USPTO PPA (filing)",
            "electric_translator": "USPTO PPA (filing)"
        },
        "capabilities": {
            "control_tower": true,
            "runtime_monitor": true,
            "tsa_rfc3161": true,
            "pscp_hardware_proof": true,
            "gpu_nvml": pscp_stat.capabilities.gpu_nvml,
            "ebpf": pscp_stat.capabilities.ebpf,
            "ecdsa_p256": true,
            "sha256_evidence_chain": true,
            "multi_trail": true,
            "countdown_oversight": true
        },
        "timestamp": Utc::now().to_rfc3339()
    }))
}

// ============================================================
// REAL RFC 3161 TSA ENDPOINT
// ============================================================

async fn tsa_anchor(
    Json(payload): Json<TsaRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let client_ts = payload
        .timestamp
        .unwrap_or_else(|| Utc::now().to_rfc3339());

    if payload.hash.len() != 64 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Hash must be 64 hex chars (SHA-256)"})),
        ));
    }

    let result = call_rfc3161_tsa(&payload.hash);

    if result.success {
        let receipt_id = result.receipt_id.unwrap_or_default();
        info!("TSA anchor OK: {}", receipt_id);
        Ok(Json(TsaResponse {
            status: "ANCHORED".into(),
            tsa_provider: "freetsa.org".into(),
            tsa_protocol: "RFC 3161".into(),
            tsa_mode: "LIVE".into(),
            anchored_hash: payload.hash,
            tsa_token: result.token_hash.unwrap_or_default(),
            receipt_hex: result.receipt_hex,
            receipt_id,
            tsa_response_size: result.response_size,
            tsa_timestamp: result.tsa_timestamp.or(Some(client_ts.clone())),
            verified: true,
            timestamp: client_ts,
            tsa_error: None,
        }))
    } else {
        let err_msg = result.error.unwrap_or_else(|| "Unknown".into());
        warn!("TSA failed: {}", err_msg);

        let mut hasher = Sha256::new();
        hasher.update(format!("{}{}AEGISFRAME_FALLBACK", payload.hash, client_ts));
        let fallback = hex::encode(hasher.finalize());

        let epoch = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(Json(TsaResponse {
            status: "FALLBACK".into(),
            tsa_provider: "freetsa.org".into(),
            tsa_protocol: "RFC 3161".into(),
            tsa_mode: "FALLBACK".into(),
            anchored_hash: payload.hash,
            tsa_token: fallback,
            receipt_hex: None,
            receipt_id: format!("FALLBACK_{}", epoch),
            tsa_response_size: None,
            tsa_timestamp: None,
            verified: false,
            timestamp: client_ts,
            tsa_error: Some(err_msg),
        }))
    }
}

fn call_rfc3161_tsa(hash_hex: &str) -> TsaResult {
    let tmpdir = match TempDir::new() {
        Ok(d) => d,
        Err(e) => {
            return TsaResult {
                success: false,
                token_hash: None,
                receipt_hex: None,
                receipt_id: None,
                response_size: None,
                tsa_timestamp: None,
                error: Some(format!("Failed to create temp dir: {}", e)),
            }
        }
    };

    let hash_file = tmpdir.path().join("data.txt");
    let tsq_file = tmpdir.path().join("request.tsq");
    let tsr_file = tmpdir.path().join("response.tsr");

    if let Err(e) = std::fs::write(&hash_file, hash_hex) {
        return TsaResult {
            success: false,
            token_hash: None,
            receipt_hex: None,
            receipt_id: None,
            response_size: None,
            tsa_timestamp: None,
            error: Some(format!("Failed to write hash file: {}", e)),
        };
    }

    // Create timestamp request
    let proc_result = Command::new("openssl")
        .args([
            "ts",
            "-query",
            "-data",
            hash_file.to_str().unwrap_or(""),
            "-no_nonce",
            "-sha256",
            "-out",
            tsq_file.to_str().unwrap_or(""),
        ])
        .output();

    match proc_result {
        Ok(output) if !output.status.success() => {
            return TsaResult {
                success: false,
                token_hash: None,
                receipt_hex: None,
                receipt_id: None,
                response_size: None,
                tsa_timestamp: None,
                error: Some(format!(
                    "openssl ts failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                )),
            };
        }
        Err(e) => {
            return TsaResult {
                success: false,
                token_hash: None,
                receipt_hex: None,
                receipt_id: None,
                response_size: None,
                tsa_timestamp: None,
                error: Some(format!("openssl command failed: {}", e)),
            };
        }
        _ => {}
    }

    // Send to freetsa.org
    let proc_result = Command::new("curl")
        .args([
            "-s",
            "-S",
            "-H",
            "Content-Type: application/timestamp-query",
            "--data-binary",
            &format!("@{}", tsq_file.to_str().unwrap_or("")),
            "--max-time",
            "15",
            "-o",
            tsr_file.to_str().unwrap_or(""),
            "https://freetsa.org/tsr",
        ])
        .output();

    match proc_result {
        Ok(output) if !output.status.success() => {
            return TsaResult {
                success: false,
                token_hash: None,
                receipt_hex: None,
                receipt_id: None,
                response_size: None,
                tsa_timestamp: None,
                error: Some(format!(
                    "curl failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                )),
            };
        }
        Err(e) => {
            return TsaResult {
                success: false,
                token_hash: None,
                receipt_hex: None,
                receipt_id: None,
                response_size: None,
                tsa_timestamp: None,
                error: Some(format!("curl command failed: {}", e)),
            };
        }
        _ => {}
    }

    // Check response
    let metadata = match std::fs::metadata(&tsr_file) {
        Ok(m) if m.len() > 0 => m,
        _ => {
            return TsaResult {
                success: false,
                token_hash: None,
                receipt_hex: None,
                receipt_id: None,
                response_size: None,
                tsa_timestamp: None,
                error: Some("Empty TSA response".into()),
            };
        }
    };

    let response_size = metadata.len();
    let receipt_bytes = match std::fs::read(&tsr_file) {
        Ok(b) => b,
        Err(e) => {
            return TsaResult {
                success: false,
                token_hash: None,
                receipt_hex: None,
                receipt_id: None,
                response_size: None,
                tsa_timestamp: None,
                error: Some(format!("Failed to read TSA response: {}", e)),
            };
        }
    };

    let receipt_hex = hex::encode(&receipt_bytes);
    let mut hasher = Sha256::new();
    hasher.update(&receipt_bytes);
    let token_hash = hex::encode(hasher.finalize());

    let epoch = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let receipt_id = format!("TSA_{}_{}", epoch, &token_hash[..8]);

    // Try to parse the response for timestamp
    let mut tsa_timestamp = None;
    if let Ok(output) = Command::new("openssl")
        .args(["ts", "-reply", "-in", tsr_file.to_str().unwrap_or(""), "-text"])
        .output()
    {
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                if line.contains("Time stamp:") {
                    let parts: Vec<&str> = line.splitn(2, "Time stamp:").collect();
                    if parts.len() == 2 {
                        tsa_timestamp = Some(parts[1].trim().to_string());
                    }
                    break;
                }
            }
        }
    }

    TsaResult {
        success: true,
        token_hash: Some(token_hash),
        receipt_hex: Some(receipt_hex),
        receipt_id: Some(receipt_id),
        response_size: Some(response_size),
        tsa_timestamp,
        error: None,
    }
}

// ============================================================
// PSCP HARDWARE PROOF ENDPOINTS
// ============================================================

/// PSCP engine capabilities and status.
async fn pscp_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(state.pscp_engine.get_status())
}

/// Capture a hardware state snapshot (before or after decision).
async fn pscp_snapshot(
    State(state): State<Arc<AppState>>,
    Query(params): Query<SnapshotQuery>,
) -> impl IntoResponse {
    let phase = params.phase.unwrap_or_else(|| "before".into());

    let snap = if phase == "before" {
        state.pscp_engine.capture_before()
    } else {
        state.pscp_engine.capture_after()
    };

    Json(serde_json::json!({
        "phase": phase,
        "snapshot": snap,
        "timestamp": Utc::now().to_rfc3339()
    }))
}

/// Execute a complete PSCP proof cycle.
async fn pscp_prove(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ProveRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let request_hash = payload.request_hash.unwrap_or_else(|| {
        let mut hasher = Sha256::new();
        hasher.update(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
                .to_string(),
        );
        hex::encode(hasher.finalize())
    });
    let decision = payload.decision.unwrap_or_else(|| "BLOCK".into());

    // Full proof cycle
    let before = state.pscp_engine.capture_before();

    // Simulate the decision delay
    tokio::time::sleep(Duration::from_millis(100)).await;

    let after = state.pscp_engine.capture_after();
    let proof = state
        .pscp_engine
        .produce_proof(&before, &after, &decision, &request_hash);

    info!("PSCP proof generated: {} -> {}", proof.proof_id, proof.verdict);

    Ok(Json(proof))
}

/// Full PSCP proof with TSA anchoring.
async fn pscp_prove_full(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ProveRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let request_hash = payload.request_hash.unwrap_or_else(|| {
        let mut hasher = Sha256::new();
        hasher.update(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
                .to_string(),
        );
        hex::encode(hasher.finalize())
    });
    let decision = payload.decision.unwrap_or_else(|| "BLOCK".into());

    // Hardware proof
    let before = state.pscp_engine.capture_before();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let after = state.pscp_engine.capture_after();
    let mut proof = state
        .pscp_engine
        .produce_proof(&before, &after, &decision, &request_hash);

    // Anchor proof hash to TSA
    let tsa_result = call_rfc3161_tsa(&proof.proof_hash);

    proof.tsa_anchor = Some(serde_json::json!({
        "anchored": tsa_result.success,
        "tsa_provider": "freetsa.org",
        "tsa_protocol": "RFC 3161",
        "proof_hash_anchored": proof.proof_hash,
        "tsa_receipt_id": tsa_result.receipt_id,
        "tsa_timestamp": tsa_result.tsa_timestamp
    }));

    info!(
        "PSCP full proof: {} -> {} + TSA {}",
        proof.proof_id,
        proof.verdict,
        if tsa_result.success { "OK" } else { "FALLBACK" }
    );

    Ok(Json(proof))
}

/// Return the append-only proof trail.
async fn pscp_trail(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let trail = state.pscp_engine.get_proof_trail();
    let count = trail.len();
    Json(serde_json::json!({
        "trail": trail,
        "count": count,
        "timestamp": Utc::now().to_rfc3339()
    }))
}

// ============================================================
// BOOT
// ============================================================

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let port: u16 = env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(10000);

    let state = Arc::new(AppState {
        pscp_engine: PSCPProofEngine::new(),
    });

    let static_dir = PathBuf::from("static");

    let app = Router::new()
        .route("/health", get(health))
        .route("/api/v1/status", get(api_status))
        .route("/api/v1/tsa/anchor", post(tsa_anchor))
        .route("/api/v1/pscp/status", get(pscp_status))
        .route("/api/v1/pscp/snapshot", post(pscp_snapshot))
        .route("/api/v1/pscp/prove", post(pscp_prove))
        .route("/api/v1/pscp/prove/full", post(pscp_prove_full))
        .route("/api/v1/pscp/trail", get(pscp_trail))
        .with_state(state)
        .fallback_service(ServeDir::new(static_dir));

    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    info!("═══════════════════════════════════════════════");
    info!("  AegisFrame Control Tower · Enterprise Server");
    info!("  X-Loop³ Labs · Kreuzlingen, Switzerland");
    info!("  Port: {}", port);
    info!("  TSA: freetsa.org (RFC 3161 LIVE)");
    info!("  PSCP: GPU + eBPF + Process Attestation");
    info!("  Patents: SIREN · PSCP · MilkMind · AegisFrame");
    info!("═══════════════════════════════════════════════");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
