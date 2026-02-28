//! AegisFrame Control Tower — Render Server
//! X-Loop³ Labs · Kreuzlingen, Switzerland
//! Patent Pending · USPTO
//!
//! Serves the AegisFrame Control Tower + Runtime Monitor demo
//! with a REAL RFC 3161 Timestamp Authority endpoint via freetsa.org

use axum::{
    extract::Json,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{env, net::SocketAddr, path::PathBuf, process::Command, time::SystemTime};
use tempfile::TempDir;
use tower_http::services::ServeDir;
use tracing::{info, warn};

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
    timestamp: String,
}

#[derive(Serialize)]
struct StatusCapabilities {
    control_tower: bool,
    runtime_monitor: bool,
    tsa_rfc3161: bool,
    ecdsa_p256: bool,
    sha256_evidence_chain: bool,
    multi_trail: bool,
    countdown_oversight: bool,
}

#[derive(Serialize)]
struct TsaInfo {
    provider: String,
    protocol: String,
    mode: String,
}

#[derive(Serialize)]
struct StatusResponse {
    service: String,
    version: String,
    vendor: String,
    location: String,
    patent_status: String,
    capabilities: StatusCapabilities,
    tsa: TsaInfo,
    timestamp: String,
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
        timestamp: Utc::now().to_rfc3339(),
    })
}

async fn api_status() -> impl IntoResponse {
    Json(StatusResponse {
        service: "AegisFrame Control Tower".into(),
        version: "v0.7.0".into(),
        vendor: "X-Loop³ Labs".into(),
        location: "Kreuzlingen, Switzerland".into(),
        patent_status: "USPTO PPA Filed".into(),
        capabilities: StatusCapabilities {
            control_tower: true,
            runtime_monitor: true,
            tsa_rfc3161: true,
            ecdsa_p256: true,
            sha256_evidence_chain: true,
            multi_trail: true,
            countdown_oversight: true,
        },
        tsa: TsaInfo {
            provider: "freetsa.org".into(),
            protocol: "RFC 3161".into(),
            mode: "LIVE".into(),
        },
        timestamp: Utc::now().to_rfc3339(),
    })
}

// ============================================================
// REAL RFC 3161 TSA ENDPOINT
// ============================================================

/// Accepts { hash: <sha256_hex>, timestamp: <iso8601> }
/// Creates a real RFC 3161 timestamp request, sends it to freetsa.org,
/// and returns the signed timestamp token.
async fn tsa_anchor(
    Json(payload): Json<TsaRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let client_ts = payload
        .timestamp
        .unwrap_or_else(|| Utc::now().to_rfc3339());

    if payload.hash.len() != 64 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Hash must be 64 hex characters (SHA-256)"})),
        ));
    }

    let result = call_rfc3161_tsa(&payload.hash);

    if result.success {
        let receipt_id = result.receipt_id.unwrap_or_default();
        info!("TSA anchor successful: {}", receipt_id);
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
        let err_msg = result.error.unwrap_or_else(|| "Unknown error".into());
        warn!("TSA call failed: {}, using fallback", err_msg);

        let mut hasher = Sha256::new();
        hasher.update(format!("{}{}AEGISFRAME_FALLBACK", payload.hash, client_ts));
        let fallback_token = hex::encode(hasher.finalize());

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
            tsa_token: fallback_token,
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

/// Makes a real RFC 3161 timestamp request using openssl.
///
/// Steps:
/// 1. Write the hash to a temp file
/// 2. Create a TimeStampReq with `openssl ts -query`
/// 3. Send it to freetsa.org/tsr via curl
/// 4. Parse the response
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

    // Write hash as data to timestamp
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
                    "openssl ts -query failed: {}",
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
                    "curl to freetsa.org failed: {}",
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

    // Check response exists and has content
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
                error: Some("Empty response from TSA".into()),
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

    // Hash the TSA receipt as our token
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
                    if let Some(ts) = line.split_once(':').map(|(_, v)| v.trim().to_string()) {
                        // The format is "Time stamp: <value>" but split_once on ':' captures "Time stamp"
                        // We need to handle "Time stamp: <date>" properly
                        let parts: Vec<&str> = line.splitn(2, "Time stamp:").collect();
                        if parts.len() == 2 {
                            tsa_timestamp = Some(parts[1].trim().to_string());
                        } else {
                            tsa_timestamp = Some(ts);
                        }
                    }
                    break;
                }
            }
        }
    }

    // tmpdir is automatically cleaned up on drop

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

    let static_dir = PathBuf::from("static");

    let app = Router::new()
        .route("/health", get(health))
        .route("/api/v1/status", get(api_status))
        .route("/api/v1/tsa/anchor", post(tsa_anchor))
        .fallback_service(ServeDir::new(static_dir));

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("AegisFrame Control Tower starting on port {}", port);
    info!("TSA Provider: freetsa.org (RFC 3161 LIVE)");
    info!("Version: v0.7.0");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
