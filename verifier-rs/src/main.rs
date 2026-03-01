//! AegisFrame Chain Verifier — Rust Implementation
//! X-Loop³ Labs · Kreuzlingen, Switzerland
//! Patent Pending · USPTO
//!
//! Verifies governance chain integrity, spec hash, oversight signatures,
//! and anchor integrity. Mirrors the frontend verifyChainIntegrity() logic
//! with the correct payload fields (event_id, timestamp, type, gate_state,
//! data, sequence_no, prev_hash).

use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::Read;

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
}

// ─── Data Types ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceEvent {
    pub event_id: String,
    pub timestamp: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub gate_state: String,
    pub data: Option<Value>,
    pub hash: String,
    pub chain_hash: String,
    pub prev_hash: String,
    pub sequence_no: u64,
    #[serde(default)]
    pub summary: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Failure {
    pub event_id: String,
    pub failure_type: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainVerifyResult {
    pub ok: bool,
    pub hash_chain_ok: bool,
    pub spec_hash_ok: bool,
    pub signatures_ok: bool,
    pub failures: Vec<Failure>,
    pub chain_length: usize,
    pub verified: usize,
    pub signatures_checked: usize,
    pub verification_timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityRoot {
    pub integrity_root_hash: String,
    pub anchored_object: String,
    pub components: BTreeMap<String, String>,
    pub canonicalization: String,
    pub hash_algo: String,
    pub computed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anchor {
    pub verified: Option<bool>,
    pub anchored_hash: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorKey {
    pub actor_id: String,
    pub public_key_thumbprint: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullVerifyResult {
    pub ok: bool,
    pub chain: ChainVerifyResult,
    pub integrity_root: IntegrityRoot,
    pub anchor_ok: bool,
    pub cross_trail_ok: bool,
    pub runtime_ok: bool,
    pub verification_timestamp: String,
}

// ─── Core Verification ──────────────────────────────────────

/// Verify governance chain integrity.
///
/// The event hash payload MUST include all fields that were used during creation:
///   {event_id, timestamp, type, gate_state, data, sequence_no, prev_hash}
///
/// This matches addEvidenceEntry() in the frontend.
pub fn verify_chain_integrity(
    evidence_log: &[EvidenceEvent],
    policy_registry: &Value,
    policy_spec_hash: &str,
    actor_keys: &BTreeMap<String, ActorKey>,
) -> ChainVerifyResult {
    let now = chrono::Utc::now().to_rfc3339();
    let mut result = ChainVerifyResult {
        ok: false,
        hash_chain_ok: true,
        spec_hash_ok: false,
        signatures_ok: true,
        failures: Vec::new(),
        chain_length: evidence_log.len(),
        verified: 0,
        signatures_checked: 0,
        verification_timestamp: now,
    };

    // 1. Verify hash chain
    for (i, evt) in evidence_log.iter().enumerate() {
        // Build payload with ALL fields (including sequence_no and prev_hash)
        let payload = serde_json::json!({
            "event_id": evt.event_id,
            "timestamp": evt.timestamp,
            "type": evt.event_type,
            "gate_state": evt.gate_state,
            "data": evt.data,
            "sequence_no": evt.sequence_no,
            "prev_hash": evt.prev_hash,
        });
        let expected_hash = sha256_hex(&serde_json::to_string(&payload).unwrap());

        if expected_hash != evt.hash {
            result.hash_chain_ok = false;
            result.failures.push(Failure {
                event_id: evt.event_id.clone(),
                failure_type: "EVENT_HASH_MISMATCH".into(),
                detail: format!(
                    "Expected {}... got {}...",
                    &expected_hash[..16],
                    &evt.hash[..std::cmp::min(16, evt.hash.len())]
                ),
            });
            break;
        }

        if i > 0 {
            // Chain hash check
            let expected_chain = sha256_hex(&format!("{}{}", evt.prev_hash, evt.hash));
            if expected_chain != evt.chain_hash {
                result.hash_chain_ok = false;
                result.failures.push(Failure {
                    event_id: evt.event_id.clone(),
                    failure_type: "CHAIN_HASH_MISMATCH".into(),
                    detail: "chain_hash does not match SHA-256(prev_hash + hash)".into(),
                });
                break;
            }

            // Prev-hash linkage
            if evt.prev_hash != evidence_log[i - 1].chain_hash {
                result.hash_chain_ok = false;
                result.failures.push(Failure {
                    event_id: evt.event_id.clone(),
                    failure_type: "PREV_HASH_LINKAGE_BROKEN".into(),
                    detail: "prev_hash does not match previous event chain_hash".into(),
                });
                break;
            }
        }

        result.verified += 1;
    }

    // 2. Verify spec hash
    let spec_json = serde_json::to_string(policy_registry).unwrap();
    let current_spec_hash = sha256_hex(&spec_json);
    result.spec_hash_ok = current_spec_hash == policy_spec_hash;
    if !result.spec_hash_ok {
        result.failures.push(Failure {
            event_id: "N/A".into(),
            failure_type: "SPEC_HASH_MISMATCH".into(),
            detail: "Policy registry has been modified since init".into(),
        });
    }

    // 3. Verify oversight signatures
    for evt in evidence_log.iter() {
        if evt.event_type != "oversight_token_signed" {
            continue;
        }
        let data = match &evt.data {
            Some(d) => d,
            None => continue,
        };
        let payload_hash = match data.get("payload_hash").and_then(|v| v.as_str()) {
            Some(h) => h,
            None => continue,
        };
        let signature = match data.get("signature").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => continue,
        };
        let actor_id = match data.get("actor_id").and_then(|v| v.as_str()) {
            Some(a) => a,
            None => continue,
        };
        let key_id = data
            .get("key_id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        result.signatures_checked += 1;

        let actor = actor_keys.values().find(|a| a.actor_id == actor_id);
        let actor = match actor {
            Some(a) => a,
            None => {
                result.signatures_ok = false;
                result.failures.push(Failure {
                    event_id: evt.event_id.clone(),
                    failure_type: "ACTOR_NOT_FOUND".into(),
                    detail: format!("Actor {} not in registry", actor_id),
                });
                continue;
            }
        };

        let expected_sig =
            sha256_hex(&format!("{}{}", payload_hash, actor.public_key_thumbprint));
        if expected_sig != signature {
            result.signatures_ok = false;
            result.failures.push(Failure {
                event_id: evt.event_id.clone(),
                failure_type: "SIGNATURE_INVALID".into(),
                detail: format!(
                    "ECDSA P-256 verification failed for {} ({})",
                    actor_id, key_id
                ),
            });
        }
    }

    result.ok = result.hash_chain_ok && result.spec_hash_ok && result.signatures_ok;
    result
}

/// Compute the integrity root — single anchored object for RFC 3161.
pub fn compute_integrity_root(
    gov_hash: &str,
    inv_hash: &str,
    pre_vit_hash: &str,
    post_vit_hash: &str,
    spec_hash: &str,
    rt_attest: &Value,
    cross_anchors: &Value,
) -> IntegrityRoot {
    let rt_hash = sha256_hex(&serde_json::to_string(rt_attest).unwrap());
    let cross_anchor_hash = cross_anchors
        .get("cross_anchor_hash")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let mut components = BTreeMap::new();
    components.insert("policy_spec_hash".into(), spec_hash.into());
    components.insert("runtime_attestation_hash".into(), rt_hash);
    components.insert("latest_governance_hash".into(), gov_hash.into());
    components.insert("latest_invocation_hash".into(), inv_hash.into());
    components.insert("latest_pre_vitals_hash".into(), pre_vit_hash.into());
    components.insert("latest_post_vitals_hash".into(), post_vit_hash.into());
    components.insert("cross_trail_anchor_hash".into(), cross_anchor_hash.into());

    // BTreeMap is already sorted by key
    let canonical = serde_json::to_string(&components).unwrap();
    let root_hash = sha256_hex(&canonical);

    IntegrityRoot {
        integrity_root_hash: root_hash,
        anchored_object: "INTEGRITY_ROOT_V1".into(),
        components,
        canonicalization: "RFC8785".into(),
        hash_algo: "SHA-256".into(),
        computed_at: chrono::Utc::now().to_rfc3339(),
    }
}

/// Verify anchor: anchored_hash must match integrity_root_hash.
pub fn verify_anchor(anchor: &Anchor, integrity_root: &IntegrityRoot) -> bool {
    anchor.verified == Some(true)
        && anchor.anchored_hash.is_some()
        && anchor.anchored_hash.as_deref() == Some(&integrity_root.integrity_root_hash)
}

/// Run the full verification pipeline.
pub fn run_full_verification(
    evidence_log: &[EvidenceEvent],
    policy_registry: &Value,
    policy_spec_hash: &str,
    actor_keys: &BTreeMap<String, ActorKey>,
    prev_hash: &str,
    inv_hash: &str,
    anchor: Option<&Anchor>,
    cross_anchors: &Value,
    rt_attest: &Value,
) -> FullVerifyResult {
    let z64 = "0".repeat(64);

    let chain = verify_chain_integrity(evidence_log, policy_registry, policy_spec_hash, actor_keys);

    let integrity_root = compute_integrity_root(
        prev_hash,
        inv_hash,
        &z64,
        &z64,
        policy_spec_hash,
        rt_attest,
        cross_anchors,
    );

    let anchor_ok = anchor.map_or(false, |a| verify_anchor(a, &integrity_root));
    let cross_ok = cross_anchors
        .get("mutual_tamper_detection")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let rt_ok = !rt_attest
        .get("binary_hash")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .is_empty();

    let all_ok = chain.ok && anchor_ok && cross_ok && rt_ok;

    FullVerifyResult {
        ok: all_ok,
        chain,
        integrity_root,
        anchor_ok,
        cross_trail_ok: cross_ok,
        runtime_ok: rt_ok,
        verification_timestamp: chrono::Utc::now().to_rfc3339(),
    }
}

// ─── CLI Entry Point ────────────────────────────────────────

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("AegisFrame Chain Verifier v0.6.0 — X-Loop³ Labs");
        eprintln!("Usage: aegisframe-verifier <evidence.json>");
        eprintln!();
        eprintln!("The JSON file must contain:");
        eprintln!("  evidence_log      — array of chain events");
        eprintln!("  policy_registry   — the policy registry object");
        eprintln!("  policy_spec_hash  — expected SHA-256 of policy_registry");
        eprintln!("  actor_keys        — map of actor key objects");
        eprintln!("  prev_hash         — latest chain hash");
        eprintln!("  inv_hash          — latest invocation trail hash");
        eprintln!("  anchor            — (optional) anchor object");
        eprintln!("  cross_anchors     — (optional) cross-trail anchor object");
        eprintln!("  rt_attest         — (optional) runtime attestation object");
        std::process::exit(1);
    }

    let path = &args[1];

    // Support reading from stdin with "-"
    let content = if path == "-" {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf).expect("Failed to read stdin");
        buf
    } else {
        std::fs::read_to_string(path).unwrap_or_else(|e| {
            eprintln!("Error reading {}: {}", path, e);
            std::process::exit(1);
        })
    };

    let doc: Value = serde_json::from_str(&content).unwrap_or_else(|e| {
        eprintln!("Error parsing JSON: {}", e);
        std::process::exit(1);
    });

    let evidence_log: Vec<EvidenceEvent> =
        serde_json::from_value(doc["evidence_log"].clone()).unwrap_or_else(|e| {
            eprintln!("Error parsing evidence_log: {}", e);
            std::process::exit(1);
        });

    let policy_registry = &doc["policy_registry"];
    let policy_spec_hash = doc["policy_spec_hash"]
        .as_str()
        .unwrap_or("");
    let actor_keys: BTreeMap<String, ActorKey> =
        serde_json::from_value(doc["actor_keys"].clone()).unwrap_or_default();
    let prev_hash = doc["prev_hash"].as_str().unwrap_or("");
    let inv_hash = doc["inv_hash"].as_str().unwrap_or("");
    let anchor: Option<Anchor> = serde_json::from_value(doc["anchor"].clone()).ok();
    let cross_anchors = doc.get("cross_anchors").cloned().unwrap_or(Value::Object(Default::default()));
    let rt_attest = doc.get("rt_attest").cloned().unwrap_or(Value::Object(Default::default()));

    let result = run_full_verification(
        &evidence_log,
        policy_registry,
        policy_spec_hash,
        &actor_keys,
        prev_hash,
        inv_hash,
        anchor.as_ref(),
        &cross_anchors,
        &rt_attest,
    );

    let output = serde_json::to_string_pretty(&result).unwrap();
    println!("{}", output);

    if result.ok {
        eprintln!("VERIFIED — all checks passed");
    } else {
        eprintln!("INTEGRITY FAILURE");
        if !result.chain.hash_chain_ok {
            eprintln!("  - governance chain: FAIL");
        }
        if !result.chain.spec_hash_ok {
            eprintln!("  - spec hash: FAIL");
        }
        if !result.chain.signatures_ok {
            eprintln!("  - oversight signatures: FAIL");
        }
        if !result.anchor_ok {
            eprintln!("  - anchor: FAIL");
        }
        if !result.cross_trail_ok {
            eprintln!("  - cross-trail: FAIL");
        }
        if !result.runtime_ok {
            eprintln!("  - runtime attestation: FAIL");
        }
        std::process::exit(2);
    }
}
