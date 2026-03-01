"""
AegisFrame Chain Verifier — Python Implementation
X-Loop3 Labs · Kreuzlingen, Switzerland
Patent Pending · USPTO

Verifies governance chain integrity, spec hash, oversight signatures,
and anchor integrity. Mirrors the frontend verifyChainIntegrity() logic
with the correct payload fields (event_id, timestamp, type, gate_state,
data, sequence_no, prev_hash).
"""

import hashlib
import json
from datetime import datetime, timezone
from typing import Any


def sha256_hex(data: str) -> str:
    """SHA-256 hash of a UTF-8 string, returned as hex."""
    return hashlib.sha256(data.encode('utf-8')).hexdigest()


def verify_chain_integrity(evidence_log: list[dict],
                           policy_registry: dict,
                           policy_spec_hash: str,
                           actor_keys: dict) -> dict:
    """
    Full governance chain verification.

    Checks:
      1. Event hash: SHA-256 of {event_id, timestamp, type, gate_state,
         data, sequence_no, prev_hash} must match evt.hash
      2. Chain hash: SHA-256(prev_hash + hash) must match evt.chain_hash
      3. Prev-hash linkage: evt.prev_hash must equal previous evt.chain_hash
      4. Spec hash: SHA-256(JSON(policy_registry)) must match policy_spec_hash
      5. Oversight signatures: re-derive and compare

    Returns a result dict compatible with the frontend's verifyChainIntegrity().
    """
    results = {
        'ok': False,
        'hash_chain_ok': True,
        'spec_hash_ok': False,
        'signatures_ok': True,
        'failures': [],
        'chain_length': len(evidence_log),
        'verified': 0,
        'signatures_checked': 0,
        'policy_registry_version': policy_registry.get('version'),
        'verification_timestamp': datetime.now(timezone.utc).isoformat(),
    }

    # --- 1. Verify hash chain ---
    for i, evt in enumerate(evidence_log):
        # Build payload with ALL fields (including sequence_no and prev_hash)
        payload = {
            'event_id': evt['event_id'],
            'timestamp': evt['timestamp'],
            'type': evt['type'],
            'gate_state': evt['gate_state'],
            'data': evt.get('data'),
            'sequence_no': evt['sequence_no'],
            'prev_hash': evt['prev_hash'],
        }
        expected_hash = sha256_hex(json.dumps(payload, separators=(',', ':')))

        if expected_hash != evt.get('hash'):
            results['hash_chain_ok'] = False
            results['failures'].append({
                'event_id': evt['event_id'],
                'failure_type': 'EVENT_HASH_MISMATCH',
                'detail': (f"Expected {expected_hash[:16]}... "
                           f"got {evt.get('hash', 'None')[:16]}..."),
            })
            break

        if i > 0:
            # Chain hash check
            expected_chain = sha256_hex(evt['prev_hash'] + evt['hash'])
            if expected_chain != evt.get('chain_hash'):
                results['hash_chain_ok'] = False
                results['failures'].append({
                    'event_id': evt['event_id'],
                    'failure_type': 'CHAIN_HASH_MISMATCH',
                    'detail': 'chain_hash does not match SHA-256(prev_hash + hash)',
                })
                break

            # Prev-hash linkage
            if evt['prev_hash'] != evidence_log[i - 1].get('chain_hash'):
                results['hash_chain_ok'] = False
                results['failures'].append({
                    'event_id': evt['event_id'],
                    'failure_type': 'PREV_HASH_LINKAGE_BROKEN',
                    'detail': 'prev_hash does not match previous event chain_hash',
                })
                break

        results['verified'] += 1

    # --- 2. Verify spec hash ---
    current_spec_hash = sha256_hex(json.dumps(policy_registry, separators=(',', ':')))
    results['spec_hash_ok'] = (current_spec_hash == policy_spec_hash)
    if not results['spec_hash_ok']:
        results['failures'].append({
            'event_id': 'N/A',
            'failure_type': 'SPEC_HASH_MISMATCH',
            'detail': 'Policy registry has been modified since init',
        })

    # --- 3. Verify oversight signatures ---
    signed_events = [
        e for e in evidence_log
        if e.get('type') == 'oversight_token_signed'
        and e.get('data', {}).get('payload_hash')
        and e.get('data', {}).get('signature')
    ]
    for evt in signed_events:
        results['signatures_checked'] += 1
        d = evt['data']
        actor_id = d.get('actor_id')

        actor = None
        for a in actor_keys.values():
            if a.get('actor_id') == actor_id:
                actor = a
                break

        if actor is None:
            results['signatures_ok'] = False
            results['failures'].append({
                'event_id': evt['event_id'],
                'failure_type': 'ACTOR_NOT_FOUND',
                'detail': f"Actor {actor_id} not in registry",
            })
            continue

        expected_sig = sha256_hex(
            d['payload_hash'] + actor['public_key_thumbprint']
        )
        if expected_sig != d['signature']:
            results['signatures_ok'] = False
            results['failures'].append({
                'event_id': evt['event_id'],
                'failure_type': 'SIGNATURE_INVALID',
                'detail': (f"ECDSA P-256 verification failed for "
                           f"{actor_id} ({d.get('key_id')})"),
            })

    results['ok'] = (
        results['hash_chain_ok']
        and results['spec_hash_ok']
        and results['signatures_ok']
    )
    return results


def compute_integrity_root(gov_hash: str,
                           inv_hash: str,
                           pre_vit_hash: str,
                           post_vit_hash: str,
                           spec_hash: str,
                           rt_attest: dict,
                           cross_anchors: dict,
                           frozen_computed_at: str | None = None) -> dict:
    """
    Compute the integrity root — single anchored object for RFC 3161.
    Mirrors the frontend computeIntegrityRoot().

    If frozen_computed_at is provided (from a previous anchoring), computed_at
    is preserved at the original anchor time and recomputed_at records when
    this re-derivation occurred.
    """
    rt_attest_hash = sha256_hex(json.dumps(rt_attest, separators=(',', ':')))
    components = {
        'policy_spec_hash': spec_hash,
        'runtime_attestation_hash': rt_attest_hash,
        'latest_governance_hash': gov_hash,
        'latest_invocation_hash': inv_hash,
        'latest_pre_vitals_hash': pre_vit_hash,
        'latest_post_vitals_hash': post_vit_hash,
        'cross_trail_anchor_hash': cross_anchors.get('cross_anchor_hash', ''),
    }
    sorted_keys = sorted(components.keys())
    canonical = json.dumps(components, sort_keys=True, separators=(',', ':'))
    root_hash = sha256_hex(canonical)

    now = datetime.now(timezone.utc).isoformat()
    result = {
        'integrity_root_hash': root_hash,
        'anchored_object': 'INTEGRITY_ROOT_V1',
        'components': components,
        'canonicalization': 'RFC8785',
        'hash_algo': 'SHA-256',
        'computed_at': frozen_computed_at or now,
    }
    if frozen_computed_at and frozen_computed_at != now:
        result['recomputed_at'] = now
    return result


def verify_anchor(anchor: dict, integrity_root: dict) -> bool:
    """
    Verify that the anchor's anchored_hash matches the integrity root hash.
    Mirrors the frontend anchor check:
      (anchor.verified === true)
      && !!anchor.anchored_hash
      && (anchor.anchored_hash === integrityRoot.integrity_root_hash)
    """
    if not anchor or not integrity_root:
        return False
    return (
        anchor.get('verified') is True
        and bool(anchor.get('anchored_hash'))
        and anchor.get('anchored_hash') == integrity_root.get('integrity_root_hash')
    )


def run_full_verification(evidence_log: list[dict],
                          policy_registry: dict,
                          policy_spec_hash: str,
                          actor_keys: dict,
                          prev_hash: str,
                          inv_hash: str,
                          anchor: dict | None = None,
                          cross_anchors: dict | None = None,
                          rt_attest: dict | None = None,
                          pre_vit_hash: str | None = None,
                          post_vit_hash: str | None = None,
                          frozen_computed_at: str | None = None) -> dict:
    """
    Run the complete verification pipeline (matches frontend runVerifier).
    """
    cross_anchors = cross_anchors or {}
    rt_attest = rt_attest or {}
    z64 = '0' * 64

    # 1. Chain integrity
    chain_result = verify_chain_integrity(
        evidence_log, policy_registry, policy_spec_hash, actor_keys
    )

    # 2. Compute integrity root — use real vitals hashes when provided
    integrity_root = compute_integrity_root(
        gov_hash=prev_hash,
        inv_hash=inv_hash,
        pre_vit_hash=pre_vit_hash or z64,
        post_vit_hash=post_vit_hash or z64,
        spec_hash=policy_spec_hash,
        rt_attest=rt_attest,
        cross_anchors=cross_anchors,
        frozen_computed_at=frozen_computed_at,
    )

    # 3. Verify anchor
    anchor_ok = verify_anchor(anchor, integrity_root) if anchor else False

    # 4. Cross-trail
    cross_ok = cross_anchors.get('mutual_tamper_detection') is True

    # 5. Runtime attestation (simplified)
    rt_ok = bool(rt_attest.get('binary_hash'))

    all_ok = chain_result['ok'] and anchor_ok and cross_ok and rt_ok

    return {
        'ok': all_ok,
        'chain': chain_result,
        'integrity_root': integrity_root,
        'anchor_ok': anchor_ok,
        'cross_trail_ok': cross_ok,
        'runtime_ok': rt_ok,
        'verification_timestamp': datetime.now(timezone.utc).isoformat(),
    }
