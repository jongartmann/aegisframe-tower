"""
AegisFrame PSCP — Combined Hardware Proof API
X-Loop³ Labs · Patent Pending · USPTO 63/983,493

This module provides the unified PSCP (Pre-Semantic Structural Control Plane)
hardware proof endpoint. It orchestrates:

  1. GPU Attestation (NVML)     → "No inference compute occurred"
  2. Socket Attestation (eBPF)  → "No data left the container"
  3. Process Attestation (/proc) → "No inference process was spawned"

Combined, these three independent hardware/OS sources produce an
audit-grade proof that a governance decision was enforced BEFORE
the model was ever involved.

This is what makes PSCP different from every other AI governance tool:
they check AFTER. We prove BEFORE.
"""

import hashlib
import json
import time
import logging
from datetime import datetime, timezone

from monitoring.gpu_attestor import gpu_attestor
from monitoring.socket_monitor import socket_monitor
from monitoring.process_attestor import process_attestor

logger = logging.getLogger('aegisframe.pscp')


class PSCPProofEngine:
    """
    Orchestrates a complete PSCP hardware proof cycle.
    
    Flow:
    1. BEFORE governance decision → snapshot all three sources
    2. Governance decision executes (BLOCK or ALLOW)
    3. AFTER governance decision → snapshot all three sources
    4. Compare → produce signed attestations
    5. Combine into single PSCP_PROOF object
    """
    
    def __init__(self):
        self.proof_counter = 0
        self.proofs = []  # Append-only proof trail
        logger.info("PSCP Proof Engine initialized")
        logger.info(f"  GPU (NVML): {'AVAILABLE' if gpu_attestor.initialized else 'UNAVAILABLE'}")
        logger.info(f"  eBPF: {'AVAILABLE' if socket_monitor.available else 'FALLBACK to /proc/net'}")
        logger.info(f"  Process: {'PSUTIL' if process_attestor.available else '/proc direct'}")
    
    def capture_before(self) -> dict:
        """Capture pre-decision hardware state."""
        return {
            'gpu': gpu_attestor.snapshot(),
            'socket': socket_monitor.snapshot_connections(),
            'process': process_attestor.snapshot(),
            'captured_at': datetime.now(timezone.utc).isoformat()
        }
    
    def capture_after(self) -> dict:
        """Capture post-decision hardware state."""
        return {
            'gpu': gpu_attestor.snapshot(),
            'socket': socket_monitor.snapshot_connections(),
            'process': process_attestor.snapshot(),
            'captured_at': datetime.now(timezone.utc).isoformat()
        }
    
    def produce_proof(self, before: dict, after: dict, 
                      decision: str, request_hash: str) -> dict:
        """
        Produce a complete PSCP hardware proof.
        
        Args:
            before: Pre-decision hardware state
            after: Post-decision hardware state
            decision: 'BLOCK' or 'ALLOW'
            request_hash: SHA-256 of the original request
        
        Returns:
            Complete PSCP proof object with all three attestations
        """
        self.proof_counter += 1
        ts = datetime.now(timezone.utc).isoformat()
        
        # Individual attestations
        gpu_attest = gpu_attestor.attest_no_inference(
            before['gpu'], after['gpu']
        )
        socket_attest = socket_monitor.attest_no_outbound(
            before['socket'], after['socket']
        )
        process_attest = process_attestor.attest_no_inference_process(
            before['process'], after['process']
        )
        
        # Combined verdict
        verdicts = {
            'gpu': gpu_attest['verdict'],
            'socket': socket_attest['verdict'],
            'process': process_attest['verdict']
        }
        
        if decision == 'BLOCK':
            # For BLOCK decisions, all three must confirm no inference
            expected = {
                'gpu': 'NO_INFERENCE_CONFIRMED',
                'socket': 'NO_OUTBOUND_CONFIRMED',
                'process': 'NO_PROCESS_CONFIRMED'
            }
            # Handle unavailable GPU gracefully
            if gpu_attest.get('proof_level') == 'UNAVAILABLE':
                expected['gpu'] = None
                verdicts['gpu'] = None
            
            active_verdicts = {k: v for k, v in verdicts.items() if v is not None}
            active_expected = {k: v for k, v in expected.items() if v is not None}
            
            pscp_verified = active_verdicts == active_expected
            pscp_verdict = 'PSCP_BLOCK_VERIFIED' if pscp_verified else 'PSCP_BLOCK_VIOLATION'
        else:
            # For ALLOW decisions, we expect inference to have occurred
            pscp_verdict = 'PSCP_ALLOW_RECORDED'
            pscp_verified = True
        
        # Build the complete proof
        proof = {
            'proof_type': 'PSCP_HARDWARE_PROOF',
            'proof_id': f'PSCP_{self.proof_counter:06d}_{int(time.time())}',
            'patent_ref': 'USPTO PPA 63/983,493',
            'vendor': 'X-Loop³ Labs',
            'version': 'v0.6.0-enterprise',
            
            'decision': decision,
            'request_hash': request_hash,
            
            'verdict': pscp_verdict,
            'verified': pscp_verified,
            
            'attestations': {
                'gpu': gpu_attest,
                'socket': socket_attest,
                'process': process_attest
            },
            
            'proof_levels': {
                'gpu': gpu_attest.get('proof_level', 'UNAVAILABLE'),
                'socket': socket_attest.get('proof_level', 'UNKNOWN'),
                'process': process_attest.get('proof_level', 'UNKNOWN')
            },
            
            'timing': {
                'before_captured': before['captured_at'],
                'after_captured': after['captured_at'],
                'proof_generated': ts
            },
            
            'timestamp': ts
        }
        
        # Sign the entire proof
        proof['proof_hash'] = hashlib.sha256(
            json.dumps(proof, sort_keys=True, default=str).encode()
        ).hexdigest()
        
        # Append to proof trail
        self.proofs.append({
            'proof_id': proof['proof_id'],
            'proof_hash': proof['proof_hash'],
            'verdict': pscp_verdict,
            'timestamp': ts
        })
        
        return proof
    
    def get_proof_trail(self) -> list:
        """Return the append-only proof trail."""
        return list(self.proofs)
    
    def get_status(self) -> dict:
        """Return engine status."""
        return {
            'engine': 'PSCP Hardware Proof Engine',
            'proofs_generated': self.proof_counter,
            'capabilities': {
                'gpu_nvml': gpu_attestor.initialized,
                'gpu_device': gpu_attestor.device_count if gpu_attestor.initialized else 0,
                'gpu_driver': gpu_attestor.driver_version,
                'ebpf': socket_monitor.available,
                'process_monitor': process_attestor.available,
                'proc_path': process_attestor.proc_path
            },
            'patent_ref': 'USPTO PPA 63/983,493'
        }


# Singleton
pscp_engine = PSCPProofEngine()
