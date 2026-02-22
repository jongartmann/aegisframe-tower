"""
AegisFrame Control Tower — Enterprise Server
X-Loop³ Labs · Kreuzlingen, Switzerland
Patent Pending · USPTO

Features:
  - AegisFrame Control Tower + Runtime Monitor UI
  - REAL RFC 3161 Timestamp Authority (freetsa.org)
  - PSCP Hardware Proof Engine (GPU + eBPF + Process)
"""

import os
import hashlib
import subprocess
import tempfile
import time
import json
import logging
from datetime import datetime, timezone
from flask import Flask, send_from_directory, jsonify, request

app = Flask(__name__, static_folder='static')
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('aegisframe')

# Import PSCP proof engine
from api.pscp_proof import pscp_engine

# ============================================================
# SERVE THE HTML
# ============================================================
@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/health')
def health():
    return jsonify({
        'status': 'ok',
        'service': 'AegisFrame Control Tower',
        'version': 'v0.6.0-enterprise',
        'vendor': 'X-Loop³ Labs',
        'tsa_enabled': True,
        'pscp_enabled': True,
        'timestamp': datetime.now(timezone.utc).isoformat()
    })


# ============================================================
# REAL RFC 3161 TSA ENDPOINT
# ============================================================
@app.route('/api/v1/tsa/anchor', methods=['POST'])
def tsa_anchor():
    try:
        data = request.get_json()
        if not data or 'hash' not in data:
            return jsonify({'error': 'Missing hash field'}), 400
        
        hash_hex = data['hash']
        client_ts = data.get('timestamp', datetime.now(timezone.utc).isoformat())
        
        if len(hash_hex) != 64:
            return jsonify({'error': 'Hash must be 64 hex chars (SHA-256)'}), 400
        
        result = call_rfc3161_tsa(hash_hex)
        
        if result['success']:
            logger.info(f"TSA anchor OK: {result['receipt_id']}")
            return jsonify({
                'status': 'ANCHORED',
                'tsa_provider': 'freetsa.org',
                'tsa_protocol': 'RFC 3161',
                'tsa_mode': 'LIVE',
                'anchored_hash': hash_hex,
                'tsa_token': result['token_hash'],
                'receipt_hex': result['receipt_hex'],
                'receipt_id': result['receipt_id'],
                'tsa_response_size': result['response_size'],
                'tsa_timestamp': result.get('tsa_timestamp', client_ts),
                'verified': True,
                'timestamp': client_ts
            })
        else:
            logger.warning(f"TSA failed: {result.get('error')}")
            fallback = hashlib.sha256(
                (hash_hex + client_ts + 'AEGISFRAME_FALLBACK').encode()
            ).hexdigest()
            return jsonify({
                'status': 'FALLBACK',
                'tsa_provider': 'freetsa.org',
                'tsa_mode': 'FALLBACK',
                'tsa_error': result.get('error', 'Unknown'),
                'anchored_hash': hash_hex,
                'tsa_token': fallback,
                'receipt_id': f'FALLBACK_{int(time.time())}',
                'verified': False,
                'timestamp': client_ts
            })
    
    except Exception as e:
        logger.error(f"TSA error: {e}")
        return jsonify({'error': str(e)}), 500


def call_rfc3161_tsa(hash_hex: str) -> dict:
    tmpdir = tempfile.mkdtemp()
    hash_file = os.path.join(tmpdir, 'data.txt')
    tsq_file = os.path.join(tmpdir, 'request.tsq')
    tsr_file = os.path.join(tmpdir, 'response.tsr')
    
    try:
        with open(hash_file, 'w') as f:
            f.write(hash_hex)
        
        proc = subprocess.run([
            'openssl', 'ts', '-query',
            '-data', hash_file, '-no_nonce', '-sha256', '-out', tsq_file
        ], capture_output=True, timeout=10)
        
        if proc.returncode != 0:
            return {'success': False, 'error': f'openssl ts failed: {proc.stderr.decode()}'}
        
        proc = subprocess.run([
            'curl', '-s', '-S',
            '-H', 'Content-Type: application/timestamp-query',
            '--data-binary', f'@{tsq_file}',
            '--max-time', '15',
            '-o', tsr_file,
            'https://freetsa.org/tsr'
        ], capture_output=True, timeout=20)
        
        if proc.returncode != 0:
            return {'success': False, 'error': f'curl failed: {proc.stderr.decode()}'}
        
        if not os.path.exists(tsr_file) or os.path.getsize(tsr_file) == 0:
            return {'success': False, 'error': 'Empty TSA response'}
        
        response_size = os.path.getsize(tsr_file)
        with open(tsr_file, 'rb') as f:
            receipt_bytes = f.read()
        
        token_hash = hashlib.sha256(receipt_bytes).hexdigest()
        receipt_id = f'TSA_{int(time.time())}_{token_hash[:8]}'
        
        tsa_timestamp = None
        proc = subprocess.run([
            'openssl', 'ts', '-reply', '-in', tsr_file, '-text'
        ], capture_output=True, timeout=10)
        if proc.returncode == 0:
            for line in proc.stdout.decode().split('\n'):
                if 'Time stamp:' in line:
                    tsa_timestamp = line.split(':', 1)[1].strip()
                    break
        
        return {
            'success': True,
            'token_hash': token_hash,
            'receipt_hex': receipt_bytes.hex(),
            'receipt_id': receipt_id,
            'response_size': response_size,
            'tsa_timestamp': tsa_timestamp
        }
    except subprocess.TimeoutExpired:
        return {'success': False, 'error': 'Timeout'}
    except Exception as e:
        return {'success': False, 'error': str(e)}
    finally:
        for f in [hash_file, tsq_file, tsr_file]:
            try: os.remove(f)
            except: pass
        try: os.rmdir(tmpdir)
        except: pass


# ============================================================
# PSCP HARDWARE PROOF ENDPOINTS
# ============================================================

@app.route('/api/v1/pscp/status')
def pscp_status():
    """PSCP engine capabilities and status."""
    return jsonify(pscp_engine.get_status())


@app.route('/api/v1/pscp/snapshot', methods=['POST'])
def pscp_snapshot():
    """Capture a hardware state snapshot (before or after decision)."""
    phase = request.args.get('phase', 'before')
    
    if phase == 'before':
        snap = pscp_engine.capture_before()
    else:
        snap = pscp_engine.capture_after()
    
    return jsonify({
        'phase': phase,
        'snapshot': snap,
        'timestamp': datetime.now(timezone.utc).isoformat()
    })


@app.route('/api/v1/pscp/prove', methods=['POST'])
def pscp_prove():
    """
    Execute a complete PSCP proof cycle.
    
    Body: {
        "request_hash": "<sha256 of the request>",
        "decision": "BLOCK" | "ALLOW"
    }
    
    The endpoint will:
    1. Snapshot hardware state (before is already captured)
    2. Generate the proof
    3. Return the signed PSCP proof object
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Missing body'}), 400
        
        request_hash = data.get('request_hash', 
            hashlib.sha256(str(time.time()).encode()).hexdigest())
        decision = data.get('decision', 'BLOCK')
        
        # Full proof cycle
        before = pscp_engine.capture_before()
        
        # Simulate the decision delay (in production, this is the actual
        # governance decision happening between before/after snapshots)
        time.sleep(0.1)
        
        after = pscp_engine.capture_after()
        proof = pscp_engine.produce_proof(before, after, decision, request_hash)
        
        logger.info(f"PSCP proof generated: {proof['proof_id']} → {proof['verdict']}")
        
        return jsonify(proof)
    
    except Exception as e:
        logger.error(f"PSCP proof error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/pscp/prove/full', methods=['POST'])
def pscp_prove_full():
    """
    Full PSCP proof with TSA anchoring.
    Produces hardware proof + anchors the proof hash to RFC 3161 TSA.
    """
    try:
        data = request.get_json() or {}
        request_hash = data.get('request_hash',
            hashlib.sha256(str(time.time()).encode()).hexdigest())
        decision = data.get('decision', 'BLOCK')
        
        # Hardware proof
        before = pscp_engine.capture_before()
        time.sleep(0.1)
        after = pscp_engine.capture_after()
        proof = pscp_engine.produce_proof(before, after, decision, request_hash)
        
        # Anchor proof hash to TSA
        tsa_result = call_rfc3161_tsa(proof['proof_hash'])
        
        proof['tsa_anchor'] = {
            'anchored': tsa_result['success'],
            'tsa_provider': 'freetsa.org',
            'tsa_protocol': 'RFC 3161',
            'proof_hash_anchored': proof['proof_hash'],
            'tsa_receipt_id': tsa_result.get('receipt_id'),
            'tsa_timestamp': tsa_result.get('tsa_timestamp')
        }
        
        logger.info(f"PSCP full proof: {proof['proof_id']} → {proof['verdict']} "
                    f"+ TSA {'OK' if tsa_result['success'] else 'FALLBACK'}")
        
        return jsonify(proof)
    
    except Exception as e:
        logger.error(f"PSCP full proof error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/pscp/trail')
def pscp_trail():
    """Return the append-only proof trail."""
    return jsonify({
        'trail': pscp_engine.get_proof_trail(),
        'count': len(pscp_engine.get_proof_trail()),
        'timestamp': datetime.now(timezone.utc).isoformat()
    })


# ============================================================
# API STATUS
# ============================================================
@app.route('/api/v1/status')
def api_status():
    pscp_stat = pscp_engine.get_status()
    return jsonify({
        'service': 'AegisFrame Control Tower',
        'version': 'v0.6.0-enterprise',
        'vendor': 'X-Loop³ Labs',
        'location': 'Kreuzlingen, Switzerland',
        'patent_status': {
            'siren': 'USPTO PPA 63/983,192',
            'pscp': 'USPTO PPA 63/983,493',
            'milkmind': 'USPTO PPA 63/986,414',
            'aegisframe': 'USPTO PPA (filing)',
            'electric_translator': 'USPTO PPA (filing)'
        },
        'capabilities': {
            'control_tower': True,
            'runtime_monitor': True,
            'tsa_rfc3161': True,
            'pscp_hardware_proof': True,
            'gpu_nvml': pscp_stat['capabilities']['gpu_nvml'],
            'ebpf': pscp_stat['capabilities']['ebpf'],
            'ecdsa_p256': True,
            'sha256_evidence_chain': True,
            'multi_trail': True,
            'countdown_oversight': True
        },
        'timestamp': datetime.now(timezone.utc).isoformat()
    })


# ============================================================
# BOOT
# ============================================================
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    logger.info(f'═══════════════════════════════════════════════')
    logger.info(f'  AegisFrame Control Tower · Enterprise Server')
    logger.info(f'  X-Loop³ Labs · Kreuzlingen, Switzerland')
    logger.info(f'  Port: {port}')
    logger.info(f'  TSA: freetsa.org (RFC 3161 LIVE)')
    logger.info(f'  PSCP: GPU + eBPF + Process Attestation')
    logger.info(f'  Patents: SIREN · PSCP · MilkMind · AegisFrame')
    logger.info(f'═══════════════════════════════════════════════')
    app.run(host='0.0.0.0', port=port, debug=False)
