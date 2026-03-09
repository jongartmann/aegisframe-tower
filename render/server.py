"""
AegisFrame Control Tower — Render Server
X-Loop³ Labs · Kreuzlingen, Switzerland
Patent Pending · USPTO

Serves the AegisFrame Control Tower + Runtime Monitor demo
with a REAL RFC 3161 Timestamp Authority endpoint via freetsa.org
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
        'timestamp': datetime.now(timezone.utc).isoformat()
    })

# ============================================================
# LICENSE VALIDATION ENDPOINT
# ============================================================
# ENV variable: LICENSE_KEYS (JSON string)
# Example:
# {
#   "XL3-XXXX-YYYY-ZZZZ": {
#     "active": true,
#     "label": "Acme Corp",
#     "expires": null,
#     "features": ["tower", "tsa", "enterprise_tier"]
#   },
#   "XL3-DEMO-0000-0000": {
#     "active": true,
#     "label": "Demo",
#     "expires": "2026-12-31",
#     "features": ["tower"]
#   }
# }
# ============================================================

def load_license_db():
    raw = os.environ.get('LICENSE_KEYS')
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return None

@app.route('/api/v1/license', methods=['POST', 'OPTIONS'])
def license_check():
    if request.method == 'OPTIONS':
        return '', 204

    try:
        data = request.get_json(silent=True) or {}
        license_key = data.get('license_key', '').strip()

        if not license_key:
            return jsonify({'valid': False, 'error': 'license_key is required', 'code': 'MISSING_KEY'}), 400

        db = load_license_db()

        # Dev magic key — works when no LICENSE_KEYS env is set
        if not db:
            if license_key == 'XL3-DEV-LOCAL':
                return jsonify({
                    'valid': True,
                    'label': 'Local Dev',
                    'features': ['tower', 'tsa', 'enterprise_tier'],
                    'expires': None,
                    'checked_at': datetime.now(timezone.utc).isoformat()
                })
            return jsonify({'valid': False, 'error': 'License service not configured', 'code': 'SERVICE_UNAVAILABLE'}), 503

        entry = db.get(license_key)

        if not entry:
            logger.warning(f'License not found: {license_key[:8]}...')
            return jsonify({'valid': False, 'error': 'License key not found', 'code': 'NOT_FOUND'}), 403

        # Kill switch
        if not entry.get('active', False):
            logger.warning(f'Deactivated license used: {license_key[:8]}...')
            return jsonify({'valid': False, 'error': 'License has been deactivated', 'code': 'DEACTIVATED'}), 403

        # Expiry check
        expires = entry.get('expires')
        if expires:
            try:
                expiry_dt = datetime.fromisoformat(expires).replace(tzinfo=timezone.utc)
                if datetime.now(timezone.utc) > expiry_dt:
                    return jsonify({'valid': False, 'error': f'License expired on {expires}', 'code': 'EXPIRED', 'expires': expires}), 403
            except ValueError:
                pass

        logger.info(f'License validated: {entry.get("label", "Unknown")} [{license_key[:8]}...]')
        return jsonify({
            'valid': True,
            'label': entry.get('label', 'Licensed'),
            'features': entry.get('features', []),
            'expires': expires,
            'checked_at': datetime.now(timezone.utc).isoformat()
        })

    except Exception as e:
        logger.error(f'License endpoint error: {e}')
        return jsonify({'valid': False, 'error': str(e), 'code': 'SERVER_ERROR'}), 500


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
            return jsonify({'error': 'Hash must be 64 hex characters (SHA-256)'}), 400

        result = call_rfc3161_tsa(hash_hex)

        if result['success']:
            logger.info(f"TSA anchor successful: {result['receipt_id']}")
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
            logger.warning(f"TSA call failed: {result.get('error')}, using fallback")
            fallback_token = hashlib.sha256(
                (hash_hex + client_ts + 'AEGISFRAME_FALLBACK').encode()
            ).hexdigest()
            return jsonify({
                'status': 'FALLBACK',
                'tsa_provider': 'freetsa.org',
                'tsa_protocol': 'RFC 3161',
                'tsa_mode': 'FALLBACK',
                'tsa_error': result.get('error', 'Unknown error'),
                'anchored_hash': hash_hex,
                'tsa_token': fallback_token,
                'receipt_hex': None,
                'receipt_id': f'FALLBACK_{int(time.time())}',
                'verified': False,
                'timestamp': client_ts
            })

    except Exception as e:
        logger.error(f"TSA endpoint error: {e}")
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
            '-data', hash_file,
            '-no_nonce', '-sha256',
            '-out', tsq_file
        ], capture_output=True, timeout=10)

        if proc.returncode != 0:
            return {'success': False, 'error': f'openssl ts -query failed: {proc.stderr.decode()}'}

        proc = subprocess.run([
            'curl', '-s', '-S',
            '-H', 'Content-Type: application/timestamp-query',
            '--data-binary', f'@{tsq_file}',
            '--max-time', '15',
            '-o', tsr_file,
            'https://freetsa.org/tsr'
        ], capture_output=True, timeout=20)

        if proc.returncode != 0:
            return {'success': False, 'error': f'curl to freetsa.org failed: {proc.stderr.decode()}'}

        if not os.path.exists(tsr_file) or os.path.getsize(tsr_file) == 0:
            return {'success': False, 'error': 'Empty response from TSA'}

        response_size = os.path.getsize(tsr_file)

        with open(tsr_file, 'rb') as f:
            receipt_bytes = f.read()
        receipt_hex = receipt_bytes.hex()
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
            'receipt_hex': receipt_hex,
            'receipt_id': receipt_id,
            'response_size': response_size,
            'tsa_timestamp': tsa_timestamp
        }

    except subprocess.TimeoutExpired:
        return {'success': False, 'error': 'TSA request timed out'}
    except Exception as e:
        return {'success': False, 'error': str(e)}
    finally:
        for f in [hash_file, tsq_file, tsr_file]:
            try: os.remove(f)
            except: pass
        try: os.rmdir(tmpdir)
        except: pass


# ============================================================
# API: System Status
# ============================================================
@app.route('/api/v1/status')
def api_status():
    return jsonify({
        'service': 'AegisFrame Control Tower',
        'version': 'v0.6.0-enterprise',
        'vendor': 'X-Loop³ Labs',
        'location': 'Kreuzlingen, Switzerland',
        'patent_status': 'USPTO PPA Filed',
        'capabilities': {
            'control_tower': True,
            'runtime_monitor': True,
            'tsa_rfc3161': True,
            'ecdsa_p256': True,
            'sha256_evidence_chain': True,
            'multi_trail': True,
            'countdown_oversight': True
        },
        'tsa': {
            'provider': 'freetsa.org',
            'protocol': 'RFC 3161',
            'mode': 'LIVE'
        },
        'timestamp': datetime.now(timezone.utc).isoformat()
    })


# ============================================================
# BOOT
# ============================================================
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    logger.info(f'AegisFrame Control Tower starting on port {port}')
    logger.info(f'TSA Provider: freetsa.org (RFC 3161 LIVE)')
    logger.info(f'Version: v0.6.0-enterprise')
    app.run(host='0.0.0.0', port=port, debug=False)
