"""
AegisFrame Control Tower — Render Server
X-Loop³ Labs · Kreuzlingen, Switzerland
Patent Pending · USPTO

Serves the AegisFrame Control Tower + Runtime Monitor
with a REAL RFC 3161 Timestamp Authority endpoint via freetsa.org

PATCH NOTES (server.patched.py)
- Logs EXACT static/index.html path + sha256 prefix on every GET /
- Uses app.static_folder consistently (avoids relative-path surprises)
- Optional /favicon.ico handler (silences 404 noise)
- Adds SAME-ORIGIN LLM proxy endpoint for Mistral:
    POST /api/v1/llm/messages
  (fixes browser CORS issues by never calling the provider directly from the browser)
"""

import os
import hashlib
import subprocess
import tempfile
import time
import logging
from pathlib import Path
from datetime import datetime, timezone

from flask import Flask, send_from_directory, jsonify, request

# Optional dependency used for the LLM proxy
try:
    import requests  # pip install requests
except Exception:
    requests = None

app = Flask(__name__, static_folder='static')
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('aegisframe')

# ============================================================
# SERVE THE HTML
# ============================================================
@app.route('/')
def index():
    """
    Always serve from app.static_folder/index.html.
    Log absolute path + sha256 prefix so we can prove which file is live on Render.
    """
    p = Path(app.static_folder) / "index.html"
    try:
        data = p.read_bytes()
        h = hashlib.sha256(data).hexdigest()[:12]
        logger.info(f"SERVING index.html => {p.resolve()} sha256[:12]={h} cwd={os.getcwd()}")
    except Exception as e:
        logger.error(f"FAILED to read index.html => {p.resolve()} cwd={os.getcwd()} err={e}")

    return send_from_directory(app.static_folder, 'index.html')


@app.route('/favicon.ico')
def favicon():
    """
    Optional: place static/favicon.ico in repo.
    If missing, return 204 to avoid noisy 404 spam.
    """
    ico = Path(app.static_folder) / "favicon.ico"
    if not ico.exists():
        return ("", 204)
    return send_from_directory(app.static_folder, 'favicon.ico')


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
# REAL RFC 3161 TSA ENDPOINT
# ============================================================

@app.route('/api/v1/tsa/anchor', methods=['POST'])
def tsa_anchor():
    """
    Accepts a JSON body with { hash: <sha256_hex>, timestamp: <iso8601> }
    Creates a real RFC 3161 timestamp request, sends it to freetsa.org,
    and returns the signed timestamp token.
    """
    try:
        data = request.get_json()
        if not data or 'hash' not in data:
            return jsonify({'error': 'Missing hash field'}), 400

        hash_hex = data['hash']
        client_ts = data.get('timestamp', datetime.now(timezone.utc).isoformat())

        # Validate hash format (should be 64 hex chars = SHA-256)
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
            # Fallback: if TSA call fails, return honest error + local hash
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
    """
    Makes a real RFC 3161 timestamp request using openssl.

    Steps:
    1. Write the hash to a temp file
    2. Create a TimeStampReq with openssl ts -query
    3. Send it to freetsa.org/tsr via curl
    4. Parse the response
    """
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
            '-no_nonce',
            '-sha256',
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
            'openssl', 'ts', '-reply',
            '-in', tsr_file,
            '-text'
        ], capture_output=True, timeout=10)

        if proc.returncode == 0:
            text_output = proc.stdout.decode()
            for line in text_output.split('\n'):
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
            try:
                os.remove(f)
            except Exception:
                pass
        try:
            os.rmdir(tmpdir)
        except Exception:
            pass


# ============================================================
# LLM PROXY (Mistral) — fixes browser CORS
# Browser MUST call this endpoint instead of hitting Mistral directly.
# ============================================================
@app.route('/api/v1/llm/messages', methods=['POST'])
def llm_messages():
    """
    Same-origin proxy for Mistral chat completions.

    Requires:
      - requests installed (add to requirements.txt)
      - Render env var: MISTRAL_API_KEY
    """
    if requests is None:
        return jsonify({'error': 'requests not installed. Add "requests" to requirements.txt'}), 500

    api_key = os.environ.get("MISTRAL_API_KEY")
    if not api_key:
        return jsonify({'error': 'Missing MISTRAL_API_KEY env var'}), 500

    payload = request.get_json(force=True)

    # Common Mistral endpoint (adjust if your deployment differs)
    url = "https://api.mistral.ai/v1/chat/completions"

    try:
        r = requests.post(
            url,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=45,
        )
        return (r.text, r.status_code, {"content-type": "application/json"})
    except Exception as e:
        logger.error(f"LLM proxy error: {e}")
        return jsonify({'error': str(e)}), 500


# ============================================================
# API: System Status (for monitoring integrations)
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
            'countdown_oversight': True,
            'llm_proxy_mistral': True
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
    logger.info(f'static_folder={app.static_folder} cwd={os.getcwd()}')
    app.run(host='0.0.0.0', port=port, debug=False)
