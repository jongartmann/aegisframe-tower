"""
Aegis Tower™ License Gate
X-Loop³ Labs Ltd — Patent Pending USPTO 63/996,268
Swiss law (OR) · ICC Arbitration Zürich
"""

import os
import json
import time
import hashlib
import logging
from pathlib import Path
from datetime import datetime, timezone

LICENSE_API = "https://xloop3-license-api.xloop3.workers.dev"
CACHE_FILE  = Path(".aegis_license_cache")
CACHE_TTL   = 86400  # 24 hours in seconds
KEY_ENV_VAR = "AEGIS_LICENSE_KEY"

logger = logging.getLogger("aegis.license_gate")


class LicenseGateError(RuntimeError):
    """Raised when license validation fails — system must halt."""
    pass


def _key_fingerprint(key: str) -> str:
    """Return a short hash of the key for safe logging (never log raw key)."""
    return hashlib.sha256(key.encode()).hexdigest()[:12]


def _load_cache() -> dict | None:
    try:
        if CACHE_FILE.exists():
            data = json.loads(CACHE_FILE.read_text())
            if time.time() - data.get("cached_at", 0) < CACHE_TTL:
                return data
    except Exception:
        pass
    return None


def _save_cache(result: dict) -> None:
    try:
        result["cached_at"] = time.time()
        CACHE_FILE.write_text(json.dumps(result))
    except Exception as e:
        logger.warning(f"Could not write license cache: {e}")


def _validate_online(key: str) -> dict:
    """Call the License Chain API. Returns validation result."""
    import urllib.request
    payload = json.dumps({"license_key": key}).encode()
    req = urllib.request.Request(
        f"{LICENSE_API}/api/license/validate",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


def validate_license() -> dict:
    """
    Main entry point. Call this at Aegis Tower startup.

    Raises LicenseGateError if license is invalid or revoked.
    Returns validation result dict if valid.

    Priority order:
    1. AEGIS_LICENSE_KEY env var
    2. .env file (AEGIS_LICENSE_KEY=...)
    3. aegis_license.key file in working directory
    """
    # 1. Resolve key
    key = os.environ.get(KEY_ENV_VAR)

    if not key:
        env_file = Path(".env")
        if env_file.exists():
            for line in env_file.read_text().splitlines():
                if line.startswith(f"{KEY_ENV_VAR}="):
                    key = line.split("=", 1)[1].strip().strip('"').strip("'")
                    break

    if not key:
        key_file = Path("aegis_license.key")
        if key_file.exists():
            key = key_file.read_text().strip()

    if not key:
        raise LicenseGateError(
            "No license key found. Set AEGIS_LICENSE_KEY env var, "
            "add to .env, or create aegis_license.key file."
        )

    fingerprint = _key_fingerprint(key)
    logger.info(f"[LicenseGate] Validating key ...{fingerprint}")

    # 2. Check cache first
    cached = _load_cache()
    if cached and cached.get("valid") and cached.get("fingerprint") == fingerprint:
        logger.info(f"[LicenseGate] Cache hit — valid until "
                    f"{datetime.fromtimestamp(cached['cached_at'] + CACHE_TTL, tz=timezone.utc).isoformat()}")
        return cached

    # 3. Online validation
    try:
        result = _validate_online(key)
    except Exception as e:
        # Network error — fall back to stale cache if exists
        stale = None
        try:
            if CACHE_FILE.exists():
                stale = json.loads(CACHE_FILE.read_text())
        except Exception:
            pass

        if stale and stale.get("valid") and stale.get("fingerprint") == fingerprint:
            logger.warning(f"[LicenseGate] Network error ({e}), using stale cache. "
                           f"Will revalidate next startup.")
            return stale

        raise LicenseGateError(
            f"License validation failed (network error: {e}) and no valid cache available."
        )

    result["fingerprint"] = fingerprint

    if not result.get("valid"):
        # Clear cache on revocation
        try:
            CACHE_FILE.unlink(missing_ok=True)
        except Exception:
            pass

        status = result.get("status", "unknown")
        logger.error(f"[LicenseGate] License INVALID — status: {status}")
        raise LicenseGateError(
            f"Aegis Tower™ license is not valid (status: {status}). "
            f"Contact X-Loop³ Labs: jon@x-loop3.com"
        )

    # 4. Valid — cache and return
    _save_cache(result)
    logger.info(
        f"[LicenseGate] VALID — "
        f"customer={result.get('customer')} tier={result.get('tier')} "
        f"pos=#{result.get('position')}"
    )
    return result
