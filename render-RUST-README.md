<p align="center">
  <img src="https://img.shields.io/badge/AegisFrame-Render_Rust-0a0e1a?style=for-the-badge&labelColor=12b47a&color=0a0e1a" />
  <img src="https://img.shields.io/badge/Rust-🦀-dea584?style=for-the-badge&logo=rust&logoColor=white" />
  <img src="https://img.shields.io/badge/RFC_3161-TSA_LIVE-green?style=for-the-badge" />
</p>

# 🛡 AegisFrame Render — Rust Deployment

Standard deployment with real RFC 3161 TSA anchoring.
Single Rust binary — no Python interpreter, no virtualenv, no `pip install`.

---

## Quick Deploy to Render

1. Push this repo to GitHub
2. Go to [Render Dashboard](https://dashboard.render.com)
3. New → Web Service → Connect this repo
4. **Root Directory:** `.` (workspace root)
5. **Runtime:** Rust
6. **Build Command:** `cargo build --release -p aegisframe-render`
7. **Start Command:** `./target/release/aegisframe-render`
8. Deploy

Or use the provided `render/render.yaml` for auto-configuration.

---

## Local Development

```bash
# From workspace root
cargo run -p aegisframe-render

# Or from render directory
cd render
cargo run
```

The server starts on `http://localhost:10000` (or `$PORT`).

---

## Rust Module Structure

```
render/
├── Cargo.toml          # Dependencies: axum, tokio, sha2, chrono
├── render.yaml         # Render auto-deploy config
├── src/
│   └── main.rs         # Axum server
│       ├── GET  /              → static/index.html (fallback)
│       ├── GET  /health        → HealthResponse (JSON)
│       ├── GET  /api/v1/status → StatusResponse (JSON)
│       └── POST /api/v1/tsa/anchor → TsaResponse (JSON)
│                                     ↓
│                              openssl ts -query
│                                     ↓
│                              curl → freetsa.org/tsr
│                                     ↓
│                              TsaResult { token_hash, receipt_hex, ... }
│
└── static/
    └── index.html      # AegisFrame Control Tower + Runtime Monitor UI
```

---

## Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | AegisFrame Control Tower + Runtime Monitor |
| `GET` | `/health` | Health check |
| `GET` | `/api/v1/status` | System status + capabilities |
| `POST` | `/api/v1/tsa/anchor` | Real RFC 3161 timestamp (freetsa.org) |

---

## TSA (Timestamp Authority)

The RFC 3161 Timestamp Authority call is **real** — not simulated.

The Rust server:
1. Receives `{ "hash": "<sha256_hex>" }` via POST
2. Writes the hash to a temp file (`tempfile` crate)
3. Creates a TimeStampReq with `openssl ts -query`
4. Sends it to `freetsa.org/tsr` via `curl`
5. Parses the signed timestamp response
6. Returns the token hash + receipt as JSON

### Request
```bash
curl -X POST http://localhost:10000/api/v1/tsa/anchor \
  -H "Content-Type: application/json" \
  -d '{"hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}'
```

### Response (Success)
```json
{
  "status": "ANCHORED",
  "tsa_provider": "freetsa.org",
  "tsa_protocol": "RFC 3161",
  "tsa_mode": "LIVE",
  "anchored_hash": "e3b0c44298fc1c149afbf4c8996fb924...",
  "tsa_token": "a1b2c3d4...",
  "receipt_hex": "3082...",
  "receipt_id": "TSA_1740264000_a1b2c3d4",
  "tsa_response_size": 4523,
  "tsa_timestamp": "Feb 28 10:00:01 2026 GMT",
  "verified": true,
  "timestamp": "2026-02-28T10:00:00.000Z"
}
```

### Response (Fallback)
If freetsa.org is unreachable, the server returns a deterministic fallback hash:
```json
{
  "status": "FALLBACK",
  "tsa_mode": "FALLBACK",
  "tsa_error": "curl to freetsa.org failed: ...",
  "tsa_token": "<sha256(hash + timestamp + AEGISFRAME_FALLBACK)>",
  "verified": false
}
```

---

## Architecture

```
Browser → Axum (Tokio async) → static/index.html
                              → /api/v1/tsa/anchor → openssl ts → freetsa.org/tsr
```

### vs. Python Version
| | Python | Rust |
|-|--------|------|
| Server | Flask + Gunicorn (2 workers) | Axum + Tokio (async, multi-threaded) |
| Binary | `python server.py` | Single compiled binary |
| Deps | `pip install -r requirements.txt` | Compiled into binary |
| Memory | ~50 MB (Python interpreter) | ~5 MB (native binary) |
| Startup | ~2s | ~50ms |

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `10000` | Server listen port |
| `RUST_LOG` | `info` | Log level filter |

---

## Requirements

- `openssl` (for `ts` command — creates RFC 3161 requests)
- `curl` (sends timestamp request to freetsa.org)
- Both are available by default on most Linux distributions and on Render

---

<p align="center">
  <strong>X-Loop³ Labs</strong> · Kreuzlingen, Switzerland · Patent Pending<br>
  <em>Built with 🦀 Rust</em>
</p>
