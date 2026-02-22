# 🛡 AegisFrame — Render Deployment

Standard deployment with real RFC 3161 TSA anchoring.

## Quick Deploy

1. Push this repo to GitHub
2. Go to [Render Dashboard](https://dashboard.render.com)
3. New → Web Service → Connect this repo
4. Root Directory: `render`
5. Build Command: `pip install -r requirements.txt`
6. Start Command: `gunicorn server:app --bind 0.0.0.0:$PORT --workers 2 --timeout 30`
7. Deploy

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /` | AegisFrame Control Tower + Runtime Monitor |
| `POST /api/v1/tsa/anchor` | Real RFC 3161 timestamp (freetsa.org) |
| `GET /api/v1/status` | System status + capabilities |
| `GET /health` | Health check |

## TSA

The RFC 3161 Timestamp Authority call is **real** — not simulated.
The server uses `openssl ts` to create a proper TimeStampReq and sends it
to freetsa.org via HTTP. The response is a cryptographically signed timestamp
token that can be independently verified.

## Architecture

```
Browser → Flask (Gunicorn) → static/index.html
                           → /api/v1/tsa/anchor → openssl ts → freetsa.org/tsr
```

---
X-Loop³ Labs · Kreuzlingen, Switzerland · Patent Pending
