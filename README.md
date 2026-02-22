<p align="center">
  <img src="https://img.shields.io/badge/AegisFrame-v0.6.0--enterprise-0a0e1a?style=for-the-badge&labelColor=12b47a&color=0a0e1a" />
  <img src="https://img.shields.io/badge/USPTO-Patent_Pending-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/EU_AI_Act-Runtime_Compliance-purple?style=for-the-badge" />
  <img src="https://img.shields.io/badge/RFC_3161-TSA_LIVE-green?style=for-the-badge" />
</p>

<h1 align="center">🛡 AegisFrame AI Governance Engine</h1>

<p align="center">
  <strong>Runtime compliance for the EU AI Act. Not a checklist — a living proof engine.</strong><br>
  <em>X-Loop³ Labs · Kreuzlingen, Switzerland</em>
</p>

---

## What is AegisFrame?

AegisFrame is a **runtime AI governance engine** that enforces compliance at the architectural level — before the AI model ever sees a prompt. While competitors offer PDF checklists and static audits, AegisFrame provides **live, cryptographically verifiable evidence** that governance decisions are enforced in real-time.

```
┌─────────────────────────────────────────────────────────────┐
│  USER PROMPT                                                 │
│       ↓                                                      │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  AEGISFRAME PRE-SEMANTIC CONTROL PLANE (PSCP)       │    │
│  │  ┌───────────┐  ┌───────────┐  ┌───────────────┐   │    │
│  │  │ 7 Security│  │ 4 Domain  │  │ Risk Tier     │   │    │
│  │  │ Signals   │  │ Signals   │  │ Classifier    │   │    │
│  │  └─────┬─────┘  └─────┬─────┘  └───────┬───────┘   │    │
│  │        ↓              ↓                ↓            │    │
│  │  ┌─────────────────────────────────────────────┐    │    │
│  │  │  Gate Decision: ALLOW / WARN / DEFEND / LOCK │    │    │
│  │  └───────────────────┬─────────────────────────┘    │    │
│  │                      ↓                              │    │
│  │  Evidence → SHA-256 Chain → ECDSA P-256 Signature   │    │
│  └──────────────────────┬──────────────────────────────┘    │
│                         ↓                                    │
│  ┌──────────┐    ┌──────────────┐                           │
│  │ BLOCKED  │ or │ AI MODEL     │                           │
│  │ (proof)  │    │ (monitored)  │                           │
│  └──────────┘    └──────────────┘                           │
└─────────────────────────────────────────────────────────────┘
```

## Two Products, One Demo

AegisFrame ships as two complementary layers — licensable together or separately:

| Layer | For whom | What it does |
|-------|----------|--------------|
| **🛡 Control Tower** | Developers / Integrators | Per-prompt governance. User types a prompt → sees gates fire, risk scores, mitigations, evidence export in real-time |
| **📊 Runtime Monitor** | Compliance Officers / Auditors | Fleet surveillance. Seismograph, EKG vitals, drift detection, countdown oversight, multi-trail verification |

Both layers share the same evidence spine, the same SHA-256 chain, and the same ECDSA-signed proof trail.

## Architecture

### 7-Layer Governance Stack
```
Layer 7 │ Autonomy Gradient (L0–L5)
Layer 6 │ Proportionality Guarantee
Layer 5 │ Countdown-Not-Auto-Stop (Waymo Paradigm)
Layer 4 │ Risk Tier Classifier (Annex III)
Layer 3 │ Domain Authority Gate (4 independent signals)
Layer 2 │ Security Gate (7 independent signals)
Layer 1 │ Pre-Semantic Structural Control Plane (PSCP)
```

### Evidence Infrastructure
- **SHA-256 Evidence Spine** — Every gate decision, state transition, and oversight action is hashed and chained
- **ECDSA P-256 Actor Signatures** — Three oversight actors with individual key pairs
- **Multi-Trail Architecture** — Trail A (Governance), Trail B (Invocation), Trail C (Auditor)
- **RFC 3161 Timestamp Authority** — Real TSA anchoring via freetsa.org (not simulated)
- **INTEGRITY_ROOT** — Single anchored object binding all trails + policy spec hash

### Countdown-Not-Auto-Stop
The Waymo Paradigm: When risk exceeds threshold, a countdown starts. A human must actively decide (APPROVE or DENY) within the window. If no human acts → **auto-DENY**. The system never auto-allows in high-risk situations. Zero liability.

### Escalation Chain
When oversight is required, alerts cascade through channels with increasing urgency:
```
0s    → SMS + Email to On-Call Technician
4s    → PagerDuty
6s    → Slack
8s    → WhatsApp  
12s   → ServiceNow
60s   → Auto-escalation → Team Lead
120s  → Auto-escalation → CISO
180s  → Auto-escalation → C-Suite Management
```

## Deployments

### `/render` — Render Cloud (Standard)
Simple Flask server with real RFC 3161 TSA. Deploy in 2 minutes.

```
render/
├── server.py           # Flask + RFC 3161 TSA endpoint
├── requirements.txt    # flask + gunicorn
├── render.yaml         # Render auto-deploy config
└── static/
    └── index.html      # AegisFrame Tower + Runtime Monitor
```

### `/enterprise` — EC2 GPU (Hardware Proof)
Docker stack on NVIDIA GPU instance with kernel-level PSCP proof.

```
enterprise/
├── Dockerfile          # NVIDIA CUDA 12.2 + eBPF + Flask
├── docker-compose.yml  # --gpus all + privileged
├── setup_ec2.sh        # One-shot EC2 g5.xlarge setup
├── server.py           # TSA + PSCP Hardware Proof endpoints
├── requirements.txt
├── api/
│   └── pscp_proof.py   # PSCP Proof Engine orchestrator
├── monitoring/
│   ├── gpu_attestor.py     # NVML hardware counter attestation
│   ├── socket_monitor.py   # eBPF kernel socket probe
│   └── process_attestor.py # /proc + cgroup isolation proof
└── static/
    └── index.html
```

## PSCP Hardware Proof

The Pre-Semantic Structural Control Plane (PSCP) produces **hardware-level proof** that governance decisions are enforced before the model:

| Proof Layer | Source | What it proves |
|------------|--------|----------------|
| **GPU Attestation** | NVIDIA NVML driver | Zero compute processes, zero GPU utilization, zero VRAM delta |
| **Socket Attestation** | eBPF kernel probe | Zero bytes sent to any model API endpoint |
| **Process Attestation** | /proc + cgroups | Zero inference processes spawned, container isolated |

Three independent sources. All hardware/OS level. All saying the same thing: **Pre-Semantic.**

```json
{
  "proof_type": "PSCP_HARDWARE_PROOF",
  "verdict": "PSCP_BLOCK_VERIFIED",
  "attestations": {
    "gpu":     { "verdict": "NO_INFERENCE_CONFIRMED",  "proof_level": "HARDWARE_NVML" },
    "socket":  { "verdict": "NO_OUTBOUND_CONFIRMED",   "proof_level": "KERNEL_EBPF" },
    "process": { "verdict": "NO_PROCESS_CONFIRMED",    "proof_level": "OS_KERNEL" }
  }
}
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | AegisFrame UI (Tower + Monitor) |
| `GET` | `/health` | Health check |
| `GET` | `/api/v1/status` | System capabilities |
| `POST` | `/api/v1/tsa/anchor` | RFC 3161 timestamp anchoring |
| `POST` | `/api/v1/pscp/prove` | PSCP hardware proof (Enterprise) |
| `POST` | `/api/v1/pscp/prove/full` | PSCP proof + TSA anchor (Enterprise) |
| `GET` | `/api/v1/pscp/status` | PSCP engine capabilities (Enterprise) |
| `GET` | `/api/v1/pscp/trail` | Append-only proof trail (Enterprise) |

## EU AI Act Coverage

### Basic Mode (mandatory for all AI systems from Aug 2026)
- ✅ Art. 9 — Risk Management (7-Layer Stack)
- ✅ Art. 12 — Record-Keeping (SHA-256 Evidence Spine)
- ✅ Art. 13 — Transparency (Pre-Semantic Proof Panel)
- ✅ Art. 14 — Human Oversight (Countdown-Not-Auto-Stop)
- ✅ Art. 15 — Robustness (EMA Smoothing, Drift Detection)

### High-Risk Extension (Annex III: Medical, HR, Credit, Infrastructure)
- ✅ Art. 6 — Classification Evidence
- ✅ Art. 17 — Quality Management
- ✅ Conformity Assessment
- ✅ ECDSA P-256 Actor Signatures
- ✅ Oversight Token Flow (3-phase)
- ✅ Multi-Trail A/B/C
- ✅ External Audit Verifier
- ✅ Model Adapter Invariants
- ✅ INTEGRITY_ROOT + RFC 3161

## Patents

| # | Title | Filing | Status |
|---|-------|--------|--------|
| 1 | SIREN — Predictive Maintenance for Agricultural Robotics | 63/983,192 | Filed |
| 2 | PSCP — Pre-Semantic Structural Control Plane | 63/983,493 | Filed |
| 3 | MilkMind — Dairy Intelligence Platform | 63/986,414 | Filed |
| 4 | Electric Translator — Pre-Semantic Bidirectional Translation | — | Ready |
| 6 | AegisFrame — Risk-Adaptive AI Governance Engine | — | Ready |

## License

Proprietary · © 2026 X-Loop³ Labs Ltd. · All rights reserved.

---

<p align="center">
  <strong>X-Loop³ Labs</strong><br>
  Kreuzlingen, Switzerland<br>
  <em>Pre-Semantic AI Infrastructure</em>
</p>
