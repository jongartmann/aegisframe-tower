# ⚡ AegisFrame — Enterprise GPU Deployment

Hardware-attested PSCP proof stack on AWS EC2 with NVIDIA GPU.

## What this proves

When AegisFrame blocks a prompt, this stack provides **three independent
hardware/OS-level proofs** that no AI inference occurred:

| Proof | Source | Level |
|-------|--------|-------|
| GPU Counter | NVIDIA NVML | Hardware driver |
| Socket Monitor | eBPF | Linux kernel |
| Process Check | /proc + cgroups | OS kernel |

This is **Patent 2 (PSCP, USPTO 63/983,493)** in action.

## Setup

### 1. Launch EC2 Instance

- **Instance:** g5.xlarge (1x NVIDIA A10G, 24GB VRAM)
- **AMI:** Ubuntu 22.04 LTS
- **Storage:** 50 GB gp3
- **Security Group:** Open port 10000

### 2. Install

```bash
ssh -i your-key.pem ubuntu@<EC2-IP>
git clone https://github.com/YOUR_USER/aegisframe-tower.git
cd aegisframe-tower/enterprise
chmod +x setup_ec2.sh
sudo ./setup_ec2.sh
```

### 3. Run

```bash
docker compose up --build
```

### 4. Access

Open `http://<EC2-IP>:10000`

## API

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/pscp/prove` | Generate hardware proof |
| `POST` | `/api/v1/pscp/prove/full` | Proof + RFC 3161 TSA anchor |
| `GET` | `/api/v1/pscp/status` | Engine capabilities |
| `GET` | `/api/v1/pscp/trail` | Append-only proof trail |
| `POST` | `/api/v1/tsa/anchor` | RFC 3161 timestamp |

## Example Proof Response

```json
{
  "proof_type": "PSCP_HARDWARE_PROOF",
  "proof_id": "PSCP_000001_1740264000",
  "verdict": "PSCP_BLOCK_VERIFIED",
  "attestations": {
    "gpu": {
      "verdict": "NO_INFERENCE_CONFIRMED",
      "proof_level": "HARDWARE_NVML",
      "deltas": {
        "gpu_util_delta_percent": 0,
        "memory_delta_bytes": 0,
        "new_compute_pids": []
      }
    },
    "socket": {
      "verdict": "NO_OUTBOUND_CONFIRMED",
      "proof_level": "KERNEL_EBPF",
      "deltas": {
        "ebpf_bytes_sent": 0,
        "ebpf_connect_calls": 0
      }
    },
    "process": {
      "verdict": "NO_PROCESS_CONFIRMED",
      "proof_level": "OS_KERNEL",
      "deltas": {
        "new_inference_processes": 0,
        "new_inference_ports": 0
      }
    }
  },
  "patent_ref": "USPTO PPA 63/983,493"
}
```

## Cost

| Mode | Instance | Cost |
|------|----------|------|
| Demo (2h) | g5.xlarge Spot | ~$0.60 |
| Monthly (10h) | g5.xlarge Spot | ~$3.00 |
| Always-on | g5.xlarge Reserved 1yr | ~$360/yr |

Recommendation: Use Spot instances, spin up for demos and customer calls only.

---
X-Loop³ Labs · Kreuzlingen, Switzerland · Patent Pending · USPTO 63/983,493
