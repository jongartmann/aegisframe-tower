#!/bin/bash
# ============================================================
# AegisFrame PSCP — EC2 GPU Instance Setup
# X-Loop³ Labs · Kreuzlingen, Switzerland
#
# Target: AWS g5.xlarge (NVIDIA A10G)
# OS: Ubuntu 22.04 LTS
#
# Run: chmod +x setup_ec2.sh && sudo ./setup_ec2.sh
# ============================================================

set -e

echo "═══════════════════════════════════════════════"
echo "  AegisFrame PSCP — GPU Proof Stack Setup"
echo "  X-Loop³ Labs"
echo "═══════════════════════════════════════════════"

# Update system
echo "[1/6] Updating system..."
apt-get update && apt-get upgrade -y

# Install NVIDIA drivers
echo "[2/6] Installing NVIDIA drivers..."
apt-get install -y linux-headers-$(uname -r)
# Use the Ubuntu NVIDIA driver package
apt-get install -y nvidia-driver-535 nvidia-utils-535

# Install Docker
echo "[3/6] Installing Docker..."
apt-get install -y ca-certificates curl gnupg
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Install NVIDIA Container Toolkit
echo "[4/6] Installing NVIDIA Container Toolkit..."
curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey | gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg
curl -s -L https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list | \
    sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' | \
    tee /etc/apt/sources.list.d/nvidia-container-toolkit.list
apt-get update
apt-get install -y nvidia-container-toolkit
nvidia-ctk runtime configure --runtime=docker
systemctl restart docker

# Install eBPF tools (on host for kernel access)
echo "[5/6] Installing eBPF tools..."
apt-get install -y bpfcc-tools bpftrace linux-tools-$(uname -r) linux-tools-common

# Verify
echo "[6/6] Verifying installation..."
echo ""
echo "NVIDIA Driver:"
nvidia-smi --query-gpu=name,driver_version,memory.total --format=csv
echo ""
echo "Docker:"
docker --version
echo ""
echo "NVIDIA Container Runtime:"
docker run --rm --gpus all nvidia/cuda:12.2.0-base-ubuntu22.04 nvidia-smi --query-gpu=name --format=csv,noheader
echo ""
echo "eBPF:"
bpftrace --version

echo ""
echo "═══════════════════════════════════════════════"
echo "  ✅ Setup complete!"
echo ""
echo "  Next steps:"
echo "  1. cd /home/ubuntu/aegisframe-gpu-proof"
echo "  2. docker compose up --build"
echo "  3. Open http://<EC2-PUBLIC-IP>:10000"
echo ""
echo "  API endpoints:"
echo "  GET  /api/v1/pscp/status      — PSCP capabilities"
echo "  POST /api/v1/pscp/prove       — Generate hardware proof"
echo "  POST /api/v1/pscp/prove/full  — Proof + TSA anchor"
echo "  GET  /api/v1/pscp/trail       — Proof trail"
echo "  POST /api/v1/tsa/anchor       — RFC 3161 timestamp"
echo "═══════════════════════════════════════════════"
