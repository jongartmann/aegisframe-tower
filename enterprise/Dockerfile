# ============================================================
# AegisFrame PSCP Hardware Proof Container
# X-Loop³ Labs · Patent Pending · USPTO 63/983,493
#
# Proves Pre-Semantic control via:
#   1. NVML GPU counter attestation
#   2. eBPF kernel-level socket monitoring  
#   3. Process isolation proof via /proc + cgroups
# ============================================================

FROM nvidia/cuda:12.2.0-base-ubuntu22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# System deps: eBPF tools, openssl (for TSA), curl, python
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-dev \
    bpfcc-tools bpftrace linux-headers-generic \
    openssl curl procps iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Python deps
COPY requirements.txt /app/requirements.txt
RUN pip3 install --no-cache-dir -r /app/requirements.txt

# App code
COPY api/ /app/api/
COPY monitoring/ /app/monitoring/
COPY server.py /app/server.py
COPY static/ /app/static/

WORKDIR /app

# eBPF needs privileged or CAP_BPF + CAP_SYS_ADMIN
# GPU needs --gpus all
# Both set in docker-compose.yml

EXPOSE 10000

CMD ["gunicorn", "server:app", "--bind", "0.0.0.0:10000", "--workers", "2", "--timeout", "30"]
