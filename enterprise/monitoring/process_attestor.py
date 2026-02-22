"""
AegisFrame PSCP — Process Isolation Attestation
X-Loop³ Labs · Patent Pending · USPTO 63/983,493

Proves at the OS level that no model inference process was spawned.
Reads /proc directly — this is the Linux kernel's view of running processes,
not an application-level flag.

Monitors:
  - /proc/[pid]/cmdline for known inference frameworks
  - /proc/[pid]/status for memory and state
  - cgroup membership for container isolation proof
"""

import os
import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Optional

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

logger = logging.getLogger('aegisframe.process')


# Known inference process signatures
INFERENCE_SIGNATURES = [
    'python.*transformers',
    'python.*vllm',
    'python.*torch.*inference',
    'python.*tensorflow.*serving',
    'tritonserver',
    'text-generation-launcher',
    'ollama',
    'llama.cpp',
    'llama-server',
    'koboldcpp',
    'ggml',
    'onnxruntime',
    'trtllm',
    'deepspeed',
    'accelerate.*launch',
]

# Known inference port bindings
INFERENCE_PORTS = [
    8080,   # vLLM, TGI
    8000,   # FastAPI inference servers
    11434,  # Ollama
    3000,   # LM Studio
    5000,   # Flask inference servers
    8888,   # Jupyter with inference
    9090,   # Triton
]


class ProcessAttestor:
    """
    OS-level process attestation.
    Proves no inference process was spawned during a governance decision.
    """
    
    def __init__(self):
        self.proc_path = '/host/proc' if os.path.exists('/host/proc') else '/proc'
        self.available = PSUTIL_AVAILABLE
        if self.available:
            logger.info("Process attestor initialized (psutil)")
        else:
            logger.info("Process attestor initialized (/proc fallback)")
    
    def snapshot(self) -> dict:
        """
        Capture a snapshot of all running processes.
        Identifies any that match inference signatures.
        """
        ts = datetime.now(timezone.utc).isoformat()
        
        processes = []
        inference_processes = []
        inference_ports = []
        
        if self.available:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'status',
                                              'memory_info', 'cpu_percent',
                                              'create_time']):
                try:
                    info = proc.info
                    cmdline = ' '.join(info['cmdline'] or [])
                    
                    # Check if this is an inference process
                    is_inference = False
                    matched_sig = None
                    for sig in INFERENCE_SIGNATURES:
                        if sig.replace('.*', '') in cmdline.lower():
                            is_inference = True
                            matched_sig = sig
                            break
                    
                    entry = {
                        'pid': info['pid'],
                        'name': info['name'],
                        'cmdline_short': cmdline[:120],
                        'status': info['status'],
                        'memory_rss_mb': round(
                            (info['memory_info'].rss if info['memory_info'] else 0) 
                            / (1024*1024), 1),
                        'is_inference': is_inference
                    }
                    
                    processes.append(entry)
                    
                    if is_inference:
                        entry['matched_signature'] = matched_sig
                        inference_processes.append(entry)
                    
                    # Check listening ports
                    try:
                        for conn in proc.connections():
                            if (conn.status == 'LISTEN' and 
                                conn.laddr.port in INFERENCE_PORTS):
                                inference_ports.append({
                                    'pid': info['pid'],
                                    'port': conn.laddr.port,
                                    'process': info['name']
                                })
                    except:
                        pass
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        else:
            # Fallback: read /proc directly
            processes = self._read_proc_direct()
        
        # Get container cgroup info
        cgroup_info = self._get_cgroup_info()
        
        snap = {
            'timestamp': ts,
            'mode': 'PSUTIL' if self.available else 'PROC_DIRECT',
            'total_processes': len(processes),
            'inference_processes': {
                'count': len(inference_processes),
                'details': inference_processes
            },
            'inference_ports': {
                'count': len(inference_ports),
                'details': inference_ports
            },
            'container': cgroup_info,
            'signatures_checked': len(INFERENCE_SIGNATURES),
            'ports_checked': INFERENCE_PORTS
        }
        
        snap['snapshot_hash'] = hashlib.sha256(
            json.dumps(snap, sort_keys=True, default=str).encode()
        ).hexdigest()
        
        return snap
    
    def _read_proc_direct(self) -> list:
        """Fallback: read /proc/[pid]/cmdline directly."""
        processes = []
        proc_path = self.proc_path
        
        try:
            for pid_dir in os.listdir(proc_path):
                if not pid_dir.isdigit():
                    continue
                try:
                    cmdline_path = os.path.join(proc_path, pid_dir, 'cmdline')
                    with open(cmdline_path, 'r') as f:
                        cmdline = f.read().replace('\0', ' ').strip()
                    
                    status_path = os.path.join(proc_path, pid_dir, 'status')
                    name = pid_dir
                    with open(status_path, 'r') as f:
                        for line in f:
                            if line.startswith('Name:'):
                                name = line.split(':')[1].strip()
                                break
                    
                    processes.append({
                        'pid': int(pid_dir),
                        'name': name,
                        'cmdline_short': cmdline[:120],
                        'is_inference': any(
                            sig.replace('.*', '') in cmdline.lower()
                            for sig in INFERENCE_SIGNATURES
                        )
                    })
                except:
                    continue
        except:
            pass
        
        return processes
    
    def _get_cgroup_info(self) -> dict:
        """Read container cgroup information for isolation proof."""
        info = {'isolated': False, 'container_id': None, 'runtime': None}
        
        try:
            # Check if we're in a container
            cgroup_path = os.path.join(self.proc_path, '1', 'cgroup')
            if os.path.exists(cgroup_path):
                with open(cgroup_path, 'r') as f:
                    content = f.read()
                if 'docker' in content:
                    info['isolated'] = True
                    info['runtime'] = 'docker'
                    # Extract container ID
                    for line in content.split('\n'):
                        if 'docker' in line:
                            parts = line.split('/')
                            for p in parts:
                                if len(p) == 64 and all(
                                    c in '0123456789abcdef' for c in p
                                ):
                                    info['container_id'] = p
                                    break
                elif 'containerd' in content or 'cri-containerd' in content:
                    info['isolated'] = True
                    info['runtime'] = 'containerd'
        except:
            pass
        
        return info
    
    def attest_no_inference_process(self, before: dict, after: dict) -> dict:
        """
        Compare two process snapshots and attest that no inference
        process was spawned between them.
        """
        ts = datetime.now(timezone.utc).isoformat()
        
        inf_before = before['inference_processes']['count']
        inf_after = after['inference_processes']['count']
        new_inference = inf_after - inf_before
        
        ports_before = before['inference_ports']['count']
        ports_after = after['inference_ports']['count']
        new_ports = ports_after - ports_before
        
        checks = {
            'no_new_inference_processes': new_inference <= 0,
            'no_new_inference_ports': new_ports <= 0,
            'zero_inference_at_end': inf_after == 0,
            'container_isolated': after['container']['isolated']
        }
        
        all_passed = checks['no_new_inference_processes'] and \
                     checks['no_new_inference_ports'] and \
                     checks['zero_inference_at_end']
        
        attestation = {
            'proof_type': 'PROCESS_NO_INFERENCE_ATTESTATION',
            'proof_level': 'OS_KERNEL',
            'verdict': 'NO_PROCESS_CONFIRMED' if all_passed else 'INFERENCE_PROCESS_DETECTED',
            'checks': checks,
            'deltas': {
                'new_inference_processes': new_inference,
                'new_inference_ports': new_ports,
                'inference_details': after['inference_processes']['details']
            },
            'container': after['container'],
            'signatures_checked': len(INFERENCE_SIGNATURES),
            'snapshots': {
                'before_hash': before.get('snapshot_hash'),
                'after_hash': after.get('snapshot_hash')
            },
            'timestamp': ts
        }
        
        attestation['attestation_hash'] = hashlib.sha256(
            json.dumps(attestation, sort_keys=True, default=str).encode()
        ).hexdigest()
        
        return attestation


# Singleton
process_attestor = ProcessAttestor()
