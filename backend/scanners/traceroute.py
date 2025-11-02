import os
import subprocess
import re
import platform
import socket

def safe_run(args, timeout=120, cwd=None):
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout, cwd=cwd or os.getcwd())
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Timeout expired"
    except Exception as e:
        return -1, "", str(e)

def run_and_parse(target: str, raw_dir: str) -> dict:
    # Extract domain/IP from target
    clean_target = target.split('/')[-1].split(':')[0]
    
    # Resolve IP if target is domain
    resolved_ip = None
    if not clean_target.replace('.', '').replace(':', '').isdigit():
        try:
            resolved_ip = socket.gethostbyname(clean_target)
        except:
            pass
    
    system = platform.system()
    if system == "Windows":
        args = ["tracert", "-w", "3000", "-h", "30", clean_target]
    else:
        args = ["traceroute", "-w", "3", "-m", "30", clean_target]
    
    rc, stdout, stderr = safe_run(args)
    
    findings = {
        "success": True,  # traceroute often returns 0 even with timeouts
        "error": stderr,
        "target": clean_target,
        "resolved_ip": resolved_ip,
        "raw": stdout,
        "hops": []
    }
    
    lines = stdout.splitlines()
    for line in lines:
        parts = re.split(r'\s+', line.strip())
        if parts and parts[0].isdigit():
            hop = int(parts[0])
            rtts = []
            i = 1
            while i < len(parts) and len(rtts) < 3:
                rt = parts[i]
                rtts.append('timeout' if rt == '*' else rt)
                i += 1
            ip = parts[-1] if parts[-1] not in ['ms', '*'] else None
            findings["hops"].append({
                "hop": hop,
                "ip": ip,
                "rtts": rtts
            })
    
    findings["hop_count"] = len(findings["hops"])
    return findings