import os
import subprocess
import re
import socket

def safe_run(args, timeout=30, cwd=None):
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout, cwd=cwd or os.getcwd())
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Timeout expired"
    except Exception as e:
        return -1, "", str(e)

def run_and_parse(target: str, raw_dir: str) -> dict:
    # Extract domain from target
    domain = target.split('/')[-1].split(':')[0]
    
    args = ["nslookup", domain]
    rc, stdout, stderr = safe_run(args)
    
    # Also try socket resolution for IP
    resolved_ips = []
    try:
        ip = socket.gethostbyname(domain)
        resolved_ips.append(ip)
    except:
        pass
    
    # Try to get all IPs
    all_ips = []
    try:
        addrinfo = socket.getaddrinfo(domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for info in addrinfo:
            ip = info[4][0]
            if ip not in all_ips:
                all_ips.append(ip)
    except:
        pass
    
    findings = {
        "success": rc == 0,
        "error": stderr if rc != 0 else None,
        "target": domain,
        "raw": stdout,
        "addresses": [],
        "resolved_ips": resolved_ips,
        "all_ips": all_ips,
        "nameservers": []
    }
    
    # Extract IPs from nslookup output
    nslookup_ips = re.findall(r'Address:\s*(\S+)', stdout)
    findings["addresses"] = list(set(nslookup_ips + resolved_ips))
    
    # Extract nameservers
    for line in stdout.splitlines():
        if "Server:" in line and "Address:" not in line:
            ns = line.split("Server:")[-1].strip().split()[0]
            if ns not in findings["nameservers"]:
                findings["nameservers"].append(ns)
    
    return findings