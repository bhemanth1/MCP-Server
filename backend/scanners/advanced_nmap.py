"""
Advanced Nmap Scanner with Python Port Detection
Uses socket, requests, and subprocess for comprehensive port scanning
"""

import os
import socket
import subprocess
import json
import shutil
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(__file__))
from tool_wrapper import find_tool_executable, prepare_tool_command

# Common ports to scan
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]

def python_port_scan(target: str, ports: list = None, timeout: float = 1.0) -> list:
    """Python-based port scanning using socket"""
    if ports is None:
        ports = COMMON_PORTS
    
    open_ports = []
    target_ip = target.split('/')[-1].split(':')[0]
    
    # Resolve hostname to IP if needed
    try:
        if not target_ip.replace('.', '').isdigit():
            target_ip = socket.gethostbyname(target_ip)
    except:
        pass
    
    def check_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target_ip, port))
            sock.close()
            if result == 0:
                return port
        except:
            pass
        return None
    
    # Scan ports concurrently
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(check_port, port): port for port in ports}
        for future in as_completed(futures):
            port = future.result()
            if port:
                open_ports.append(port)
    
    return sorted(open_ports)

def identify_service(port: int, target: str) -> dict:
    """Identify service running on port"""
    service_map = {
        21: {"service": "ftp", "protocol": "tcp"},
        22: {"service": "ssh", "protocol": "tcp"},
        23: {"service": "telnet", "protocol": "tcp"},
        25: {"service": "smtp", "protocol": "tcp"},
        53: {"service": "dns", "protocol": "tcp"},
        80: {"service": "http", "protocol": "tcp"},
        110: {"service": "pop3", "protocol": "tcp"},
        135: {"service": "msrpc", "protocol": "tcp"},
        139: {"service": "netbios-ssn", "protocol": "tcp"},
        143: {"service": "imap", "protocol": "tcp"},
        443: {"service": "https", "protocol": "tcp"},
        445: {"service": "microsoft-ds", "protocol": "tcp"},
        993: {"service": "imaps", "protocol": "tcp"},
        995: {"service": "pop3s", "protocol": "tcp"},
        1723: {"service": "pptp", "protocol": "tcp"},
        3306: {"service": "mysql", "protocol": "tcp"},
        3389: {"service": "rdp", "protocol": "tcp"},
        5900: {"service": "vnc", "protocol": "tcp"},
        8080: {"service": "http-proxy", "protocol": "tcp"},
        8443: {"service": "https-alt", "protocol": "tcp"},
    }
    
    service_info = service_map.get(port, {"service": "unknown", "protocol": "tcp"})
    
    # Try to get more info via HTTP request for web ports
    if port in [80, 443, 8080, 8443]:
        try:
            import requests
            protocol = "https" if port in [443, 8443] else "http"
            url = f"{protocol}://{target.split('/')[-1].split(':')[0]}:{port}"
            response = requests.get(url, timeout=2, verify=False, allow_redirects=False)
            service_info["product"] = response.headers.get("Server", "")
        except:
            pass
    
    return service_info

def safe_run(args, timeout=180, cwd=None):
    try:
        tool_name = args[0] if args else None
        tool_path = shutil.which(tool_name)
        if not tool_path:
            return -1, "", f"Tool '{tool_name}' not found. Using Python port scanner."
        
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout, cwd=cwd or os.getcwd())
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Timeout expired - using Python scanner"
    except Exception as e:
        return -1, "", str(e)

def run_and_parse(target: str, raw_dir: str) -> dict:
    # Extract domain/IP from target
    clean_target = target.split('/')[-1].split(':')[0]
    
    # Resolve IP if target is domain
    resolved_ip = None
    try:
        if not clean_target.replace('.', '').isdigit():
            resolved_ip = socket.gethostbyname(clean_target)
        else:
            resolved_ip = clean_target
    except:
        resolved_ip = clean_target
    
    findings = {
        "success": False,
        "error": None,
        "target": clean_target,
        "resolved_ip": resolved_ip,
        "hosts": [],
        "services": {},
        "open_ports_count": 0,
        "method_used": "none"
    }
    
    # Try nmap first
    json_path = os.path.join(raw_dir, "nmap.json")
    args = ["nmap", "-sV", "--open", "-oJ", json_path, clean_target]
    rc, stdout, stderr = safe_run(args, timeout=120)
    
    # If nmap worked, parse results
    if rc == 0 and os.path.exists(json_path):
        try:
            with open(json_path, 'r') as f:
                nmap_json = json.load(f)
            if isinstance(nmap_json, list) and len(nmap_json) > 0:
                open_ports = []
                for host_data in nmap_json[1:]:
                    addresses = host_data.get("addresses", [])
                    ip = next((a.get("addr") for a in addresses if a.get("addrtype") == "ipv4"), None)
                    if not ip:
                        ip = resolved_ip
                    ports = host_data.get("ports", [])
                    port_list = []
                    for port in ports:
                        if port.get("state") == "open":
                            service = port.get("service", {})
                            svc_name = service.get("name", "unknown")
                            product = service.get("product", "")
                            port_list.append({
                                "port": int(port["portid"]),
                                "protocol": port.get("protocol", "tcp"),
                                "service": svc_name,
                                "product": product
                            })
                            findings["services"][svc_name] = findings["services"].get(svc_name, 0) + 1
                    if port_list:
                        findings["hosts"].append({"ip": ip, "ports": port_list})
                        findings["open_ports_count"] += len(port_list)
                findings["success"] = True
                findings["method_used"] = "nmap"
                return findings
        except (json.JSONDecodeError, IOError):
            pass
    
    # Python-based port scanning
    findings["method_used"] = "python_socket"
    try:
        open_ports = python_port_scan(clean_target, COMMON_PORTS, timeout=1.0)
        
        if open_ports:
            port_list = []
            for port in open_ports:
                service_info = identify_service(port, clean_target)
                port_list.append({
                    "port": port,
                    "protocol": service_info.get("protocol", "tcp"),
                    "service": service_info.get("service", "unknown"),
                    "product": service_info.get("product", "")
                })
                svc_name = service_info.get("service", "unknown")
                findings["services"][svc_name] = findings["services"].get(svc_name, 0) + 1
            
            findings["hosts"].append({"ip": resolved_ip, "ports": port_list})
            findings["open_ports_count"] = len(port_list)
        
        findings["success"] = True
    except Exception as e:
        findings["error"] = f"Python port scan failed: {str(e)}"
        findings["success"] = False
    
    return findings

