import os
import shutil
import socket
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from urllib.parse import urlparse


def _normalize_target(target: str) -> str:
    # Accept domain or URL; return hostname/IP
    if target.startswith("http://") or target.startswith("https://"):
        parsed = urlparse(target)
        host = parsed.netloc or parsed.path
        return host.split(":")[0]
    return target


def _find_nmap() -> str | None:
    return shutil.which("nmap")


def _parse_nmap_xml(xml_path: str):
    hosts = []
    open_ports_total = 0
    resolved_ip = None
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        for host in root.findall("host"):
            # Address
            addr = None
            for a in host.findall("address"):
                if a.get("addrtype") == "ipv4":
                    addr = a.get("addr")
                    if not resolved_ip:
                        resolved_ip = addr
                    break

            ports_node = host.find("ports")
            ports = []
            if ports_node is not None:
                for p in ports_node.findall("port"):
                    state = p.find("state")
                    if state is not None and state.get("state") == "open":
                        service = p.find("service")
                        name = None
                        if service is not None:
                            product = service.get("product") or ""
                            ver = service.get("version") or ""
                            svcname = service.get("name") or ""
                            if product or ver:
                                name = (product + " " + ver).strip()
                            else:
                                name = svcname
                        ports.append({
                            "port": int(p.get("portid")),
                            "protocol": p.get("protocol"),
                            "service": name or "unknown",
                        })
                open_ports_total += len(ports)
            hosts.append({
                "address": addr,
                "ports": ports,
            })
    except Exception:
        pass
    return hosts, open_ports_total, resolved_ip


def run_and_parse(target: str, raw_dir: str) -> dict:
    target_host = _normalize_target(target)

    # Resolve IP (best effort)
    resolved_ip = None
    try:
        resolved_ip = socket.gethostbyname(target_host)
    except Exception:
        pass

    nmap_path = _find_nmap()
    if not nmap_path:
        return {
            "success": False,
            "error": "nmap not found in PATH",
            "hosts": [],
            "open_ports_count": 0,
            "resolved_ip": resolved_ip,
        }

    os.makedirs(raw_dir, exist_ok=True)
    with tempfile.NamedTemporaryFile(prefix="nmap_", suffix=".xml", delete=False, dir=raw_dir) as tmp:
        xml_out = tmp.name

    # Fast, common scan: top ports and service detection
    args = [
        nmap_path,
        "-Pn",            # no ping
        "-sS",            # SYN scan
        "-sV",            # version detection
        "--top-ports", "1000",
        "-T4",
        "-oX", xml_out,
        target_host,
    ]

    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=300, cwd=os.getcwd())
        rc = proc.returncode
        if rc != 0:
            # Still attempt to parse if file exists
            pass
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": "nmap timeout",
            "hosts": [],
            "open_ports_count": 0,
            "resolved_ip": resolved_ip,
        }

    hosts, open_ports_total, first_ip = _parse_nmap_xml(xml_out)
    if not resolved_ip and first_ip:
        resolved_ip = first_ip

    return {
        "success": True,
        "error": None,
        "hosts": hosts,
        "open_ports_count": open_ports_total,
        "resolved_ip": resolved_ip,
    }
