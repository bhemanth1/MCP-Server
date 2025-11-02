"""
Enhanced Gobuster Scanner with Python Fallback
Handles HTTP/HTTPS scanning with multiple methods
"""

import os
import subprocess
import json
import re
import shutil
import sys
import socket
import time
import requests
import urllib3
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

# Disable SSL warnings for requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
requests.packages.urllib3.disable_warnings()

sys.path.insert(0, os.path.dirname(__file__))
from tool_wrapper import find_tool_executable, prepare_tool_command

WORDLIST = [
    "admin", "administrator", "autodiscover", "backup", "bin", "cgi-bin",
    "config", "db", "dev", "etc", "home", "images", "info", "js", "login",
    "log", "mail", "news", "private", "public", "read", "sadmin", "secret",
    "server", "srv", "ssh", "ssl", "store", "tmp", "tools", "uploads",
    "wp-admin", "wp-content", "wp-includes", "dashboard", "api", "v1", "test", "status"
]

def python_dir_scan(base_url: str, wordlist: list, timeout: int = 3) -> list:
    """Python-based directory scanning fallback using requests"""
    results = []
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    })
    
    interesting_status = {200, 201, 301, 302, 307, 401, 403, 405}
    
    for path in wordlist[:40]:  # Limit to first 40 for faster scanning
        try:
            url = urljoin(base_url.rstrip('/'), '/' + path.lstrip('/'))
            response = session.get(
                url,
                allow_redirects=False,
                timeout=timeout,
                verify=False,
                stream=True  # Don't download full content
            )
            
            if response.status_code in interesting_status:
                results.append({
                    "path": path,
                    "status": response.status_code,
                    "size": int(response.headers.get('Content-Length', 0)),
                    "url": url
                })
        except requests.exceptions.Timeout:
            continue
        except requests.exceptions.SSLError:
            # Try HTTP if HTTPS fails
            if base_url.startswith('https://'):
                try:
                    http_url = base_url.replace('https://', 'http://')
                    url = urljoin(http_url.rstrip('/'), '/' + path.lstrip('/'))
                    response = session.get(url, allow_redirects=False, timeout=timeout, verify=False, stream=True)
                    if response.status_code in interesting_status:
                        results.append({
                            "path": path,
                            "status": response.status_code,
                            "size": int(response.headers.get('Content-Length', 0)),
                            "url": url
                        })
                except:
                    pass
            continue
        except requests.exceptions.RequestException:
            continue
        except Exception:
            continue
    
    return results

def safe_run(args, timeout=300, cwd=None):
    try:
        tool_name = args[0] if args else None
        executable, cmd_args = prepare_tool_command(tool_name, args[1:] if len(args) > 1 else [])
        
        if not executable:
            tool_path = shutil.which(tool_name)
            if not tool_path:
                go_bin = os.path.join(os.environ.get("USERPROFILE", ""), "go", "bin")
                exe_path = os.path.join(go_bin, f"{tool_name}.exe")
                if os.path.exists(exe_path):
                    executable = exe_path
                    cmd_args = args[1:]
                else:
                    return None, "", "Tool not found, will use Python fallback"
            else:
                executable = tool_path
                cmd_args = args[1:]
        
        final_args = [executable] + cmd_args if cmd_args else [executable]
        proc = subprocess.run(final_args, capture_output=True, text=True, timeout=timeout, cwd=cwd or os.getcwd())
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return None, "", "Timeout - will use Python fallback"
    except FileNotFoundError:
        return None, "", "Not found - will use Python fallback"
    except Exception as e:
        return None, "", str(e)

def run_and_parse(target: str, raw_dir: str) -> dict:
    # Normalize target URL
    if not target.startswith(('http://', 'https://')):
        target = f"https://{target}"
    
    parsed = urlparse(target)
    domain = parsed.netloc or parsed.path
    base_url = f"{parsed.scheme}://{domain}" if parsed.scheme else f"https://{domain}"
    
    wl_path = os.path.join(raw_dir, "gobuster_wl.txt")
    with open(wl_path, "w") as f:
        f.write("\n".join(WORDLIST) + "\n")
    
    # Resolve IP
    target_ip = None
    try:
        target_ip = socket.gethostbyname(domain.split(':')[0])
    except:
        pass
    
    findings = {
        "success": False,
        "error": None,
        "target": domain,
        "target_url": base_url,
        "target_ip": target_ip,
        "directories": [],
        "interesting_count": 0,
        "method_used": "none"
    }
    
    # Use Python-based scanning directly (faster and more reliable)
    findings["method_used"] = "python_requests"
    try:
        # Try HTTPS first, then HTTP
        python_results = python_dir_scan(base_url, WORDLIST, timeout=3)
        
        # If no results from HTTPS, try HTTP
        if len(python_results) == 0 and base_url.startswith('https://'):
            http_url = base_url.replace('https://', 'http://')
            python_results = python_dir_scan(http_url, WORDLIST, timeout=3)
        
        findings["directories"] = python_results
        findings["interesting_count"] = len(python_results)
        findings["success"] = True if len(python_results) > 0 else True  # Success even if no dirs found
    except Exception as e:
        findings["error"] = f"Python scanning failed: {str(e)}"
        findings["success"] = False
    
    return findings

