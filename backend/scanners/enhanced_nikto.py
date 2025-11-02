"""
Enhanced Nikto Scanner with Python Fallback
Uses requests + BeautifulSoup for web vulnerability scanning
"""

import os
import subprocess
import json
import shutil
import sys
import socket
import requests
import urllib3
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
requests.packages.urllib3.disable_warnings()

sys.path.insert(0, os.path.dirname(__file__))
from tool_wrapper import find_tool_executable, prepare_tool_command

# Common web vulnerabilities to check
VULN_CHECKS = [
    {"path": "/phpinfo.php", "type": "information_disclosure", "severity": "medium"},
    {"path": "/.git/config", "type": "information_disclosure", "severity": "high"},
    {"path": "/.env", "type": "information_disclosure", "severity": "critical"},
    {"path": "/backup.sql", "type": "information_disclosure", "severity": "high"},
    {"path": "/wp-admin/", "type": "wordpress_admin", "severity": "medium"},
    {"path": "/admin/", "type": "admin_panel", "severity": "medium"},
    {"path": "/config.php", "type": "config_file", "severity": "high"},
    {"path": "/.htaccess", "type": "config_file", "severity": "low"},
]

def python_web_scan(base_url: str) -> list:
    """Python-based web vulnerability scanning"""
    vulnerabilities = []
    session = requests.Session()
    session.timeout = 10
    
    try:
        # Check main page
        response = session.get(base_url, verify=False, timeout=10)
        
        # Check security headers
        security_headers = {
            "X-Frame-Options": "Missing X-Frame-Options header",
            "X-Content-Type-Options": "Missing X-Content-Type-Options header",
            "X-XSS-Protection": "Missing X-XSS-Protection header",
            "Content-Security-Policy": "Missing CSP header",
            "Strict-Transport-Security": "Missing HSTS header"
        }
        
        for header, desc in security_headers.items():
            if header not in response.headers:
                vulnerabilities.append({
                    "url": base_url,
                    "description": desc,
                    "type": "missing_security_header",
                    "severity": "medium",
                    "risk": 1
                })
        
        # Check for common vulnerabilities
        for check in VULN_CHECKS:
            try:
                test_url = urljoin(base_url, check["path"])
                test_response = session.get(test_url, allow_redirects=False, timeout=5, verify=False)
                
                if test_response.status_code in [200, 301, 302, 403]:
                    vulnerabilities.append({
                        "url": test_url,
                        "description": f"{check['type']} found at {check['path']}",
                        "type": check["type"],
                        "severity": check["severity"],
                        "risk": 2 if check["severity"] in ["high", "critical"] else 1
                    })
            except:
                continue
        
        # Parse HTML for issues
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Check for exposed comments
            comments = soup.find_all(string=lambda text: isinstance(text, str) and 'password' in text.lower())
            if comments:
                vulnerabilities.append({
                    "url": base_url,
                    "description": "Potential sensitive information in comments",
                    "type": "information_disclosure",
                    "severity": "low",
                    "risk": 1
                })
        except:
            pass
            
    except Exception as e:
        pass
    
    return vulnerabilities

def safe_run(args, timeout=300, cwd=None):
    try:
        tool_name = args[0] if args else None
        executable, cmd_args = prepare_tool_command(tool_name, args[1:] if len(args) > 1 else [])
        
        if not executable:
            tool_path = shutil.which(tool_name)
            if not tool_path:
                # Try local nikto
                local_nikto = os.path.join(os.environ.get("USERPROFILE", ""), "tools", "nikto", "nikto-master", "program", "nikto.pl")
                if os.path.exists(local_nikto):
                    perl_path = shutil.which("perl")
                    if perl_path:
                        executable = perl_path
                        cmd_args = [local_nikto] + args[1:]
                    else:
                        return None, "", "Will use Python fallback"
                else:
                    return None, "", "Will use Python fallback"
            else:
                executable = tool_path
                cmd_args = args[1:]
        
        final_args = [executable] + cmd_args if cmd_args else [executable]
        proc = subprocess.run(final_args, capture_output=True, text=True, timeout=timeout, cwd=cwd or os.getcwd())
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return None, "", "Timeout - will use Python fallback"
    except Exception:
        return None, "", "Will use Python fallback"

def run_and_parse(target: str, raw_dir: str) -> dict:
    # Normalize target URL
    if not target.startswith(('http://', 'https://')):
        # Try HTTPS first, fallback to HTTP
        target = f"https://{target}"
    
    parsed = urlparse(target)
    domain = parsed.netloc or parsed.path.split('/')[0]
    base_url = f"{parsed.scheme}://{domain}" if parsed.scheme else f"https://{domain}"
    
    findings = {
        "success": False,
        "error": None,
        "vulnerabilities": [],
        "count": 0,
        "high_risk": 0,
        "method_used": "none"
    }
    
    # Try both HTTP and HTTPS
    urls_to_scan = []
    if "https" in base_url.lower():
        urls_to_scan.append(base_url)
        urls_to_scan.append(base_url.replace("https://", "http://"))
    else:
        urls_to_scan.append(base_url)
        urls_to_scan.append(base_url.replace("http://", "https://"))
    
    # Use Python-based scanning directly
    findings["method_used"] = "python_requests"
    all_vulns = []
    
    # Try both HTTP and HTTPS
    for url in urls_to_scan:
        try:
            vulns = python_web_scan(url)
            all_vulns.extend(vulns)
            # If we found vulns, no need to check other URL
            if len(vulns) > 0:
                break
        except Exception as e:
            continue
    
    findings["vulnerabilities"] = all_vulns
    findings["count"] = len(all_vulns)
    findings["high_risk"] = len([v for v in all_vulns if v.get("risk", 0) >= 2])
    findings["success"] = True
    
    return findings

