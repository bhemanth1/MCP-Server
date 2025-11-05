"""
Enhanced Subfinder with DNS Python fallback
"""

import os
import subprocess
import json
import shutil
import sys
import socket
from pathlib import Path

# Optional DNS resolver
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

sys.path.insert(0, os.path.dirname(__file__))
from tool_wrapper import find_tool_executable, prepare_tool_command

def python_subdomain_scan(domain: str) -> list:
    """Python-based subdomain discovery using DNS - comprehensive wordlist"""
    subdomains = []
    
    # Comprehensive subdomain wordlist
    common_subdomains = [
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
        "admin", "blog", "pop3", "imap", "vpn", "ns", "www2", "http", "https", "m",
        "shop", "mail2", "test", "ns2", "news", "demo", "wap", "mx",
        "exchange", "direct", "forums", "images", "img", "www1", "intranet", "portal",
        "video", "sip", "dns2", "api", "cdn", "stats", "dns1", "ns3", "smtp2",
        "www3", "ns4", "www4", "secure", "forum", "server", "mx2", "chat", "cdn2",
        "api2", "ads", "admin2", "srv", "ads2", "host", "cms", "app", "dev", "mx1",
        # Additional common subdomains
        "staging", "prod", "production", "qa", "test", "dev2", "preprod", "demo2",
        "www5", "www6", "beta", "alpha", "internal", "external", "extranet", "intranet",
        "mobile", "web", "site", "www-site", "old", "new", "legacy", "backup",
        "download", "upload", "files", "static", "assets", "media", "content",
        "support", "help", "docs", "documentation", "wiki", "kb", "knowledgebase",
        "dashboard", "panel", "control", "controlpanel", "cpanel", "whm",
        "webmin", "phpmyadmin", "mysql", "db", "database", "sql",
        "mail1", "mail3", "email", "smtp1", "smtp3", "imap1", "imap2",
        "pop1", "pop2", "pop3", "smtp", "imap", "exchange", "owa", "outlook",
        "git", "svn", "cvs", "repo", "repository", "code", "source",
        "ci", "jenkins", "build", "deploy", "automation", "pipeline",
        "monitor", "monitoring", "nagios", "zabbix", "grafana", "prometheus",
        "logs", "log", "logging", "syslog", "audit",
        "backup1", "backup2", "backups", "archive", "archives",
        "crm", "erp", "portal", "intranet", "extranet",
        "api3", "api4", "rest", "graphql", "websocket", "ws",
        "cdn3", "cdn4", "static1", "static2", "media1", "media2",
        "cache", "cache1", "cache2", "redis", "memcached",
        "lb", "loadbalancer", "load", "balancer",
        "www-old", "www-new", "www-test", "www-dev", "www-staging",
        "mail-old", "mail-new", "webmail1", "webmail2",
        "auth", "auth1", "auth2", "sso", "login", "logout", "signin", "signup",
        "www7", "www8", "www9", "www10",
        "ns5", "ns6", "ns7", "ns8",
        "dns3", "dns4", "dns5", "dns6"
    ]
    
    for sub in common_subdomains:
        try:
            subdomain = f"{sub}.{domain}"
            socket.gethostbyname(subdomain)
            subdomains.append(subdomain)
        except:
            continue
    
    # Try DNS enumeration (if dnspython is available)
    if DNS_AVAILABLE:
        try:
            answers = dns.resolver.resolve(domain, 'NS')
            for rdata in answers:
                ns_domain = str(rdata.target).rstrip('.')
                if ns_domain not in subdomains:
                    subdomains.append(ns_domain)
        except:
            pass
    
    return subdomains

def safe_run(args, timeout=120, cwd=None):
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
    import socket
    from urllib.parse import urlparse
    
    # Robustly extract domain from either a plain domain or a full URL
    parsed = urlparse(target if '://' in target else f"https://{target}")
    host = parsed.netloc or parsed.path
    domain = host.split(':')[0].replace('www.', '')
    
    txt_path = os.path.join(raw_dir, "subfinder.txt")
    args = ["subfinder", "-d", domain, "-silent", "-o", txt_path]
    rc, stdout, stderr = safe_run(args, timeout=120)
    
    # Resolve main domain IP
    main_domain_ip = None
    try:
        main_domain_ip = socket.gethostbyname(domain)
    except:
        pass
    
    subdomains = []
    subdomain_ips = {}
    
    # If subfinder worked
    if rc == 0 and os.path.exists(txt_path):
        with open(txt_path, 'r', encoding='utf-8', errors='ignore') as f:
            subdomains = [line.strip() for line in f if line.strip()]
    else:
        # Python fallback
        subdomains = python_subdomain_scan(domain)
        with open(txt_path, 'w', encoding='utf-8') as f:
            f.write("\n".join(subdomains) + "\n")
    
    # Resolve subdomain IPs
    for subdomain in subdomains[:50]:
        try:
            ip = socket.gethostbyname(subdomain)
            subdomain_ips[subdomain] = ip
        except:
            pass
    
    # Compose subdomain details (url + ip)
    scheme = "https"
    subdomain_details = [
        {"subdomain": s, "ip": subdomain_ips.get(s), "url": f"{scheme}://{s}"}
        for s in subdomains
    ]

    findings = {
        "success": True,
        "error": None,
        "main_domain_ip": main_domain_ip,
        "subdomain_ips": subdomain_ips,
        "subdomains": subdomains,
        "subdomain_details": subdomain_details,
        "count": len(subdomains),
        "method_used": "subfinder" if rc == 0 else "python_dns"
    }
    
    return findings

