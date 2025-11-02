"""
IP Address Resolver Utility
Resolves IP addresses for domains and provides DNS information
"""

import socket
import dns.resolver
import sys

def resolve_ip(domain: str) -> dict:
    """Resolve IP address and DNS information for a domain"""
    result = {
        "domain": domain,
        "ipv4": None,
        "ipv6": None,
        "all_ips": [],
        "error": None
    }
    
    try:
        # IPv4 resolution
        try:
            ipv4 = socket.gethostbyname(domain)
            result["ipv4"] = ipv4
            result["all_ips"].append(ipv4)
        except socket.gaierror:
            pass
        
        # Try to get all IPs using socket.getaddrinfo
        try:
            addrinfo = socket.getaddrinfo(domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            for info in addrinfo:
                ip = info[4][0]
                if ip not in result["all_ips"]:
                    result["all_ips"].append(ip)
                    if ':' in ip:  # IPv6
                        result["ipv6"] = ip
        except:
            pass
            
        # Try DNS resolver for more info
        try:
            import dns.resolver
            answers = dns.resolver.resolve(domain, 'A')
            for rdata in answers:
                if rdata.address not in result["all_ips"]:
                    result["all_ips"].append(rdata.address)
        except:
            pass
            
    except Exception as e:
        result["error"] = str(e)
    
    return result

def get_ip_info(domain: str) -> dict:
    """Get comprehensive IP and DNS information"""
    info = resolve_ip(domain)
    
    # Add reverse DNS
    if info["ipv4"]:
        try:
            hostname, aliases, ipaddrs = socket.gethostbyaddr(info["ipv4"])
            info["reverse_dns"] = hostname
            info["aliases"] = aliases
        except:
            pass
    
    return info

