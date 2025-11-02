"""
Tool Availability Checker
Checks if scanning tools are installed and provides installation guidance
"""

import os
import shutil
import platform
import subprocess

TOOL_INSTALL_GUIDES = {
    "nmap": {
        "windows": "Download from https://nmap.org/download.html or install via: choco install nmap",
        "linux": "sudo apt-get install nmap  # Debian/Ubuntu\nsudo yum install nmap  # RHEL/CentOS",
        "macos": "brew install nmap",
        "check_command": ["nmap", "--version"]
    },
    "subfinder": {
        "windows": "Install Go first: https://golang.org/dl/\nThen: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest\nAdd Go bin to PATH",
        "linux": "Install Go, then: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "macos": "brew install go\nThen: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "check_command": ["subfinder", "-version"]
    },
    "nikto": {
        "windows": "Download from https://github.com/sullo/nikto or use WSL (Windows Subsystem for Linux)\nOr: choco install nikto (if available)",
        "linux": "sudo apt-get install nikto  # Debian/Ubuntu\nsudo yum install nikto  # RHEL/CentOS",
        "macos": "brew install nikto",
        "check_command": ["nikto", "-Version"]
    },
    "gobuster": {
        "windows": "Install Go first: https://golang.org/dl/\nThen: go install github.com/OJ/gobuster/v3@latest\nAdd Go bin to PATH",
        "linux": "Install Go, then: go install github.com/OJ/gobuster/v3@latest",
        "macos": "brew install gobuster\nOr: go install github.com/OJ/gobuster/v3@latest",
        "check_command": ["gobuster", "-h"]
    },
    "nslookup": {
        "windows": "Built-in Windows tool (nslookup.exe)",
        "linux": "Usually pre-installed (dnsutils package)",
        "macos": "Built-in macOS tool",
        "check_command": ["nslookup", "-?"] if platform.system() == "Windows" else ["nslookup"]
    },
    "traceroute": {
        "windows": "Built-in Windows tool (tracert.exe)",
        "linux": "sudo apt-get install traceroute  # Usually pre-installed",
        "macos": "Built-in macOS tool",
        "check_command": ["tracert"] if platform.system() == "Windows" else ["traceroute", "-h"]
    }
}

def check_tool_available(tool_name: str) -> dict:
    """Check if a tool is available in the system PATH"""
    result = {
        "available": False,
        "path": None,
        "version": None,
        "error": None,
        "install_guide": None
    }
    
    # Get install guide for current OS
    system = platform.system()
    os_key = "windows" if system == "Windows" else ("macos" if system == "Darwin" else "linux")
    
    tool_info = TOOL_INSTALL_GUIDES.get(tool_name.lower())
    if not tool_info:
        result["error"] = f"Unknown tool: {tool_name}"
        return result
    
    result["install_guide"] = tool_info.get(os_key, "Tool installation guide not available for this OS")
    
    # Check if tool exists in PATH
    tool_path = shutil.which(tool_name)
    if tool_path:
        result["available"] = True
        result["path"] = tool_path
        
        # Try to get version
        check_cmd = tool_info.get("check_command", [tool_name, "--version"])
        try:
            proc = subprocess.run(check_cmd, capture_output=True, text=True, timeout=5)
            if proc.returncode == 0:
                result["version"] = proc.stdout.split('\n')[0].strip()
        except:
            pass
    else:
        result["error"] = f"{tool_name} not found in PATH"
    
    return result

def check_all_tools() -> dict:
    """Check availability of all scanning tools"""
    tools_status = {}
    for tool_name in ["nmap", "subfinder", "nikto", "gobuster", "nslookup", "traceroute"]:
        tools_status[tool_name] = check_tool_available(tool_name)
    return tools_status


