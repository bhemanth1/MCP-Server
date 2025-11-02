import os
import subprocess
import json
import shutil
import socket

def safe_run(args, timeout=180, cwd=None):
    try:
        # Check if tool exists
        tool_name = args[0] if args else None
        tool_path = shutil.which(tool_name)
        if not tool_path:
            return -1, "", f"Tool '{tool_name}' not found in PATH. Install via: choco install nmap (Windows) or sudo apt-get install nmap (Linux)"
        
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout, cwd=cwd or os.getcwd())
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Timeout expired"
    except FileNotFoundError as e:
        return -1, "", f"Tool not found: {str(e)}. Install nmap from https://nmap.org/download.html"
    except Exception as e:
        return -1, "", str(e)

def run_and_parse(target: str, raw_dir: str) -> dict:
    # Use advanced Python-based scanner
    try:
        from scanners.advanced_nmap import run_and_parse as advanced_parse
        return advanced_parse(target, raw_dir)
    except ImportError:
        # Fallback to direct import
        import sys
        import os
        sys.path.insert(0, os.path.dirname(__file__))
        from advanced_nmap import run_and_parse as advanced_parse
        return advanced_parse(target, raw_dir)