"""
Tool Wrapper - Handles different execution methods for tools
Provides fallback options and Windows-specific handling
"""

import os
import subprocess
import platform
import shutil

def find_tool_executable(tool_name: str) -> str:
    """Find tool executable with fallbacks"""
    # Direct check
    tool_path = shutil.which(tool_name)
    if tool_path:
        return tool_path
    
    # Windows-specific fallbacks
    if platform.system() == "Windows":
        # Check common installation paths
        if tool_name == "nikto":
            # Try WSL
            if shutil.which("wsl"):
                return "wsl nikto"
            
            # Try local installation
            local_paths = [
                os.path.join(os.environ.get("USERPROFILE", ""), "tools", "nikto", "nikto-master", "program", "nikto.pl"),
                os.path.join("C:", "tools", "nikto", "nikto-master", "program", "nikto.pl"),
            ]
            for path in local_paths:
                if os.path.exists(path):
                    perl_path = shutil.which("perl")
                    if perl_path:
                        return f'{perl_path} "{path}"'
        
        # Check Go bin path
        go_bin = os.path.join(os.environ.get("USERPROFILE", ""), "go", "bin")
        if tool_name in ["subfinder", "gobuster"]:
            exe_path = os.path.join(go_bin, f"{tool_name}.exe")
            if os.path.exists(exe_path):
                return exe_path
    
    return None

def prepare_tool_command(tool_name: str, args: list) -> tuple:
    """
    Prepare command for tool execution
    Returns: (executable_path, command_args)
    """
    executable = find_tool_executable(tool_name)
    
    if not executable:
        return None, args
    
    # Handle WSL commands
    if executable.startswith("wsl "):
        # Split WSL command
        parts = executable.split(" ", 1)
        wsl_args = ["wsl"] + [parts[1]] + args
        return "wsl", wsl_args
    
    # Handle Perl scripts
    if executable.endswith(".pl") or "perl" in executable.lower():
        # Extract perl and script path
        if '"' in executable:
            parts = executable.split('"')
            perl_exe = parts[0].strip()
            script_path = parts[1]
            return perl_exe, [script_path] + args
    
    # Standard executable
    return executable, args


