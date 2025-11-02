import os
import subprocess
import json
import shutil
import sys
sys.path.insert(0, os.path.dirname(__file__))
from tool_wrapper import find_tool_executable, prepare_tool_command

def safe_run(args, timeout=300, cwd=None):
    try:
        # Check if tool exists with wrapper
        tool_name = args[0] if args else None
        executable, cmd_args = prepare_tool_command(tool_name, args[1:] if len(args) > 1 else [])
        
        if not executable:
            # Try direct path
            tool_path = shutil.which(tool_name)
            if not tool_path:
                # For nikto on Windows, skip if WSL not available (don't fail)
                if os.name == 'nt' and tool_name == 'nikto':
                    # Try to find local nikto installation
                    local_nikto = os.path.join(os.environ.get("USERPROFILE", ""), "tools", "nikto", "nikto-master", "program", "nikto.pl")
                    if os.path.exists(local_nikto):
                        perl_path = shutil.which("perl")
                        if perl_path:
                            executable = perl_path
                            cmd_args = [local_nikto] + args[1:]
                        else:
                            return -1, "", f"Tool '{tool_name}' not found. Install Perl or use WSL: wsl sudo apt-get install nikto"
                    elif shutil.which("wsl"):
                        executable = "wsl"
                        cmd_args = ["bash", "-c", f"nikto {' '.join(args[1:])}"]
                    else:
                        return -1, "", f"Tool '{tool_name}' not found. Install via WSL or download from https://github.com/sullo/nikto"
                else:
                    return -1, "", f"Tool '{tool_name}' not found in PATH. Install via: sudo apt-get install nikto (Linux) or download from https://github.com/sullo/nikto"
            else:
                executable = tool_path
                cmd_args = args[1:]
        
        final_args = [executable] + cmd_args if cmd_args else [executable]
        proc = subprocess.run(final_args, capture_output=True, text=True, timeout=timeout, cwd=cwd or os.getcwd())
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Timeout expired"
    except FileNotFoundError as e:
        return -1, "", f"Tool not found: {str(e)}. Install nikto: sudo apt-get install nikto (Linux/WSL) or download from https://github.com/sullo/nikto"
    except Exception as e:
        return -1, "", str(e)

def run_and_parse(target: str, raw_dir: str) -> dict:
    # Always use enhanced Python version
    try:
        from scanners.enhanced_nikto import run_and_parse as enhanced_parse
        return enhanced_parse(target, raw_dir)
    except ImportError:
        # If import fails, use direct import
        import sys
        import os
        sys.path.insert(0, os.path.dirname(__file__))
        from enhanced_nikto import run_and_parse as enhanced_parse
        return enhanced_parse(target, raw_dir)