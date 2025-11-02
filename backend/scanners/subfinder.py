import os
import subprocess
import json
import shutil
import sys
from pathlib import Path
sys.path.insert(0, os.path.dirname(__file__))
from tool_wrapper import find_tool_executable, prepare_tool_command

def safe_run(args, timeout=120, cwd=None):
    try:
        # Check if tool exists with wrapper
        tool_name = args[0] if args else None
        executable, cmd_args = prepare_tool_command(tool_name, args[1:] if len(args) > 1 else [])
        
        if not executable:
            # Try direct path
            tool_path = shutil.which(tool_name)
            if not tool_path:
                # Check Go bin path
                go_bin = os.path.join(os.environ.get("USERPROFILE", ""), "go", "bin")
                exe_path = os.path.join(go_bin, f"{tool_name}.exe")
                if os.path.exists(exe_path):
                    executable = exe_path
                    cmd_args = args[1:]
                else:
                    return -1, "", f"Tool '{tool_name}' not found in PATH. Install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest. Then add {go_bin} to PATH."
            else:
                executable = tool_path
                cmd_args = args[1:]
        
        final_args = [executable] + cmd_args if cmd_args else [executable]
        proc = subprocess.run(final_args, capture_output=True, text=True, timeout=timeout, cwd=cwd or os.getcwd())
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Timeout expired"
    except FileNotFoundError as e:
        go_bin = os.path.join(os.environ.get("USERPROFILE", ""), "go", "bin")
        return -1, "", f"Tool not found: {str(e)}. Install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest. Add {go_bin} to PATH and restart."
    except Exception as e:
        return -1, "", str(e)

def run_and_parse(target: str, raw_dir: str) -> dict:
    # Always use enhanced Python version
    try:
        from scanners.enhanced_subfinder import run_and_parse as enhanced_parse
        return enhanced_parse(target, raw_dir)
    except ImportError:
        # If import fails, use direct import
        import sys
        import os
        sys.path.insert(0, os.path.dirname(__file__))
        from enhanced_subfinder import run_and_parse as enhanced_parse
        return enhanced_parse(target, raw_dir)