"""
Scan Architecture Logger
Tracks request/response for each scan step
"""

import os
import json
from datetime import datetime
from typing import Dict, List, Any

class ScanArchitecture:
    """Track scan architecture - requests, responses, and flow"""
    
    def __init__(self, scan_id: str, raw_dir: str):
        self.scan_id = scan_id
        self.raw_dir = raw_dir
        self.architecture = {
            "scan_id": scan_id,
            "start_time": datetime.utcnow().isoformat(),
            "tools": [],
            "flow": [],
            "requests": [],
            "responses": []
        }
    
    def log_tool_start(self, tool_name: str):
        """Log when a tool starts"""
        self.architecture["tools"].append({
            "name": tool_name,
            "start_time": datetime.utcnow().isoformat(),
            "status": "started"
        })
    
    def log_request(self, tool_name: str, method: str, url: str, headers: Dict = None, body: str = None):
        """Log a request"""
        request_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "tool": tool_name,
            "method": method,
            "url": url,
            "headers": headers or {},
            "body": body or ""
        }
        self.architecture["requests"].append(request_data)
        self.architecture["flow"].append({
            "step": f"{tool_name}_request",
            "timestamp": datetime.utcnow().isoformat(),
            "type": "request",
            "data": request_data
        })
    
    def log_response(self, tool_name: str, status_code: int, headers: Dict = None, body: str = None, size: int = 0):
        """Log a response"""
        response_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "tool": tool_name,
            "status_code": status_code,
            "headers": headers or {},
            "body_size": len(body) if body else size,
            "body_preview": (body or "")[:500] if body else ""
        }
        self.architecture["responses"].append(response_data)
        self.architecture["flow"].append({
            "step": f"{tool_name}_response",
            "timestamp": datetime.utcnow().isoformat(),
            "type": "response",
            "data": response_data
        })
    
    def log_tool_complete(self, tool_name: str, success: bool, findings_count: int = 0):
        """Log when a tool completes"""
        for tool in self.architecture["tools"]:
            if tool["name"] == tool_name:
                tool["end_time"] = datetime.utcnow().isoformat()
                tool["status"] = "completed" if success else "failed"
                tool["findings_count"] = findings_count
                break
    
    def finalize(self):
        """Finalize architecture log"""
        self.architecture["end_time"] = datetime.utcnow().isoformat()
        
        # Save to file
        arch_path = os.path.join(self.raw_dir, "architecture.json")
        with open(arch_path, 'w') as f:
            json.dump(self.architecture, f, indent=2, default=str)
        
        return self.architecture
    
    def get_flow_diagram_data(self) -> List[Dict]:
        """Get data for flow diagram"""
        return self.architecture["flow"]
    
    def get_request_response_summary(self) -> Dict:
        """Get summary of requests/responses"""
        return {
            "total_requests": len(self.architecture["requests"]),
            "total_responses": len(self.architecture["responses"]),
            "tools_used": [t["name"] for t in self.architecture["tools"]],
            "duration": "Calculated from timestamps"
        }

