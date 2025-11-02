# mcp_server.py
import os
import uuid
import json
import sqlite3
import importlib
import csv
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, Any, List, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from jinja2 import Template
from playwright.async_api import async_playwright

# ----------------------------------------------------------------------
# 1. CONFIG & DB (unchanged)
# ----------------------------------------------------------------------
SCAN_ROOT = os.path.abspath("../scans")
os.makedirs(SCAN_ROOT, exist_ok=True)
DB_PATH = os.path.join(SCAN_ROOT, "mcp.db")
MAX_WORKERS = 3
PDF_ROOT = os.path.join(SCAN_ROOT, "pdf")
os.makedirs(PDF_ROOT, exist_ok=True)

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS scans (
                 id TEXT PRIMARY KEY,
                 target TEXT,
                 tools TEXT,
                 status TEXT,
                 created_at TEXT,
                 updated_at TEXT,
                 meta TEXT)""")
    conn.commit()
    conn.close()
init_db()

# ----------------------------------------------------------------------
# 2. TOOL REGISTRY (unchanged)
# ----------------------------------------------------------------------
TOOLS: dict[str, callable] = {}
# In TOOLS registry section
tool_modules = [
    ("subfinder",   "scanners.subfinder"),
    ("nmap",        "scanners.nmap"),
    ("nikto",       "scanners.nikto"),
    ("gobuster",    "scanners.gobuster"),
    ("nslookupdns","scanners.nslookupdns"),
    ("traceroute",  "scanners.traceroute"),
    ("playwright",  "scanners.playwright_scanner"),  # Advanced browser scanning
    ("selenium",    "scanners.selenium_scanner"),    # Browser automation
]

for name, mod_path in tool_modules:
    try:
        module = importlib.import_module(mod_path)
        TOOLS[name] = module.run_and_parse
        print(f"[+] Loaded tool: {name}")
    except Exception as e:
        print(f"[!] Could not load {name}: {e}")

# ----------------------------------------------------------------------
# 3. FASTAPI APP (enhanced with CORS)
# ----------------------------------------------------------------------
app = FastAPI(
    title="MCP Scanner API",
    description="Multi-tool Cybersecurity Reconnaissance Platform",
    version="2.0.0"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)

class ScanRequest(BaseModel):
    target: str  # Now accepts full URL like https://www.example.com
    tools: list[str] = ["nmap", "subfinder"]
    options: Optional[Dict[str, Any]] = {}

class ScanStatus(BaseModel):
    id: str
    target: str
    tools: list[str]
    status: str
    created_at: str
    updated_at: str
    meta: Dict[str, Any]

# ----------------------------------------------------------------------
# 4. DB HELPERS (unchanged)
# ----------------------------------------------------------------------
def save_scan_record(scan_id: str, **kwargs):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = datetime.utcnow().isoformat()
    c.execute("SELECT 1 FROM scans WHERE id=?", (scan_id,))
    if not c.fetchone():
        c.execute(
            """INSERT INTO scans
               (id, target, tools, status, created_at, updated_at, meta)
               VALUES (?,?,?,?,?,?,?)""",
            (
                scan_id,
                kwargs.get("target"),
                json.dumps(kwargs.get("tools") or []),
                kwargs.get("status", "queued"),
                now,
                now,
                json.dumps(kwargs.get("meta") or {})
            ),
        )
    else:
        c.execute(
            """UPDATE scans
               SET status=?, updated_at=?, meta=?
               WHERE id=?""",
            (
                kwargs.get("status"),
                now,
                json.dumps(kwargs.get("meta") or {}),
                scan_id,
            ),
        )
    conn.commit()
    conn.close()

# ----------------------------------------------------------------------
# 5. UTILITIES IMPORT
# ----------------------------------------------------------------------
try:
    from utils.vulnerability_db import get_mitigations_for_scan
    from utils.tool_checker import check_all_tools
except ImportError:
    # Fallback if utils not available
    def get_mitigations_for_scan(findings):
        return []
    def check_all_tools():
        return {}

# ----------------------------------------------------------------------
# 6. WORKER (enhanced: compute Risk Index with progress tracking)
# ----------------------------------------------------------------------
def worker_run_scan(scan_id: str, target: str, tools: list[str], options: Dict[str, Any] = None):
    from scanners.scan_architecture import ScanArchitecture
    
    scan_dir = os.path.join(SCAN_ROOT, scan_id)
    raw_dir = os.path.join(scan_dir, "raw")
    os.makedirs(raw_dir, exist_ok=True)

    # Initialize architecture tracking
    arch = ScanArchitecture(scan_id, raw_dir)

    options = options or {}
    progress = {"completed": 0, "total": len(tools), "current_tool": None}
    
    save_scan_record(scan_id, status="running", target=target, tools=tools, 
                     meta={"step": "started", "progress": progress})

    findings: Dict[str, Dict[str, Any]] = {}
    total_vulns = 0
    open_ports = 0
    subdomain_count = 0
    high_risk_findings = 0
    
    for idx, tool_name in enumerate(tools):
        progress["current_tool"] = tool_name
        progress["completed"] = idx
        arch.log_tool_start(tool_name)
        arch.log_request(tool_name, "SCAN", target, {"tool": tool_name})
        
        save_scan_record(scan_id, status="running", meta={"progress": progress, "findings": findings})
        
        parser = TOOLS.get(tool_name)
        if parser:
            try:
                tool_findings = parser(target, raw_dir)
                findings[tool_name] = tool_findings
                
                # Log response
                findings_count = 0
                if isinstance(tool_findings, dict):
                    if "vulnerabilities" in tool_findings:
                        findings_count = len(tool_findings.get("vulnerabilities", []))
                    elif "directories" in tool_findings:
                        findings_count = len(tool_findings.get("directories", []))
                    elif "subdomains" in tool_findings:
                        findings_count = len(tool_findings.get("subdomains", []))
                    elif "hosts" in tool_findings:
                        for host in tool_findings.get("hosts", []):
                            findings_count += len(host.get("ports", []))
                    elif "subdomains_found" in tool_findings:
                        findings_count = len(tool_findings.get("subdomains_found", []))
                    elif "links" in tool_findings:
                        findings_count = len(tool_findings.get("links", []))
                
                arch.log_response(tool_name, 200 if tool_findings.get("success") else 500, 
                                 {}, None, findings_count)
                arch.log_tool_complete(tool_name, tool_findings.get("success", False), findings_count)
                
                # Aggregate for Risk Index
                if tool_name == "nikto":
                    total_vulns += tool_findings.get("count", 0)
                    high_risk_findings += tool_findings.get("high_risk", 0)
                if tool_name == "nmap":
                    open_ports += tool_findings.get("open_ports_count", 0)
                if tool_name == "subfinder":
                    subdomain_count += tool_findings.get("count", 0)
                    # Also check for subdomains found by Playwright/Selenium
                    subdomain_count += len(tool_findings.get("subdomains_found", []))
                # Collect subdomains from Playwright/Selenium
                if tool_name in ["playwright", "selenium"]:
                    subdomain_count += len(tool_findings.get("subdomains_found", []))
            except Exception as exc:
                findings[tool_name] = {"error": str(exc), "success": False}
                arch.log_response(tool_name, 500, {}, str(exc), 0)
                arch.log_tool_complete(tool_name, False, 0)
        else:
            findings[tool_name] = {"error": f"Tool '{tool_name}' not available", "success": False}
            arch.log_response(tool_name, 404, {}, "Tool not found", 0)
            arch.log_tool_complete(tool_name, False, 0)

    # Enhanced Risk Index (0-10): Multi-factor calculation
    risk_score = 0
    if total_vulns > 0:
        risk_score += min(4, total_vulns * 0.5)
    if high_risk_findings > 0:
        risk_score += min(3, high_risk_findings * 1.0)
    if open_ports > 20:
        risk_score += min(2, (open_ports - 20) * 0.1)
    if subdomain_count > 50:
        risk_score += min(1, (subdomain_count - 50) * 0.02)
    
    risk_index = min(10, int(risk_score))
    
    progress["completed"] = len(tools)
    progress["current_tool"] = None
    
    # Finalize architecture tracking
    architecture = arch.finalize()
    
    # Generate mitigation recommendations (ensure it's a list, not generator)
    mitigations = list(get_mitigations_for_scan(findings))
    
    # Serialize findings to ensure no generators remain
    serialized_findings = {}
    for tool, data in findings.items():
        if isinstance(data, dict):
            # Deep copy and serialize
            try:
                serialized_findings[tool] = json.loads(json.dumps(data, default=str))
            except:
                serialized_findings[tool] = data
        else:
            serialized_findings[tool] = data
    
    save_scan_record(scan_id, status="finished", 
                     meta={"findings": serialized_findings, "risk_index": risk_index, 
                           "progress": progress, "summary": {
                               "total_vulns": total_vulns,
                               "open_ports": open_ports,
                               "subdomains": subdomain_count,
                               "high_risk": high_risk_findings
                           },
                           "mitigations": mitigations,
                           "architecture": architecture})

# ----------------------------------------------------------------------
# 6. ENDPOINTS (minor: validate URL-like target)
# ----------------------------------------------------------------------
@app.post("/start_scan")
async def start_scan(req: ScanRequest):
    # Enhanced URL sanitization
    dangerous_chars = [";", "&", "$", "`", "|", "<", ">", "\"", "'"]
    if any(c in req.target for c in dangerous_chars):
        raise HTTPException(status_code=400, detail="Invalid characters in target")
    
    # Extract domain from URL if needed
    clean_target = req.target
    if clean_target.startswith("http://") or clean_target.startswith("https://"):
        from urllib.parse import urlparse
        parsed = urlparse(clean_target)
        clean_target = parsed.netloc or parsed.path
    
    if not clean_target or "." not in clean_target:
        raise HTTPException(status_code=400, detail="Invalid target format")
    
    if not req.tools:
        raise HTTPException(status_code=400, detail="At least one tool must be selected")
    
    # Validate tools
    invalid_tools = [t for t in req.tools if t not in TOOLS]
    if invalid_tools:
        raise HTTPException(status_code=400, detail=f"Invalid tools: {invalid_tools}")
    
    scan_id = str(uuid.uuid4())
    save_scan_record(scan_id, target=req.target, tools=req.tools, status="queued", meta={})
    executor.submit(worker_run_scan, scan_id, clean_target, req.tools, req.options)
    return {"scan_id": scan_id, "status": "queued", "target": req.target, "tools": req.tools}

@app.get("/status/{scan_id}")
async def get_status(scan_id: str):
    if len(scan_id) != 36:
        raise HTTPException(status_code=400, detail="Invalid scan_id length")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, target, tools, status, created_at, updated_at, meta FROM scans WHERE id=?", (scan_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    meta = json.loads(row[6]) if row[6] else {}
    return {
        "id": row[0], "target": row[1], "tools": json.loads(row[2]), "status": row[3],
        "created_at": row[4], "updated_at": row[5], "meta": meta
    }

@app.get("/scans")
async def list_scans(limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0), 
                     status: Optional[str] = None):
    """List all scans with pagination"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    query = "SELECT id, target, tools, status, created_at, updated_at, meta FROM scans"
    params = []
    if status:
        query += " WHERE status = ?"
        params.append(status)
    query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    
    c.execute(query, params)
    rows = c.fetchall()
    
    # Get total count
    count_query = "SELECT COUNT(*) FROM scans"
    count_params = []
    if status:
        count_query += " WHERE status = ?"
        count_params.append(status)
    c.execute(count_query, count_params)
    total = c.fetchone()[0]
    
    conn.close()
    
    scans = []
    for row in rows:
        meta = json.loads(row[6]) if row[6] else {}
        scans.append({
            "id": row[0],
            "target": row[1],
            "tools": json.loads(row[2]) if row[2] else [],
            "status": row[3],
            "created_at": row[4],
            "updated_at": row[5],
            "risk_index": meta.get("risk_index", 0),
            "summary": meta.get("summary", {})
        })
    
    return {"scans": scans, "total": total, "limit": limit, "offset": offset}

@app.get("/export/{scan_id}/json")
async def export_json(scan_id: str):
    """Export scan results as JSON"""
    status_data = await get_status(scan_id)
    return JSONResponse(content=status_data)

@app.get("/export/{scan_id}/csv")
async def export_csv(scan_id: str):
    """Export scan findings as CSV"""
    status_data = await get_status(scan_id)
    findings = status_data.get("meta", {}).get("findings", {})
    
    csv_path = os.path.join(SCAN_ROOT, scan_id, "export.csv")
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["Tool", "Finding Type", "Details"])
        
        for tool_name, tool_data in findings.items():
            if isinstance(tool_data, dict):
                if "hosts" in tool_data:  # nmap
                    for host in tool_data.get("hosts", []):
                        for port in host.get("ports", []):
                            writer.writerow([tool_name, "Open Port", 
                                            f"{port.get('port')}/{port.get('protocol')} - {port.get('service')}"])
                elif "subdomains" in tool_data:  # subfinder
                    for subdomain in tool_data.get("subdomains", [])[:100]:  # Limit to 100
                        writer.writerow([tool_name, "Subdomain", subdomain])
                elif "subdomains_found" in tool_data:  # playwright/selenium
                    for subdomain in tool_data.get("subdomains_found", [])[:100]:
                        writer.writerow([tool_name, "Subdomain", subdomain])
                elif "vulnerabilities" in tool_data:  # nikto
                    for vuln in tool_data.get("vulnerabilities", [])[:100]:
                        writer.writerow([tool_name, "Vulnerability", 
                                        vuln.get("url", "") + " - " + str(vuln.get("description", ""))])
                elif "directories" in tool_data:  # gobuster
                    for dir_entry in tool_data.get("directories", [])[:100]:
                        writer.writerow([tool_name, "Directory", 
                                        f"{dir_entry.get('path', '')} - Status: {dir_entry.get('status', '')}"])
    
    return FileResponse(csv_path, media_type="text/csv", 
                       filename=f"MCP_Export_{scan_id[:8]}.csv")

@app.get("/tools")
async def get_available_tools():
    """Get list of available scanning tools"""
    tools_status = check_all_tools()
    return {
        "tools": list(TOOLS.keys()),
        "descriptions": {
            "nmap": "Network mapper - Port scanning and service detection",
            "subfinder": "Subdomain discovery tool",
            "nikto": "Web server scanner - Vulnerability detection",
            "gobuster": "Directory/file brute-forcer",
            "nslookupdns": "DNS lookup and resolution",
            "traceroute": "Network path tracing",
            "playwright": "Advanced browser scanning - Handles pop-ups, crawls all data",
            "selenium": "Browser automation - Full page rendering, pop-up handling"
        },
        "status": tools_status
    }

# --------------------------------------------------------------
# 7. NEW REPORT TEMPLATE – WITH REAL VISUALISATIONS
# --------------------------------------------------------------
REPORT_TEMPLATE_STR = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>MCP Scan Intelligence Report - {{ target }}</title>
  <script src="https://cdn.plot.ly/plotly-2.27.0.min.js"></script>
  <style>
    @page { size: A4; margin: .8in; }
    body {font-family:'Segoe UI',sans-serif;margin:0;color:#333;line-height:1.5;}
    .page {page-break-after:always;padding:30px;max-width:800px;margin:0 auto;}
    .page:last-child {page-break-after:avoid;}
    .header {text-align:center;font-weight:bold;border-bottom:2px solid #0078d4;padding-bottom:8px;margin-bottom:20px;}
    h1,h2,h3 {color:#0078d4;}
    .risk-gauge {height:200px;margin:20px 0;}
    .chart {height:350px;margin:30px 0;}
    .footer {margin-top:40px;padding-top:15px;border-top:1px solid #ddd;font-size:11px;text-align:center;color:#666;}
    .risk-score {font-size:28px;font-weight:bold;}
    .high {color:#d9534f;}
    .med  {color:#f0ad4e;}
    .low  {color:#5cb85c;}
    @media screen {.page {box-shadow:0 0 8px rgba(0,0,0,.1);margin-bottom:20px;}}
  </style>
</head>
<body>

<!-- PAGE 1 – Summary + Risk Gauge -->
<div class="page">
  <div class="header">MCP Scan Intelligence Report – {{ target }} | Page 1</div>
  <h1>Domain Vulnerability Scan Overview</h1>
  <p>Comprehensive intelligence for <strong>{{ target }}</strong>
  {% if meta.findings.nmap and meta.findings.nmap.resolved_ip %}
    → IP: <strong>{{ meta.findings.nmap.resolved_ip }}</strong>
  {% elif meta.findings.subfinder and meta.findings.subfinder.main_domain_ip %}
    → IP: <strong>{{ meta.findings.subfinder.main_domain_ip }}</strong>
  {% endif %}
  – from discovery to remediation.</p>

  <div style="text-align:center;">
    <div class="risk-gauge" id="riskGauge"></div>
    <div class="risk-score {{ 'high' if risk_index>=7 else 'med' if risk_index>=4 else 'low' }}">
      Risk Index: {{ risk_index }}/10
    </div>
  </div>

  <h2>Quick Stats</h2>
  <ul>
    <li>Tools executed: {{ meta.findings|length }}</li>
    <li>Open ports: {{ meta.findings.nmap.open_ports_count|default(0) }}</li>
    <li>Sub-domains: {{ meta.findings.subfinder.count|default(0) }}</li>
    <li>Known vulnerabilities: {{ meta.findings.nikto.count|default(0) }}</li>
  </ul>
</div>

<!-- PAGE 2 – Nmap & Subfinder -->
<div class="page">
  <div class="header">MCP Scan Intelligence Report – {{ target }} | Page 2</div>
  <h2>Open Ports by Service (Nmap)</h2>
  <div class="chart" id="portsChart"></div>

  <h2>Sub-domains Discovered (Subfinder)</h2>
  <div class="chart" id="subdomainsChart"></div>
</div>

<!-- PAGE 3 – Nikto & Gobuster -->
<div class="page">
  <div class="header">MCP Scan Intelligence Report – {{ target }} | Page 3</div>
  <h2>Known Vulnerabilities (Nikto)</h2>
  <div class="chart" id="niktoHeatmap"></div>

  <h2>Directory Discovery (Gobuster)</h2>
  <div class="chart" id="gobusterPie"></div>
</div>

<!-- PAGE 4 – Mitigation Steps -->
<div class="page">
  <div class="header">MCP Scan Intelligence Report – {{ target }} | Page 4</div>
  <h2>🔒 Vulnerability Mitigation & Remediation Steps</h2>
  {% if meta.mitigations and meta.mitigations|length > 0 %}
    {% for mitigation in meta.mitigations %}
    <div style="margin-bottom:25px;padding:15px;border-left:4px solid {% if mitigation.severity == 'critical' %}#dc3545{% elif mitigation.severity == 'high' %}#f0ad4e{% elif mitigation.severity == 'medium' %}#ffc107{% else %}#28a745{% endif %};background:#f9f9f9;border-radius:4px;">
      <h3 style="color:{% if mitigation.severity == 'critical' %}#dc3545{% elif mitigation.severity == 'high' %}#f0ad4e{% elif mitigation.severity == 'medium' %}#ffc107{% else %}#28a745{% endif %};margin-top:0;">
        {{ mitigation.title }} ({{ mitigation.severity|upper }})
      </h3>
      <p><strong>Finding:</strong> {{ mitigation.finding }}</p>
      <p>{{ mitigation.description }}</p>
      <h4>Remediation Steps:</h4>
      <ol>
        {% for step in mitigation.mitigation %}
        <li>{{ step }}</li>
        {% endfor %}
      </ol>
      {% if mitigation.references %}
      <h4>References:</h4>
      <ul>
        {% for ref in mitigation.references %}
        <li><a href="{{ ref }}" target="_blank">{{ ref }}</a></li>
        {% endfor %}
      </ul>
      {% endif %}
    </div>
    {% endfor %}
  {% else %}
    <p>No vulnerabilities detected requiring mitigation.</p>
  {% endif %}
</div>

<!-- PAGE 5 – Architecture Flow Diagram -->
<div class="page">
  <div class="header">MCP Scan Intelligence Report – {{ target }} | Page 5</div>
  <h2>Scan Architecture & Request Flow</h2>
  {% if meta.architecture %}
  <div style="margin:20px 0;">
    <h3>Scan Process Flow</h3>
    <table style="width:100%;border-collapse:collapse;margin:20px 0;font-size:0.9em;">
      <thead>
        <tr style="background:#0078d4;color:white;">
          <th style="padding:10px;text-align:left;">Step</th>
          <th style="padding:10px;text-align:left;">Tool</th>
          <th style="padding:10px;text-align:left;">Type</th>
          <th style="padding:10px;text-align:left;">Timestamp</th>
        </tr>
      </thead>
      <tbody>
        {% for flow_item in meta.architecture.flow[:15] %}
        <tr style="border-bottom:1px solid #ddd;">
          <td style="padding:8px;">{{ loop.index }}</td>
          <td style="padding:8px;"><strong>{{ flow_item.get('tool', 'N/A') }}</strong></td>
          <td style="padding:8px;color:{% if flow_item.get('type') == 'request' %}#0078d4{% else %}#28a745{% endif %};">{{ flow_item.get('type', 'N/A')|upper }}</td>
          <td style="padding:8px;font-size:0.85em;">{{ flow_item.get('timestamp', 'N/A') }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
    
    <h3>Request/Response Summary</h3>
    <ul>
      <li><strong>Total Requests:</strong> {{ meta.architecture.requests|length }}</li>
      <li><strong>Total Responses:</strong> {{ meta.architecture.responses|length }}</li>
      <li><strong>Tools Used:</strong> {% for tool in meta.architecture.tools %}{{ tool.get('name', '') }}{% if not loop.last %}, {% endif %}{% endfor %}</li>
      <li><strong>Start Time:</strong> {{ meta.architecture.start_time }}</li>
      <li><strong>End Time:</strong> {{ meta.architecture.end_time }}</li>
    </ul>
  </div>
  {% endif %}
  
  <div style="margin-top:30px;">
    <h2>Network Path (Traceroute)</h2>
    <div class="chart" id="tracerouteSankey"></div>
  </div>
</div>

<!-- PAGE 6 – Detailed Request/Response & Footer -->
<div class="page">
  <div class="header">MCP Scan Intelligence Report – {{ target }} | Page 6</div>
  {% if meta.architecture %}
  <h2>Request & Response Details</h2>
  {% for req in meta.architecture.requests[:8] %}
  <div style="margin-bottom:20px;padding:15px;border-left:4px solid #0078d4;background:#f0f8ff;">
    <h4 style="margin-top:0;color:#0078d4;">{{ req.get('tool', 'UNKNOWN')|upper }} Request</h4>
    <p><strong>Method:</strong> {{ req.get('method', 'N/A') }} | <strong>URL:</strong> {{ req.get('url', 'N/A') }}</p>
    <p><strong>Timestamp:</strong> {{ req.get('timestamp', 'N/A') }}</p>
  </div>
  {% endfor %}
  
  {% for resp in meta.architecture.responses[:8] %}
  <div style="margin-bottom:20px;padding:15px;border-left:4px solid #28a745;background:#f0fff4;">
    <h4 style="margin-top:0;color:#28a745;">{{ resp.get('tool', 'UNKNOWN')|upper }} Response</h4>
    <p><strong>Status:</strong> {{ resp.get('status_code', 'N/A') }} | <strong>Size:</strong> {{ resp.get('body_size', 0) }} bytes</p>
    <p><strong>Timestamp:</strong> {{ resp.get('timestamp', 'N/A') }}</p>
  </div>
  {% endfor %}
  {% endif %}

  <div class="footer">
    <p><strong>About MCP:</strong> Multi-tool scanning engine – intuitive, fast, local.</p>
    <p>mcp-app.com | Generated: {{ created_at }} | <em>Only scan authorized domains.</em></p>
  </div>
</div>

<script>
/* ---------- 1. Risk Gauge ---------- */
const gauge = {
  type: "indicator",
  mode: "gauge+number",
  value: {{ risk_index }},
  gauge: { axis: { range: [0,10] }, bar: { color: "{{ '#d9534f' if risk_index>=7 else '#f0ad4e' if risk_index>=4 else '#5cb85c' }}" } },
  title: { text: "Risk Index" }
};
Plotly.newPlot('riskGauge', [gauge], {responsive:true});

/* ---------- 2. Ports by Service ---------- */
{% set services = {} %}
{% for h in meta.findings.nmap.hosts|default([]) %}
  {% for p in h.ports %}
    {% set _ = services.update({p.service: services.get(p.service,0)+1}) %}
  {% endfor %}
{% endfor %}
const portLabels = {{ list(services.keys())|tojson }};
const portValues = {{ list(services.values())|tojson }};
const portsData = [{ x: portLabels, y: portValues, type:'bar', marker:{color:'#0078d4'} }];
Plotly.newPlot('portsChart', portsData, {title:'Open Ports per Service', responsive:true});

/* ---------- 3. Sub-domains (top 20) ---------- */
const subdomains = {{ meta.findings.subfinder.subdomains|default([])|list|slice(":20")|tojson }};
const subData = [{ y: subdomains, type:'bar', orientation:'h', marker:{color:'#17a2b8'} }];
Plotly.newPlot('subdomainsChart', subData, {title:'Top 20 Sub-domains', responsive:true});

/* ---------- 4. Nikto Heat-map (first 15) ---------- */
const nikto = {{ meta.findings.nikto.vulnerabilities|default([])|list|slice(":15")|tojson }};
const heatX = nikto.map(v=>v.url.split('/').slice(0,3).join('/'));   // shorten URL
const heatY = nikto.map(v=>v.risk || 'unknown');
const heatZ = nikto.map(v=>1);
const heatData = [{ x: heatX, y: heatY, z: heatZ, type:'heatmap',
  colorscale: [[0,'#5cb85c'],[0.5,'#f0ad4e'],[1,'#d9534f']] }];
Plotly.newPlot('niktoHeatmap', heatData, {title:'Vulnerability Heat-map (Nikto)', responsive:true});

/* ---------- 5. Gobuster Pie ---------- */
{% set status_counts = {} %}
{% for d in meta.findings.gobuster.directories|default([]) %}
  {% set _ = status_counts.update({d.status: status_counts.get(d.status,0)+1}) %}
{% endfor %}
const pieLabels = {{ list(status_counts.keys())|tojson }};
const pieValues = {{ list(status_counts.values())|tojson }};
const pieData = [{ labels: pieLabels, values: pieValues, type:'pie' }];
Plotly.newPlot('gobusterPie', pieData, {title:'Directory Status Codes (Gobuster)', responsive:true});

/* ---------- 6. Traceroute Sankey ---------- */
const hops = {{ meta.findings.traceroute.hops|default([])|tojson }};
const sankeyLabels = hops.map((h,i)=>`Hop ${i+1}${h.ip?': '+h.ip:''}`);
const source = hops.slice(0,-1).map((_,i)=>i);
const target = hops.slice(1).map((_,i)=>i+1);
const sankeyData = [{ type:'sankey', node:{ label: sankeyLabels }, link:{ source:source, target:target, value: hops.map(()=>1) } }];
Plotly.newPlot('tracerouteSankey', sankeyData, {title:'Network Path (Traceroute)', responsive:true});
</script>
</body>
</html>
"""
REPORT_TEMPLATE = Template(REPORT_TEMPLATE_STR)

@app.get("/report/{scan_id}", response_class=HTMLResponse)
async def get_report(scan_id: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, target, tools, status, created_at, updated_at, meta FROM scans WHERE id=?", (scan_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    meta = json.loads(row[6]) if row[6] else {}
    meta.setdefault("created_at", row[4])
    risk_index = meta.get("risk_index", 0)
    # Ensure findings structure exists
    if "findings" not in meta:
        meta["findings"] = {}
    
    html = REPORT_TEMPLATE.render(
        scan_id=row[0], target=row[1], tools=json.loads(row[2]), meta=meta, created_at=row[4], risk_index=risk_index
    )
    return HTMLResponse(html)

@app.get("/report_pdf/{scan_id}")
async def get_report_pdf(scan_id: str):
    """Generate and download PDF report"""
    try:
        # Get scan data
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT id, target, tools, status, created_at, updated_at, meta FROM scans WHERE id=?", (scan_id,))
        row = c.fetchone()
        conn.close()
        
        if not row:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Generate HTML report
        html_resp = await get_report(scan_id)
        html_content = html_resp.body.decode()
        
        # Ensure PDF directory exists
        pdf_dir = Path(PDF_ROOT)
        pdf_dir.mkdir(parents=True, exist_ok=True)
        
        pdf_path = pdf_dir / f"{scan_id}.pdf"
        
        # Use Playwright for PDF generation with better rendering
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()
                
                # Load HTML content
                await page.set_content(html_content, wait_until="networkidle")
                
                # Wait for charts to render
                await page.wait_for_timeout(3000)
                
                # Generate PDF
                await page.pdf(
                    path=str(pdf_path),
                    format="A4",
                    print_background=True,
                    margin={"top": "0.5in", "right": "0.5in", "bottom": "0.5in", "left": "0.5in"}
                )
                await browser.close()
        except Exception as pdf_error:
            # If Playwright fails, try saving HTML temporarily
            import traceback
            raise HTTPException(status_code=500, detail=f"PDF generation failed: {str(pdf_error)}\n{traceback.format_exc()}")
        
        # Verify PDF was created
        if not pdf_path.exists():
            raise HTTPException(status_code=500, detail="PDF file was not created")
        
        # Return PDF file as download (FileResponse already imported at top)
        return FileResponse(
            path=str(pdf_path),
            media_type="application/pdf",
            filename=f"MCP_Report_{scan_id[:8]}.pdf",
            headers={
                "Content-Disposition": f"attachment; filename=MCP_Report_{scan_id[:8]}.pdf",
                "Content-Type": "application/pdf"
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        raise HTTPException(status_code=500, detail=f"PDF generation error: {str(e)}\n{traceback.format_exc()}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)