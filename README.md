>>>>>>> origin/main

# MCP Security Scanner

**Multi-Tool Cybersecurity Reconnaissance**

A comprehensive, modern application for cybersecurity reconnaissance that integrates multiple scanning tools into a unified, user-friendly interface with advanced visualizations and reporting.

---

## Features

### Core Capabilities
- **Multi-Tool Scanning**: Nmap, Subfinder, Nikto, Gobuster, NSLookup DNS, Traceroute, Wappalyzer
- **Real-Time Progress Tracking**: Live updates with per-tool status monitoring  
- **Advanced Risk Assessment**: Automated risk scoring (0–10) based on multiple factors  
- **Interactive Visualizations**: Plotly.js charts for ports, subdomains, vulnerabilities  
- **Comprehensive Reporting**: HTML, PDF, JSON, and CSV export options  
- **Scan History**: Complete audit trail with search and filtering  
- **Modern UI**: Beautiful animations with Framer Motion, glass-morphism design  

### Security & Legal
- **Local Processing**: All scans run locally — no data leaves your machine  
- **Authorization Reminder**: Built-in warnings to only scan authorized targets  
- **Secure Storage**: SQLite database with encrypted metadata options  
- **Input Sanitization**: Robust validation and sanitization of scan targets  

---

## Architecture

### High-Level Design

```

                   ┌────────────────────────────────────────────┐
                   │          Frontend (React + Electron)        │
                   │────────────────────────────────────────────│
                   │ • Dashboard UI                              │
                   │ • Real-time progress tracking               │
                   │ • Interactive visualizations                │
                   └───────────────────────┬────────────────────┘
                                           │
                                   (HTTP / JSON API)
                                           │
                   ┌───────────────────────▼────────────────────┐
                   │              Backend (FastAPI)              │
                   │────────────────────────────────────────────│
                   │ • REST API endpoints                        │
                   │ • Worker orchestration                      │
                   │ • Tool execution management                 │
                   └───────────────────────┬────────────────────┘
                                           │
                                   (Subprocess Calls)
                                           │
                   ┌───────────────────────▼────────────────────┐
                   │              Scanner Tools                  │
                   │────────────────────────────────────────────│
                   │ • nmap, subfinder, nikto, etc.              │
                   └────────────────────────────────────────────┘


````

---

## Technology Stack

**Backend:**
- Python 3.11+
- FastAPI (REST API)
- SQLite (local database)
- Jinja2 (report templating)
- Playwright (PDF generation)
- Concurrent.futures (parallel execution)

**Frontend:**
- React 18
- Electron (desktop packaging)
- Framer Motion (animations)
- Plotly.js (charts)
- Lucide React (icons)
- Axios (HTTP client)

---

## ⚙️ Quick Start

### Prerequisites

1. **Python 3.11+** installed  
2. **Node.js 18+** installed  
3. **Scanning Tools** installed and in PATH:
   - `nmap` — Network mapper  
   - `subfinder` — Subdomain discovery  
   - `nikto` — Web vulnerability scanner  
   - `gobuster` — Directory brute-forcer  
   - `nslookup` — DNS lookup (usually pre-installed)  
   - `traceroute` / `tracert` — Network path tracing (usually pre-installed)

---

### Tool Installation (Nmap, Subfinder, Gobuster, Nikto)

#### Windows (PowerShell)

```powershell
# Optional: Install Chocolatey
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Install Nmap and Go
choco install nmap golang -y

# Install Go-based tools (ensure %USERPROFILE%\go\bin is in PATH)
$env:Path += ";$env:USERPROFILE\go\bin"
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/OJ/gobuster/v3@latest

# Nikto (best via WSL) or download from GitHub
````

#### Linux (Debian/Ubuntu)

```bash
sudo apt-get update
sudo apt-get install -y nmap nikto dnsutils traceroute golang-go
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/OJ/gobuster/v3@latest
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc && source ~/.bashrc
```

#### macOS (Homebrew)

```bash
brew install nmap nikto go
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/OJ/gobuster/v3@latest
echo 'export PATH=$PATH:~/go/bin' >> ~/.zshrc && source ~/.zshrc
```

Verify tools:

```bash
nmap --version
subfinder -version
nikto -Version
gobuster -h
```

---

## Installation

1. **Clone or navigate to the project:**

   ```bash
   cd MCP-APP
   ```

2. **Setup Backend:**

   ```bash
   cd backend
   pip install -r requirements.txt
   playwright install chromium
   ```

3. **Setup Frontend:**

   ```bash
   cd frontend
   npm install
   ```

---

## Running the Application

### Option 1: Development Mode

**Terminal 1 – Backend:**

```bash
cd backend
python mcp_server.py
```

Runs on `http://127.0.0.1:8000`

**Terminal 2 – Frontend:**

```bash
cd frontend
npm start
```

Runs on `http://localhost:3000`

### Option 2: One-Click Launch (Windows)

```bash
# Backend
backend\start_backend.bat

# Frontend (new terminal)
frontend\start_frontend.bat
```

---

## Usage Guide

### Starting a Scan

1. Navigate to **"New Scan"** tab
2. Enter target (domain or URL)
3. Select tools
4. Click **"Start Security Scan"**

### Monitoring Progress

* Check **"Progress"** tab for real-time status
* Each tool shows its individual progress and completion

### Viewing Results

* **Report Tab**: Detailed charts and results
* **History Tab**: Past scans, searchable and filterable
* **Export Options**: PDF, JSON, CSV, HTML

---

## Risk Score Calculation

Risk Index (0–10) considers:

* Number & severity of vulnerabilities
* High-risk findings
* Open ports
* Subdomain count

---

## Project Structure

```
MCP-APP/
├── backend/
│   ├── mcp_server.py
│   ├── requirements.txt
│   ├── scanners/
│   │   ├── nmap.py
│   │   ├── subfinder.py
│   │   ├── nikto.py
│   │   ├── gobuster.py
│   │   ├── nslookupdns.py
│   │   └── traceroute.py
│   └── scans/
│       ├── mcp.db
│       └── {scan_id}/
│           ├── raw/
│           └── report.pdf
│
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── Dashboard.js
│   │   │   ├── ScanForm.js
│   │   │   ├── ScanProgress.js
│   │   │   ├── ScanHistory.js
│   │   │   └── ScanReport.js
│   │   ├── App.js
│   │   ├── App.css
│   │   └── index.js
│   └── package.json
│
└── README.md
```

---

## API Endpoints

### 🔹 Scan Management

* `POST /start_scan` – Start a new scan
* `GET /status/{scan_id}` – Get scan status
* `GET /scans` – List all scans

### 🔹 Reports & Export

* `GET /report/{scan_id}` – HTML report
* `GET /report_pdf/{scan_id}` – PDF export
* `GET /export/{scan_id}/json` – JSON export
* `GET /export/{scan_id}/csv` – CSV export

### 🔹 Utilities

* `GET /tools` – List available scanning tools

---

## Features in Detail

### Real-Time Progress Tracking

* Live updates every 2 seconds
* Animated progress indicators
* Tool completion notifications

### Advanced Visualizations

* Port distribution charts
* Subdomain lists
* Risk gauge
* Vulnerability heatmaps

### Export Options

* PDF, JSON, CSV, HTML

---

## Legal & Ethical Guidelines

**IMPORTANT:** Only scan domains you own or have explicit permission to test.
Unauthorized scanning may be **illegal**.

**Best Practices:**

* Always obtain written authorization
* Respect rate limits
* Keep results confidential

---

## Development Guide

### Adding New Tools

Create a scanner module in `backend/scanners/`:

```python
def run_and_parse(target: str, raw_dir: str) -> dict:
    # Your scanning logic
    return {
        "success": True,
        "findings": [...],
        "count": 0
    }
```

Register it in `mcp_server.py`.

### Customizing UI

* Edit `frontend/src/App.css` for styles
* Modify components in `frontend/src/components/`
* Update Framer Motion animations

---

## Building Desktop App

```bash
cd frontend
npm run build
npm run electron
```

Or create installer:

```bash
npm run build && electron-builder
```

---

## Troubleshooting

### Tools Not Found

Ensure tools are installed and in PATH.
Example checks:

```bash
nmap --version
subfinder -version
nikto -Version
gobuster -h
```

### Backend Connection Errors

* Verify backend is running (`http://127.0.0.1:8000/docs`)
* Check CORS configuration
* Disable firewall temporarily if needed

### PDF Export Fails

```bash
playwright install chromium
```

---

## Quick Run Commands

To start the project quickly:

```bash
# Backend
cd backend
python .\mcp_server.py
```

```bash
# Frontend
cd frontend
npm start
```

---

## License & Credits

**Disclaimer:**
This tool is for authorized security testing only. Use responsibly.

**Built With:**

* FastAPI
* React
* Framer Motion
* Plotly.js
* Electron

---

## Version History

### v2.0.0 (Current)

* UI redesign with animations
* Real-time tracking
* Enhanced risk scoring
* Export formats: PDF, JSON, CSV
* Scan history with search/filter

### v1.0.0

* Initial release
* Basic scanning
* Simple HTML reports

---

## Contributing

Contributions are welcome!
Please:

1. Follow code style conventions
2. Add tests for new features
3. Update documentation
4. Respect security best practices

---

## Support

For issues or suggestions:

* Check GitHub Issues
* Review Troubleshooting
* Ensure prerequisites are installed

---

**Built with security in mind. Use responsibly.**

---

**Team Members (The Project Developed By Woxsen Junior Scholars)**
1) Bandi Hemanth (22WU0106028)
2) Vamsi.P (22WU0106013)
3) Rahul Samineni (22WU0106023)
