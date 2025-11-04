# MCP Security Scanner

**Multi-Tool Cybersecurity Reconnaissance Platform**

A comprehensive, modern desktop application for cybersecurity reconnaissance that integrates multiple scanning tools into a unified, user-friendly interface with advanced visualizations and reporting.

## Features

### Core Capabilities
- **Multi-Tool Scanning**: Nmap, Subfinder, Nikto, Gobuster, NSLookup DNS, Traceroute
- **Real-Time Progress Tracking**: Live updates with per-tool status monitoring
- **Advanced Risk Assessment**: Automated risk scoring (0-10) based on multiple factors
- **Interactive Visualizations**: Plotly.js charts for ports, subdomains, vulnerabilities
- **Comprehensive Reporting**: HTML, PDF, JSON, and CSV export options
- **Scan History**: Complete audit trail with search and filtering
- **Modern UI**: Beautiful animations with Framer Motion, glass-morphism design

### Security & Legal
- **Local Processing**: All scans run locally, no data leaves your machine
- **Authorization Reminder**: Built-in warnings to only scan authorized targets
- **Secure Storage**: SQLite database with encrypted metadata options
- **Input Sanitization**: Robust validation and sanitization of scan targets

## Architecture

### High-Level Design
```
┌─────────────────────────────────────────┐
│      Frontend (React + Electron)        │
│  - Dashboard UI                         │
│  - Real-time progress tracking          │
│  - Interactive visualizations           │
└──────────────┬──────────────────────────┘
               │ HTTP/JSON API
┌──────────────▼──────────────────────────┐
│      Backend (FastAPI)                  │
│  - REST API endpoints                   │
│  - Worker orchestration                │
│  - Tool execution management           │
└──────────────┬──────────────────────────┘
               │ Subprocess Calls
┌──────────────▼──────────────────────────┐
│   Scanner Tools                         │
│  - nmap, subfinder, nikto, etc.        │
└─────────────────────────────────────────┘
```

### Technology Stack

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

## Quick Start

### Prerequisites

1. **Python 3.11+** installed
2. **Node.js 18+** installed
3. **Scanning Tools** installed and in PATH:
   - `nmap` - Network mapper
   - `subfinder` - Subdomain discovery
   - `nikto` - Web vulnerability scanner
   - `gobuster` - Directory brute-forcer
   - `nslookup` - DNS lookup (usually pre-installed)
   - `traceroute` / `tracert` - Network path tracing (usually pre-installed)

### Tool Installation (nmap, subfinder, gobuster, nikto)

Windows (PowerShell):

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
```

Linux (Debian/Ubuntu):

```bash
sudo apt-get update
sudo apt-get install -y nmap nikto dnsutils traceroute golang-go
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/OJ/gobuster/v3@latest
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc && source ~/.bashrc
```

macOS (Homebrew):

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

### Installation

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

### Running the Application

#### Option 1: Development Mode

**Terminal 1 - Backend:**
```bash
cd backend
python mcp_server.py
```
Backend runs on `http://127.0.0.1:8000`

**Terminal 2 - Frontend:**
```bash
cd frontend
npm start
```
Frontend runs on `http://localhost:3000`

#### Option 2: One-Click Launch (Windows)

```bash
# Backend
backend\start_backend.bat

# Frontend (new terminal)
frontend\start_frontend.bat
```

## Usage Guide

### Starting a Scan

1. **Navigate to "New Scan" tab**
2. **Enter target**: Domain (e.g., `example.com`) or full URL (e.g., `https://example.com`)
3. **Select tools**: Choose which scanning tools to run
4. **Click "Start Security Scan"**

### Monitoring Progress

- Switch to **"Progress"** tab to see real-time status
- Each tool shows its completion status
- Progress bar indicates overall completion percentage

### Viewing Results

- **Report Tab**: Comprehensive view with charts and statistics
- **History Tab**: Browse all previous scans, search and filter
- **Export Options**: PDF, JSON, CSV, or HTML reports

### Understanding Risk Score

The risk index (0-10) considers:
- **Vulnerabilities**: Number and severity of security issues found
- **High-Risk Findings**: Critical vulnerabilities that need immediate attention
- **Open Ports**: Exposed services and potential attack surface
- **Subdomain Count**: Attack surface expansion

## Project Structure

```
MCP-APP/
├── backend/
│   ├── mcp_server.py          # FastAPI server
│   ├── requirements.txt        # Python dependencies
│   ├── scanners/               # Tool wrapper modules
│   │   ├── nmap.py
│   │   ├── subfinder.py
│   │   ├── nikto.py
│   │   ├── gobuster.py
│   │   ├── nslookupdns.py
│   │   └── traceroute.py
│   └── scans/                  # Scan results storage
│       ├── mcp.db             # SQLite database
│       └── {scan_id}/         # Per-scan directories
│           ├── raw/           # Raw tool outputs
│           └── report.pdf     # Generated reports
│
├── frontend/
│   ├── src/
│   │   ├── components/        # React components
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

## API Endpoints

### Scan Management
- `POST /start_scan` - Start a new scan
- `GET /status/{scan_id}` - Get scan status
- `GET /scans` - List all scans (with pagination)

### Reports & Export
- `GET /report/{scan_id}` - HTML report
- `GET /report_pdf/{scan_id}` - PDF export
- `GET /export/{scan_id}/json` - JSON export
- `GET /export/{scan_id}/csv` - CSV export

### Utilities
- `GET /tools` - List available scanning tools

## Features in Detail

### Real-Time Progress Tracking
- Live updates every 2 seconds
- Per-tool status indicators
- Animated progress bars
- Tool completion notifications

### Advanced Visualizations
- **Port Distribution Charts**: Service-based port analysis
- **Subdomain Lists**: Discovered subdomains with badges
- **Risk Gauge**: Visual risk assessment meter
- **Vulnerability Heatmaps**: Severity-based visualization

### Export Options
- **PDF**: Professional reports with charts (via Playwright)
- **JSON**: Complete raw data for programmatic analysis
- **CSV**: Structured findings for spreadsheet analysis
- **HTML**: Interactive web reports with embedded charts

## Legal & Ethical Guidelines

**CRITICAL**: Only scan domains you own or have explicit written permission to test.

- Unauthorized scanning may be:
  - Illegal in your jurisdiction
  - Violation of computer fraud laws
  - Cause for legal action
  - Against terms of service

**Best Practices:**
- Always obtain written authorization
- Respect rate limits
- Use responsible disclosure for findings
- Keep scan results confidential

## Development

### Adding New Tools

1. Create scanner module in `backend/scanners/`
2. Implement `run_and_parse(target, raw_dir)` function
3. Return standardized dictionary with findings
4. Register in `mcp_server.py` TOOLS registry

Example:
```python
# backend/scanners/example.py
def run_and_parse(target: str, raw_dir: str) -> dict:
    # Your scanning logic
    return {
        "success": True,
        "findings": [...],
        "count": 0
    }
```

### Customizing UI

- **Styles**: Edit `frontend/src/App.css`
- **Components**: Modify React components in `frontend/src/components/`
- **Animations**: Adjust Framer Motion props
- **Theme**: Update CSS variables and gradients

### Building Desktop App

```bash
cd frontend
npm run build
npm run electron
```

Or create installer:
```bash
npm run build && electron-builder
```

## Troubleshooting

### Tools Not Found
- Ensure all tools are installed and in system PATH
- Check tool availability: `nmap --version`, `subfinder -version`, etc.
- On Windows, may need full paths in tool wrappers

### Backend Connection Errors
- Verify backend is running: `http://127.0.0.1:8000/docs`
- Check CORS settings in `mcp_server.py`
- Ensure no firewall blocking localhost:8000

### PDF Export Fails
- Run `playwright install chromium`
- Check Playwright installation: `python -m playwright --version`

### Scan Timeouts
- Increase timeout values in scanner modules
- Check tool-specific configuration
- Some tools may need extended timeouts for large targets

## 📝 License & Credits

**Disclaimer**: This tool is for authorized security testing only. Users are responsible for compliance with all applicable laws.

**Built With:**
- FastAPI - Modern Python web framework
- React - UI library
- Framer Motion - Animation library
- Plotly.js - Visualization library
- Electron - Desktop app framework

## Version History

### v2.0.0 (Current)
- Complete UI redesign with animations
- Real-time progress tracking
- Enhanced risk scoring algorithm
- Scan history with search/filter
- Multiple export formats
- Advanced visualizations

### v1.0.0
- Initial release
- Basic scanning functionality
- Simple HTML reports

## Contributing

Contributions welcome! Please:
1. Follow code style conventions
2. Add tests for new features
3. Update documentation
4. Respect security best practices

## Support

For issues, questions, or suggestions:
- Check existing GitHub issues
- Review troubleshooting section
- Ensure all prerequisites are met

---

**Built with security in mind. Use responsibly.**


