# 🚀 Quick Setup Guide

## Prerequisites Installation

### 1. Install Python 3.11+
Download from [python.org](https://www.python.org/downloads/)
- ✅ Check "Add Python to PATH" during installation
- Verify: `python --version`

### 2. Install Node.js 18+
Download from [nodejs.org](https://nodejs.org/)
- Includes npm package manager
- Verify: `node --version` and `npm --version`

### 3. Install Scanning Tools

#### Windows:
```powershell
# Using Chocolatey (recommended)
choco install nmap
choco install go

# Then install Go-based tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/OJ/gobuster/v3@latest

# Nikto (download from https://github.com/sullo/nikto or use WSL)
```

#### Linux:
```bash
sudo apt-get update
sudo apt-get install nmap nikto golang-go
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/OJ/gobuster/v3@latest
```

#### macOS:
```bash
brew install nmap nikto go
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest@latest
go install github.com/OJ/gobuster/v3@latest
```

**Note**: Ensure all tools are in your system PATH. Test with:
- `nmap --version`
- `subfinder -version`
- `nikto -help`
- `gobuster -h`

## Installation Steps

### Step 1: Backend Setup

```bash
cd backend
pip install -r requirements.txt
playwright install chromium
```

### Step 2: Frontend Setup

```bash
cd frontend
npm install
```

### Step 3: Verify Installation

**Backend:**
```bash
cd backend
python mcp_server.py
```
Should start on http://127.0.0.1:8000

**Frontend:**
```bash
cd frontend
npm start
```
Should open http://localhost:3000

## Running the Application

### Windows (Quick Start)
1. Double-click `backend\start_backend.bat`
2. In new window, double-click `frontend\start_frontend.bat`

### Manual Start

**Terminal 1:**
```bash
cd backend
python mcp_server.py
```

**Terminal 2:**
```bash
cd frontend
npm start
```

## First Scan

1. Open browser to http://localhost:3000
2. Enter a target domain (e.g., `example.com`)
3. Select scanning tools
4. Click "Start Security Scan"
5. Monitor progress in "Progress" tab
6. View results in "Report" tab

## Troubleshooting

### "Tool not found" errors
- Verify tool is installed: `nmap --version`
- Check PATH environment variable
- Restart terminal/IDE after PATH changes

### Backend won't start
- Check Python version: `python --version` (need 3.11+)
- Install dependencies: `pip install -r requirements.txt`
- Check port 8000 is available

### Frontend won't start
- Check Node version: `node --version` (need 18+)
- Clear cache: `npm cache clean --force`
- Delete node_modules and reinstall: `rm -rf node_modules && npm install`

### PDF export fails
- Install Playwright: `playwright install chromium`
- Check Playwright: `python -m playwright --version`

### CORS errors
- Ensure backend is running on 127.0.0.1:8000
- Check frontend is on localhost:3000
- Verify CORS settings in `mcp_server.py`

## Next Steps

- Read [README.md](README.md) for detailed documentation
- Review API documentation at http://127.0.0.1:8000/docs
- Check scan history for previous results
- Export reports in PDF/JSON/CSV formats

---

**⚠️ Remember**: Only scan authorized targets!


