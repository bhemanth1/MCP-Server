# 🔧 Tool Installation Guide

This guide provides step-by-step instructions to install all required scanning tools for MCP Scanner on different operating systems.

## Required Tools

- **nmap** - Network mapper for port scanning
- **subfinder** - Subdomain discovery tool  
- **nikto** - Web vulnerability scanner
- **gobuster** - Directory/file brute-forcer
- **nslookup** - DNS lookup (usually pre-installed)
- **traceroute** - Network path tracing (usually pre-installed)

---

## Windows Installation

### Option 1: Using Chocolatey (Recommended)

1. **Install Chocolatey** (if not already installed):
   ```powershell
   Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
   ```

2. **Install Tools**:
   ```powershell
   choco install nmap -y
   ```

3. **Install Go** (required for subfinder and gobuster):
   ```powershell
   choco install golang -y
   ```

4. **Install Go-based tools** (after Go installation):
   ```powershell
   # Add Go bin to PATH if not already added
   $env:Path += ";$env:USERPROFILE\go\bin"
   
   # Install subfinder
   go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
   
   # Install gobuster
   go install github.com/OJ/gobuster/v3@latest
   ```

5. **Install Nikto**:
   - Download from: https://github.com/sullo/nikto
   - Or use WSL (Windows Subsystem for Linux):
     ```powershell
     wsl --install
     wsl
     sudo apt-get update
     sudo apt-get install nikto
     ```

### Option 2: Manual Installation

1. **Nmap**:
   - Download installer from: https://nmap.org/download.html
   - Run installer and add to PATH

2. **Go**:
   - Download from: https://golang.org/dl/
   - Install and add Go bin directory to PATH:
     - `C:\Users\<YourUsername>\go\bin`

3. **Subfinder & Gobuster**:
   ```powershell
   go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
   go install github.com/OJ/gobuster/v3@latest
   ```

4. **Nikto** (via WSL):
   ```powershell
   # In WSL terminal
   sudo apt-get update
   sudo apt-get install nikto
   ```

---

## Linux (Debian/Ubuntu)

```bash
# Update package list
sudo apt-get update

# Install tools
sudo apt-get install -y nmap nikto dnsutils traceroute

# Install Go
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc

# Install Go-based tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/OJ/gobuster/v3@latest

# Add Go bin to PATH
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
source ~/.bashrc
```

## Linux (RHEL/CentOS/Fedora)

```bash
# Install tools
sudo yum install -y nmap nikto bind-utils traceroute

# For Fedora:
sudo dnf install -y nmap nikto bind-utils traceroute

# Install Go (same as Debian/Ubuntu)
# Then install Go-based tools (same as above)
```

---

## macOS

```bash
# Install Homebrew (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install tools
brew install nmap nikto go

# Install Go-based tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/OJ/gobuster/v3@latest

# Add Go bin to PATH (if not already in ~/.zshrc)
echo 'export PATH=$PATH:~/go/bin' >> ~/.zshrc
source ~/.zshrc
```

---

## Verification

After installation, verify all tools are available:

```bash
# Check each tool
nmap --version
subfinder -version
nikto -Version
gobuster -h
nslookup -?
tracert -h  # Windows
traceroute -h  # Linux/macOS
```

---

## Troubleshooting

### Tool Not Found in PATH

**Windows:**
1. Add tool directory to System Environment Variables
2. Restart terminal/PowerShell
3. Verify: `$env:Path`

**Linux/macOS:**
1. Check if tool is in PATH: `which <tool-name>`
2. Add to PATH if needed: `export PATH=$PATH:/path/to/tool`
3. Make permanent: Add to `~/.bashrc` or `~/.zshrc`

### Go Tools Not Found

1. Verify Go installation: `go version`
2. Check Go bin directory: `echo $GOPATH/bin` or `echo $HOME/go/bin`
3. Add to PATH if missing
4. Reinstall tools after PATH fix

### Nikto Issues on Windows

- Use WSL (Windows Subsystem for Linux) for best compatibility
- Or download Windows version from GitHub releases
- Ensure Perl is installed (Nikto dependency)

---

## Quick Install Scripts

### Windows PowerShell (Run as Administrator)
```powershell
# Install Chocolatey
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Install tools
choco install nmap golang -y

# Install Go tools
$env:Path += ";$env:USERPROFILE\go\bin"
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/OJ/gobuster/v3@latest

Write-Host "Installation complete! Please restart your terminal."
```

### Linux (Debian/Ubuntu)
```bash
#!/bin/bash
sudo apt-get update
sudo apt-get install -y nmap nikto dnsutils traceroute golang-go

# Install Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/OJ/gobuster/v3@latest

echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
source ~/.bashrc

echo "Installation complete!"
```

---

## Next Steps

After installing all tools:

1. **Verify Installation**: Check all tools are accessible from command line
2. **Restart Backend**: Restart the MCP backend server
3. **Test Scan**: Run a test scan to verify all tools work
4. **Check Tool Status**: Visit `http://127.0.0.1:8000/tools` to see tool availability

---

**Note**: Some tools may require administrator/sudo privileges for certain scan types.


