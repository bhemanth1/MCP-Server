@echo off
cd /d %~dp0
echo Starting MCP Backend Server...
echo Backend will run on http://127.0.0.1:8000
echo API docs available at http://127.0.0.1:8000/docs
python mcp_server.py
pause