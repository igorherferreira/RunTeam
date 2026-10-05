@echo off
cd /d "%~dp0"
if not exist .venv (
  python -m venv .venv
  .venv\Scripts\pip install -r requirements.txt
)
start "" cmd /c "timeout /t 3 >nul & start http://localhost:8000"
.venv\Scripts\uvicorn main:app
