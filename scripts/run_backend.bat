@echo off
cd /d "%~dp0.."
.venv\Scripts\python.exe -m uvicorn backend.app:app --port 8000 --reload
