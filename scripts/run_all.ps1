# Start the crypTen backend and dashboard together.
$root = Split-Path $PSScriptRoot -Parent
Start-Process powershell -ArgumentList "-NoExit","-Command","cd '$root'; .\.venv\Scripts\python.exe -m uvicorn backend.app:app --port 8000 --reload"
Start-Process powershell -ArgumentList "-NoExit","-Command","cd '$root\frontend'; npm run dev"
