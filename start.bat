@echo off
title WiFi Sentinel

echo.
echo  WiFi Sentinel Starting...
echo.

cd /d "%~dp0"

:: Check if port 5001 is in use and kill it
for /f "tokens=5" %%a in ('netstat -aon ^| find ":5001"') do (
  echo Stopping existing instance on port 5001...
  taskkill /PID %%a /F >nul 2>&1
)

:: Start dashboard
echo Starting dashboard at http://localhost:5001
start /b venv\Scripts\python dashboard.py

:: Check if scheduler should auto start
for /f %%i in ('venv\Scripts\python -c "from config import AUTO_LAUNCH_SCHEDULER; print(AUTO_LAUNCH_SCHEDULER)"') do set SCHEDULER=%%i
if "%SCHEDULER%"=="True" (
  echo Starting scheduler...
  start /b venv\Scripts\python scheduler.py
)

:: Wait for dashboard to start
timeout /t 2 /nobreak >nul

:: Open browser
echo Opening browser...
start http://localhost:5001

echo.
echo WiFi Sentinel is running!
echo Dashboard: http://localhost:5001
echo Close this window to stop
echo.

:: Keep window open
pause