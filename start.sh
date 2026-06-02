#!/bin/bash

# WiFi Sentinel Launch Script — macOS/Linux

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_DIR"

echo ""
echo "🛡️  Starting WiFi Sentinel..."
echo ""

# Activate virtual environment
source venv/bin/activate

# Check if port 5001 is already in use and kill it
PORT=5001
PID=$(lsof -ti :$PORT)
if [ ! -z "$PID" ]; then
  echo "⚠️  Port $PORT in use — stopping existing instance..."
  kill -9 $PID
  sleep 1
fi

# Start dashboard in background
echo "🌐 Starting dashboard at http://localhost:$PORT"
venv/bin/python dashboard.py &
DASHBOARD_PID=$!
echo $DASHBOARD_PID > .dashboard.pid

# Start scheduler if enabled in config
SCHEDULER_ENABLED=$(python -c "from config import AUTO_LAUNCH_SCHEDULER; print(AUTO_LAUNCH_SCHEDULER)")
if [ "$SCHEDULER_ENABLED" = "True" ]; then
  echo "⏰ Starting scheduler..."
  sudo venv/bin/python scheduler.py &
  echo $! > .scheduler.pid
fi

# Wait for dashboard to start
sleep 2

# Open browser automatically
echo "🔗 Opening browser..."
open http://localhost:$PORT

echo ""
echo "✅ WiFi Sentinel is running!"
echo "   Dashboard: http://localhost:$PORT"
echo "   Press Ctrl+C to stop"
echo ""

# Wait for dashboard process
wait $DASHBOARD_PID