# dashboard.py — WiFi Sentinel web dashboard

import json
import os
import signal
import subprocess
import threading
import uuid
import tempfile
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from config import (
    DASHBOARD_PASSWORD,
    DASHBOARD_SECRET_KEY,
    SCAN_INTERVAL,
    WHITELIST_FILE,
    LOG_FILE
)

app = Flask(__name__)

# Generate a new token every server start — invalidates all existing sessions
_token_file = os.path.join(tempfile.gettempdir(), "wifisentinel.token")
_session_token = str(uuid.uuid4())
with open(_token_file, "w") as _tf:
    _tf.write(_session_token)

app.secret_key = DASHBOARD_SECRET_KEY + _session_token
app.config.update(
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_NAME="wifisentinel_session"
)

# Track active sessions via heartbeat {session_id: last_heartbeat_timestamp}
_active_sessions = {}
_sessions_lock = threading.Lock()

scheduler_process = None
scheduler_running = False
scan_in_progress = False
scan_results_cache = []


# ── Session cleanup thread ────────────────────────────────────────────────────

def _session_cleanup():
    """Background thread — expires sessions that haven't sent a heartbeat in 15 seconds"""
    while True:
        import time
        time.sleep(5)
        now = datetime.now()
        with _sessions_lock:
            expired = [sid for sid, ts in _active_sessions.items()
                       if (now - ts).total_seconds() > 3]
            for sid in expired:
                del _active_sessions[sid]

_cleanup_thread = threading.Thread(target=_session_cleanup, daemon=True)
_cleanup_thread.start()


# ── Auth ──────────────────────────────────────────────────────────────────────

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        # Check session exists
        if not session.get("logged_in"):
            return redirect(url_for("login"))

        # Verify server token matches this instance
        try:
            with open(_token_file, "r") as tf:
                current_token = tf.read().strip()
            if session.get("server_token") != current_token:
                session.clear()
                return redirect(url_for("login"))
        except Exception:
            session.clear()
            return redirect(url_for("login"))

        # Verify heartbeat is still active
        sid = session.get("session_id")
        with _sessions_lock:
            if sid not in _active_sessions:
                session.clear()
                return redirect(url_for("login"))

        return f(*args, **kwargs)
    return decorated


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        if request.form.get("password") == DASHBOARD_PASSWORD:
            sid = str(uuid.uuid4())
            session["logged_in"] = True
            session["server_token"] = _session_token
            session["session_id"] = sid
            with _sessions_lock:
                _active_sessions[sid] = datetime.now()
            return redirect(url_for("network"))
        error = "Incorrect password"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    sid = session.get("session_id")
    if sid:
        with _sessions_lock:
            _active_sessions.pop(sid, None)
    session.clear()
    return redirect(url_for("login"))


@app.route("/api/heartbeat", methods=["POST"])
def heartbeat():
    """Browser calls this every 10 seconds to keep session alive"""
    sid = session.get("session_id")
    if not sid:
        return jsonify({"status": "expired"})
    with _sessions_lock:
        if sid not in _active_sessions:
            return jsonify({"status": "expired"})
        _active_sessions[sid] = datetime.now()
    return jsonify({"status": "ok"})


# ── Pages ─────────────────────────────────────────────────────────────────────

@app.route("/")
@login_required
def network():
    whitelist = load_json(WHITELIST_FILE)
    last_scan_results = load_json("last_scan_results.json")
    if isinstance(last_scan_results, dict):
        last_scan_results = list(last_scan_results.values())
    last_scan = "Never"
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()
            if lines:
                last_line = lines[-1].strip()
                if last_line.startswith("["):
                    last_scan = last_line[1:20]
    return render_template("network.html",
        devices=whitelist,
        scheduler_running=scheduler_running,
        last_scan=last_scan,
        last_scan_results=last_scan_results
    )


@app.route("/history")
@login_required
def history():
    logs = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            logs = f.readlines()
    logs.reverse()
    return render_template("history.html", logs=logs)


@app.route("/flagged")
@login_required
def flagged():
    devices = load_json("flagged_devices.json")
    return render_template("flagged.html", devices=devices)


@app.route("/settings")
@login_required
def settings():
    import importlib
    import config as cfg
    importlib.reload(cfg)
    return render_template("settings.html",
        scan_interval=cfg.SCAN_INTERVAL,
        scheduler_running=scheduler_running,
        notifications_enabled=cfg.ENABLE_DESKTOP,
        auto_launch=cfg.AUTO_LAUNCH,
        auto_launch_scheduler=cfg.AUTO_LAUNCH_SCHEDULER
    )


# ── API endpoints ─────────────────────────────────────────────────────────────

@app.route("/api/scan", methods=["POST"])
@login_required
def trigger_scan():
    """Start a scan in a background thread"""
    global scan_in_progress, scan_results_cache
    if scan_in_progress:
        return jsonify({"status": "error", "message": "Scan already in progress"})
    scan_in_progress = True
    scan_results_cache = []
    thread = threading.Thread(target=run_scan_thread)
    thread.daemon = True
    thread.start()
    return jsonify({"status": "success", "message": "Scan started"})


def run_scan_thread():
    """Runs the actual scan in the background"""
    global scan_in_progress, scan_results_cache
    try:
        from scanner import log_event
        from config import SUDO_PASSWORD

        result = subprocess.run(
            ["sudo", "-S", "venv/bin/python", "-c",
             "from scanner import scan_network, check_for_intruders, load_whitelist, lookup_vendor; "
             "import json; "
             "devices = scan_network(); "
             "whitelist = load_whitelist(); "
             "unknown = {mac: {**info, 'mac': mac, 'vendor': lookup_vendor(mac)} for mac, info in check_for_intruders(devices, whitelist).items()}; "
             "print(json.dumps({'devices': devices, 'unknown': list(unknown.values())}))"],
            input=f"{SUDO_PASSWORD}\n",
            capture_output=True,
            text=True,
            timeout=120
        )

        if result.returncode != 0:
            print(f"Scan stderr: {result.stderr}")
            scan_results_cache = []
            return

        output = result.stdout.strip()
        for line in output.splitlines():
            if line.startswith("{"):
                data = json.loads(line)
                unknown = data.get("unknown", [])
                devices = data.get("devices", {})

                if unknown:
                    for device in unknown:
                        log_event(f"⚠️  UNKNOWN DEVICE — IP: {device['ip']} | MAC: {device['mac']} | Vendor: {device['vendor']}")
                else:
                    log_event(f"Scan complete. {len(devices)} device(s) found. All trusted.")

                scan_results_cache = unknown
                save_json("last_scan_results.json", unknown)
                break

    except Exception as e:
        import traceback
        print(f"Scan error: {e}")
        traceback.print_exc()
        scan_results_cache = []
    finally:
        scan_in_progress = False


@app.route("/api/scan/status", methods=["GET"])
@login_required
def scan_status():
    return jsonify({
        "in_progress": scan_in_progress,
        "unknown": scan_results_cache
    })


@app.route("/api/scan/clear-results", methods=["POST"])
@login_required
def clear_scan_results():
    save_json("last_scan_results.json", [])
    return jsonify({"status": "success"})


@app.route("/api/scheduler/start", methods=["POST"])
@login_required
def start_scheduler():
    global scheduler_process, scheduler_running
    if not scheduler_running:
        scheduler_process = subprocess.Popen(["sudo", "venv/bin/python", "scheduler.py"])
        scheduler_running = True
    return jsonify({"status": "success", "running": scheduler_running})


@app.route("/api/scheduler/stop", methods=["POST"])
@login_required
def stop_scheduler():
    global scheduler_process, scheduler_running
    if scheduler_process:
        scheduler_process.terminate()
        scheduler_running = False
    return jsonify({"status": "success", "running": scheduler_running})


@app.route("/api/interval", methods=["POST"])
@login_required
def update_interval():
    interval = request.json.get("interval")
    if not interval or not str(interval).isdigit():
        return jsonify({"status": "error", "message": "Invalid interval"})
    with open("config.py", "r") as f:
        content = f.read()
    lines = content.splitlines()
    for i, line in enumerate(lines):
        if line.startswith("SCAN_INTERVAL"):
            lines[i] = f"SCAN_INTERVAL = {interval}"
            break
    with open("config.py", "w") as f:
        f.write("\n".join(lines))
    return jsonify({"status": "success", "interval": interval})


@app.route("/api/whitelist/remove", methods=["POST"])
@login_required
def remove_from_whitelist():
    mac = request.json.get("mac")
    whitelist = load_json(WHITELIST_FILE)
    if mac in whitelist:
        del whitelist[mac]
        save_json(WHITELIST_FILE, whitelist)
        return jsonify({"status": "success"})
    return jsonify({"status": "error", "message": "Device not found"})


@app.route("/api/whitelist/edit", methods=["POST"])
@login_required
def edit_whitelist_device():
    mac = request.json.get("mac")
    vendor = request.json.get("vendor")
    device_name = request.json.get("device_name")
    whitelist = load_json(WHITELIST_FILE)
    if mac in whitelist:
        if vendor:
            whitelist[mac]["vendor"] = vendor
        if device_name:
            whitelist[mac]["device_name"] = device_name
        save_json(WHITELIST_FILE, whitelist)
        return jsonify({"status": "success"})
    return jsonify({"status": "error", "message": "Device not found"})


@app.route("/api/whitelist/flag", methods=["POST"])
@login_required
def flag_from_whitelist():
    mac = request.json.get("mac")
    whitelist = load_json(WHITELIST_FILE)
    if mac in whitelist:
        info = whitelist[mac]
        info["flagged_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        flagged = load_json("flagged_devices.json")
        flagged[mac] = info
        save_json("flagged_devices.json", flagged)
        del whitelist[mac]
        save_json(WHITELIST_FILE, whitelist)
        return jsonify({"status": "success"})
    return jsonify({"status": "error", "message": "Device not found"})


@app.route("/api/whitelist/flag-new", methods=["POST"])
@login_required
def flag_new_device():
    mac = request.json.get("mac")
    ip = request.json.get("ip", "Unknown")
    vendor = request.json.get("vendor", "Unknown")
    from scanner import flag_device
    flag_device(mac, {"ip": ip, "vendor": vendor, "hostname": "Unknown"})
    return jsonify({"status": "success"})


@app.route("/api/whitelist/add", methods=["POST"])
@login_required
def add_to_whitelist():
    mac = request.json.get("mac")
    ip = request.json.get("ip")
    hostname = request.json.get("hostname")
    vendor = request.json.get("vendor", "Unknown")
    device_name = request.json.get("device_name", "")
    whitelist = load_json(WHITELIST_FILE)
    whitelist[mac] = {
        "ip": ip,
        "hostname": hostname,
        "vendor": vendor,
        "device_name": device_name,
        "last_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    save_json(WHITELIST_FILE, whitelist)
    from scanner import log_event
    log_event(f"Device added to whitelist: {mac} | {ip} | {vendor} | {device_name}")
    return jsonify({"status": "success"})


@app.route("/api/flagged/clear", methods=["POST"])
@login_required
def clear_flagged():
    save_json("flagged_devices.json", {})
    return jsonify({"status": "success"})


@app.route("/api/flagged/dismiss", methods=["POST"])
@login_required
def dismiss_flagged():
    mac = request.json.get("mac")
    flagged = load_json("flagged_devices.json")
    if mac in flagged:
        del flagged[mac]
        save_json("flagged_devices.json", flagged)
        from scanner import log_event
        log_event(f"Flagged device dismissed: {mac}")
        return jsonify({"status": "success"})
    return jsonify({"status": "error", "message": "Device not found"})


@app.route("/api/flagged/whitelist", methods=["POST"])
@login_required
def flagged_to_whitelist():
    mac = request.json.get("mac")
    vendor = request.json.get("vendor", "Unknown")
    device_name = request.json.get("device_name", "")
    flagged = load_json("flagged_devices.json")
    if mac in flagged:
        info = flagged[mac]
        info["vendor"] = vendor
        info["device_name"] = device_name
        info["last_seen"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        whitelist = load_json(WHITELIST_FILE)
        whitelist[mac] = info
        save_json(WHITELIST_FILE, whitelist)
        del flagged[mac]
        save_json("flagged_devices.json", flagged)
        from scanner import log_event
        log_event(f"Device moved from flagged to whitelist: {mac} | {info.get('ip')} | {vendor} | {device_name}")
        return jsonify({"status": "success"})
    return jsonify({"status": "error", "message": "Device not found"})


@app.route("/api/flagged/lookup", methods=["POST"])
@login_required
def retry_vendor_lookup():
    mac = request.json.get("mac")
    from scanner import lookup_vendor
    vendor = lookup_vendor(mac)
    flagged = load_json("flagged_devices.json")
    if mac in flagged:
        flagged[mac]["vendor"] = vendor
        save_json("flagged_devices.json", flagged)
    return jsonify({"status": "success", "vendor": vendor})


@app.route("/api/notifications/toggle", methods=["POST"])
@login_required
def toggle_notifications():
    enabled = request.json.get("enabled")
    key = request.json.get("key", "ENABLE_DESKTOP")
    try:
        _update_config(key, enabled)
        return jsonify({"status": "success", "enabled": enabled})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


@app.route("/api/startup/enable", methods=["POST"])
@login_required
def enable_startup():
    try:
        _update_config("AUTO_LAUNCH", True)
        return jsonify({"status": "success", "message": "Auto-launch enabled — use start.sh to launch"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


@app.route("/api/startup/disable", methods=["POST"])
@login_required
def disable_startup():
    try:
        _update_config("AUTO_LAUNCH", False)
        return jsonify({"status": "success", "message": "Auto-launch disabled"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


# ── Startup helpers ───────────────────────────────────────────────────────────

def _update_config(key, value):
    """Update a key in config.py"""
    with open("config.py", "r") as f:
        lines = f.read().splitlines()
    for i, line in enumerate(lines):
        if line.startswith(key):
            lines[i] = f"{key} = {value}"
            break
    with open("config.py", "w") as f:
        f.write("\n".join(lines))


# ── Helpers ───────────────────────────────────────────────────────────────────

def load_json(filepath):
    if not os.path.exists(filepath):
        return {}
    with open(filepath, "r") as f:
        content = f.read().strip()
        if not content or content == "{}":
            return {}
        return json.loads(content)


def save_json(filepath, data):
    with open(filepath, "w") as f:
        json.dump(data, f, indent=4)


# ── Run ───────────────────────────────────────────────────────────────────────

def free_port(port):
    """Kill any process using the specified port"""
    try:
        result = subprocess.run(
            ["lsof", "-ti", f":{port}"],
            capture_output=True,
            text=True
        )
        pids = result.stdout.strip().split("\n")
        for pid in pids:
            if pid:
                os.kill(int(pid), signal.SIGKILL)
                print(f"   Stopped existing instance (PID {pid})")
    except Exception:
        pass


if __name__ == "__main__":
    free_port(5001)
    print("\n🛡️  WiFi Sentinel Dashboard")
    print("   Open http://localhost:5001 in your browser\n")
    app.run(debug=False, host="0.0.0.0", port=5001)