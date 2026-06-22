# WiFi Sentinel 🛡️

A cross-platform Python network monitor that scans your WiFi for unknown
devices and sends instant desktop alerts. Works on macOS, Windows, and Linux.

Built as a personal security tool after going through the process of securing
my home network and realizing I had no way of knowing when new devices connected.

---

## Features

- 🔍 Scans your entire home network using nmap
- 📋 Maintains a whitelist of trusted devices
- 🔔 Cross-platform desktop notifications (macOS, Windows, Linux)
- 🏭 Automatic MAC vendor lookup to identify device manufacturers
- 🧑‍💻 Interactive mode to review and name unknown devices on the spot
- 🚩 Flags unrecognized devices with repeat offender tracking
- 📝 Logs all scan activity with timestamps
- ⏰ Runs automatically in the background on a configurable schedule
- 🛠️ Setup wizard that works on any OS
- 🔐 Password protected web dashboard
- ⚙️ Dashboard settings to control scheduler, scan interval, and notifications
- 💾 Scan results persist across page navigation
- 🔒 Session expires upon tab closure or disconnection
- 🚀 Single command launch script for all platforms

---

## Supported Platforms

| Platform | Notifications | Scanning | Tested |
| -------- | ------------- | -------- | ------ |
| macOS    | ✅            | ✅       | ✅     |
| Windows  | ✅            | ✅       | ✅     |
| Linux    | ✅            | ✅       | ⏳     |

---

## Tech Stack

- Python 3.8+
- [python-nmap](https://pypi.org/project/python-nmap/) — network scanning
- [plyer](https://pypi.org/project/plyer/) — cross-platform desktop notifications
- [schedule](https://pypi.org/project/schedule/) — job scheduling
- [certifi](https://pypi.org/project/certifi/) — SSL certificate handling
- [macvendors.com](https://macvendors.com/) — MAC address vendor lookup

---

## Quick Start

### 1. Prerequisites

**macOS:**

```bash
brew install nmap
```

**Windows:**
Download nmap from https://nmap.org/download.html
Make sure to check "Add to PATH" during installation.

**Linux:**

```bash
sudo apt install nmap
```

### 2. Clone the repo

```bash
git clone https://github.com/abrinson808/wifi-sentinel.git
cd wifi-sentinel
```

### 3. Create a virtual environment

**macOS/Linux:**

```bash
python3 -m venv venv
source venv/bin/activate
```

**Windows:**

```bash
python -m venv venv
venv\Scripts\activate
```

### 4. Run the setup wizard

```bash
python setup.py
```

This will install all dependencies and create your config file automatically.

### 5. Configure

Open `config.py` and set your network range:

**macOS:**

```bash
ipconfig getifaddr en0
```

**Windows:**

```bash
ipconfig
```

**Linux:**

```bash
ip addr
```

### 6. Run

**macOS/Linux:**

```bash
./start.sh
```

**Windows:**

```batch
start.bat
```

This will start the dashboard, open your browser automatically, and start the scheduler if enabled in settings.

Then open your browser and go to:

```
http://localhost:5001
```

---

## First Run

On first run, WiFi Sentinel will automatically scan your network and walk
you through building your whitelist device by device. For each device found
you will be asked:

1. Whether you recognize the device
2. To confirm or correct the vendor name
3. To give the device a name (ex: iPhone, PS5, Smart TV)

Any device you don't recognize is automatically saved to `flagged_devices.json`
for review. Devices you recognize are saved to your whitelist as trusted.
Press Enter on any field you don't know to skip it.

### Running in interactive mode

Interactive mode is recommended for day to day use. It scans your network and
prompts you to review any unknown devices directly from the terminal.

**macOS/Linux:**

```bash
sudo venv/bin/python scanner.py --interactive
```

**Windows (Command Prompt as Administrator):**

```bash
venv\Scripts\python scanner.py --interactive
```

### Unknown device flow

When an unknown device is detected in interactive mode, WiFi Sentinel will:

1. Display the device's IP, MAC address, and vendor name
2. Ask if you recognize the device
3. If yes — let you confirm the vendor name and enter a device name
4. If no — flag it to flagged_devices.json and keep alerting on future scans
5. Any input other than 'y' defaults to flagging the device as unrecognized

### Silent scheduled mode

To run WiFi Sentinel silently in the background on a schedule:

**macOS/Linux:**

```bash
sudo venv/bin/python scheduler.py
```

**Windows (Command Prompt as Administrator):**

```bash
venv\Scripts\python scheduler.py
```

---

## Project Structure

```
wifi-sentinel/
├── scanner.py              # core scanning, vendor lookup, interactive flow
├── notifier.py             # cross-platform desktop alerts
├── scheduler.py            # automatic scheduling
├── dashboard.py            # Flask web dashboard
├── setup.py                # first-run setup wizard
├── start.sh                # macOS/Linux launch script
├── start.bat               # Windows launch script
├── templates/              # HTML templates for dashboard
│   ├── base.html           # shared nav, layout, and session heartbeat
│   ├── login.html          # password login page
│   ├── network.html        # live network and scan controls
│   ├── history.html        # color coded scan history log
│   ├── flagged.html        # flagged devices with actions
│   └── settings.html       # scheduler, notifications, auto-launch
├── static/css/style.css    # dashboard stylesheet with dark/light mode
├── whitelist.json          # trusted devices (gitignored)
├── flagged_devices.json    # unrecognized devices log (gitignored)
├── scan_log.txt            # scan history (gitignored)
├── last_scan_results.json  # last scan results (gitignored)
├── config.py               # your settings (gitignored)
├── config-example.py       # safe template for config
└── README.md
```

---

## Roadmap

- [x] Cross-platform support (macOS, Windows, Linux)
- [x] MAC vendor lookup
- [x] Interactive whitelist management
- [x] Flagged devices log with repeat offender tracking
- [x] Web dashboard with live network, history, and flagged devices
- [x] Dashboard settings with scheduler controls and notification toggle
- [x] Scan results persistence across navigation
- [x] Session security with heartbeat expiry
- [x] Single command launch script
- [ ] Email alerts via Gmail SMTP

---

## Author

Built by [@abrinson808](https://github.com/abrinson808)
