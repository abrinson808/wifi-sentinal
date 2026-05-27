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
- 🚩 Flags unrecognized devices to a separate log for review
- 📝 Logs all scan activity with timestamps
- ⏰ Runs automatically in the background on a configurable schedule
- 🛠️ Setup wizard that works on any OS
- 🌐 Web dashboard to monitor and manage your network from a browser
- ⚙️ Dashboard settings to control scheduler, scan interval, and notifications
- 💾 Scan results persist across page navigation
- 🔒 Session expires on server restart requiring password re-entry

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
# Manual scan
sudo venv/bin/python scanner.py

# Interactive mode (recommended)
sudo venv/bin/python scanner.py --interactive

# Run on a schedule
sudo venv/bin/python scheduler.py

# Launch the web dashboard (user friendly)
venv/bin/python dashboard.py
```

**Windows (Command Prompt as Administrator):**

```bash
# Manual scan
venv\Scripts\python scanner.py

# Interactive mode (recommended)
venv\Scripts\python scanner.py --interactive

# Run on a schedule
venv\Scripts\python scheduler.py

# Launch the web dashboard (user friendly)
venv\Scripts\python dashboard.py
```

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
├── templates/              # HTML templates for dashboard
│   ├── base.html           # shared nav and layout
│   ├── login.html          # password login page
│   ├── network.html        # live network and scan controls
│   ├── history.html        # scan history log
│   ├── flagged.html        # flagged devices
│   └── settings.html       # scheduler, notifications, manual scan
├── static/css/style.css    # dashboard stylesheet
├── whitelist.json          # trusted devices (gitignored)
├── flagged_devices.json    # unrecognized devices log (gitignored)
├── scan_log.txt            # scan history (gitignored)
├── config.py               # your settings (gitignored)
├── config.example.py       # safe template for config
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
- [x] Session security
- [ ] Auto-launch on startup
- [ ] Email alerts via Gmail SMTP

---

## Author

Built by [@abrinson808](https://github.com/abrinson808)
