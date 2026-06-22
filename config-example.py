# config.example.py — copy this to config.py and fill in your values

NETWORK_RANGE = "192.168.1.0/24"
SCAN_INTERVAL = 15

TWILIO_ACCOUNT_SID = "your_account_sid_here"
TWILIO_AUTH_TOKEN = "your_auth_token_here"
TWILIO_FROM_NUMBER = "+1XXXXXXXXXX"
TWILIO_TO_NUMBER = "+1XXXXXXXXXX"

ENABLE_SMS = False
ENABLE_DESKTOP = True

LOG_FILE = "scan_log.txt"
WHITELIST_FILE = "whitelist.json"

# Dashboard settings
DASHBOARD_PASSWORD = "your_password_here"
DASHBOARD_SECRET_KEY = "change_this_to_a_random_string"
SUDO_PASSWORD = "your_mac_login_password_here"

AUTO_LAUNCH = False
AUTO_LAUNCH_SCHEDULER = False

#Stealth mode settings
STEALTH_MODE = False
STEALTH_TIMING = "T2"  # Options: T1, T2, T3
STEALTH_HOSTNAME = " "  # Set to a common device name like "iPhone" or "Android" to blend in with typical network traffic