# scanner.py — scans the network and detects unknown devices

import nmap
import json
import os
import time
import urllib.request
import platform
import sys
import argparse
from datetime import datetime
from config import NETWORK_RANGE, LOG_FILE, WHITELIST_FILE
from notifier import alert_unknown_device

def check_system():
    """Detect OS and warn if requirements aren't met"""
    os_name = platform.system()
    
    if os_name == "Windows":
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        if not is_admin:
            print("⚠️  WiFi Sentinel requires administrator privileges on Windows.")
            print("   Right-click your terminal and select 'Run as administrator'")
            sys.exit(1)
    
    elif os_name in ("Darwin", "Linux"):
        if os.geteuid() != 0:
            print("⚠️  WiFi Sentinel requires sudo on Mac/Linux.")
            print("   Run with: sudo venv/bin/python scanner.py")
            sys.exit(1)
    
    print(f"✅ Running on {os_name}")
    return os_name

def load_whitelist():
    if not os.path.exists(WHITELIST_FILE):
        return {}
    with open(WHITELIST_FILE, "r") as f:
        content = f.read().strip()
        if not content:
            return {}
        return json.loads(content)


def save_whitelist(whitelist):
    with open(WHITELIST_FILE, "w") as f:
        json.dump(whitelist, f, indent=4)

def flag_device(mac, info):
    """Save an unrecognized device to the flagged devices log"""
    if not os.path.exists("flagged_devices.json"):
        flagged = {}
    else:
        with open("flagged_devices.json", "r") as f:
            content = f.read().strip()
            flagged = json.loads(content) if content and content != "{}" else {}

    # Track how many times this device has been flagged
    existing = flagged.get(mac, {})
    count = existing.get("flag_count", 0) + 1

    flagged[mac] = {
        "ip": info.get("ip", "Unknown"),
        "vendor": info.get("vendor", "Unknown"),
        "hostname": info.get("hostname", "Unknown"),
        "flagged_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "flag_count": count
    }

    with open("flagged_devices.json", "w") as f:
        json.dump(flagged, f, indent=4)

    log_event(f"⛳ Device flagged as unrecognized: {mac} | {info.get('ip')} | {info.get('vendor', 'Unknown')} (seen {count} time(s))")
    print("  ⛳ Flagged as unrecognized\n")


def log_event(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] {message}"
    print(entry)
    with open(LOG_FILE, "a") as f:
        f.write(entry + "\n")

def lookup_vendor(mac):
    """Look up the manufacturer of a device by its MAC address, with caching"""
    if mac == "UNKNOWN":
        return "Unknown"

    # Check whitelist cache first
    whitelist = load_whitelist()
    if mac in whitelist and whitelist[mac].get("vendor"):
        return whitelist[mac]["vendor"]

    # Otherwise hit the API
    try:
        import ssl
        import certifi
        url = f"https://api.macvendors.com/{mac}"
        ctx = ssl.create_default_context(cafile=certifi.where())
        req = urllib.request.Request(url, headers={"User-Agent": "wifi-sentinel"})
        with urllib.request.urlopen(req, timeout=5, context=ctx) as response:
            vendor = response.read().decode("utf-8").strip()
            time.sleep(1)
            return vendor
    except Exception:
        return "Unknown"


def scan_network():
    print(f"\n🔍 Scanning {NETWORK_RANGE} ...")
    nm = nmap.PortScanner()
    nm.scan(hosts=NETWORK_RANGE, arguments="-sn")

    devices = {}
    for host in nm.all_hosts():
        mac = nm[host]["addresses"].get("mac", "UNKNOWN")
        hostname = nm[host].hostname() or "Unknown"
        devices[mac] = {
            "ip": host,
            "hostname": hostname,
            "last_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    return devices


def check_for_intruders(devices, whitelist):
    unknown = {}
    for mac, info in devices.items():
        if mac not in whitelist and mac != "UNKNOWN":
            unknown[mac] = info
    return unknown

def interactive_review(unknown):
    """Prompt the user to add unknown devices to the whitelist"""
    if not unknown:
        return

    whitelist = load_whitelist()
    print("\n📋 Unknown devices found — review each one:\n")

    for mac, info in unknown.items():
        print(f"  IP:          {info['ip']}")
        print(f"  MAC:         {mac}")
        print(f"  Vendor:      {info.get('vendor', 'Unknown')}")

        response = input("\n  Do you recognize this device? (y/n): ").strip().lower()

        if response == "y":
            current_vendor = info.get("vendor", "Unknown")
            custom_vendor = input(f"  Vendor name (press Enter to keep '{current_vendor}'): ").strip()
            device_name = input(f"  Device name (ex: iPhone, PS5, Smart TV — press Enter to skip): ").strip()

            if custom_vendor:
                info["vendor"] = custom_vendor
            if device_name:
                info["device_name"] = device_name

            whitelist[mac] = info
            save_whitelist(whitelist)
            log_event(f"Device added to whitelist: {mac} | {info['ip']} | {info.get('vendor', 'Unknown')} | {info.get('device_name', 'Unknown')}")
            print("  ✅ Added!\n")
        else:
            flag_device(mac, info)

def build_whitelist_from_scan():
    """First-run setup — scan and approve all current devices as known"""
    print("\n🛠  First run detected — building your whitelist...\n")
    devices = scan_network()

    if not devices:
        print("⚠️  No devices found. Check your NETWORK_RANGE in config.py")
        return

    print(f"Found {len(devices)} device(s) on your network:\n")
    for mac, info in devices.items():
        vendor = lookup_vendor(mac)
        info["vendor"] = vendor
        print(f"  IP: {info['ip']:<16} MAC: {mac:<20} Vendor: {vendor}")

    print("\n📋 Let's identify your devices before saving the whitelist.")
    print("   Press Enter to skip any field you don't know.\n")

    trusted = {}
    for mac, info in devices.items():
        print(f"  IP: {info['ip']:<16} MAC: {mac:<20} Vendor: {info.get('vendor', 'Unknown')}")

        recognized = input("  Do you recognize this device? (y/n): ").strip().lower()

        if recognized == "y":
            current_vendor = info.get("vendor", "Unknown")
            custom_vendor = input(f"  Vendor name (press Enter to keep '{current_vendor}'): ").strip()
            device_name = input(f"  Device name (ex: iPhone, PS5, Smart TV — press Enter to skip): ").strip()

            if custom_vendor:
                info["vendor"] = custom_vendor
            if device_name:
                info["device_name"] = device_name

            trusted[mac] = info
        else:
            flag_device(mac, info)

        print()

    print("Adding recognized devices to your whitelist...")
    save_whitelist(trusted)
    log_event(f"Whitelist created with {len(trusted)} trusted devices.")
    print("✅ Whitelist saved to whitelist.json\n")

def run_scan():
    check_system()
    whitelist = load_whitelist()

    if not whitelist:
        build_whitelist_from_scan()
        return

    devices = scan_network()
    unknown = check_for_intruders(devices, whitelist)

    if unknown:
        for mac, info in unknown.items():
            vendor = lookup_vendor(mac)
            message = f"⚠️  UNKNOWN DEVICE — IP: {info['ip']} | MAC: {mac} | Vendor: {vendor} | Hostname: {info['hostname']}"
            log_event(message)
            alert_unknown_device(
                mac=mac,
                ip=info['ip'],
                hostname=info['hostname'],
                vendor=vendor
            )
        return unknown
    else:
        log_event(f"Scan complete. {len(devices)} device(s) found. All trusted.")
        print("✅ All devices recognized. Network looks clean!\n")
        return {}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WiFi Sentinel — home network monitor")
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Prompt to add unknown devices to whitelist after scan"
    )
    args = parser.parse_args()

    if args.interactive:
        whitelist = load_whitelist()
        if not whitelist:
            build_whitelist_from_scan()
        else:
            devices = scan_network()
            unknown = check_for_intruders(devices, whitelist)
            if unknown:
                for mac, info in unknown.items():
                    vendor = lookup_vendor(mac)
                    info["vendor"] = vendor
                    message = f"⚠️  UNKNOWN DEVICE — IP: {info['ip']} | MAC: {mac} | Vendor: {vendor} | Hostname: {info['hostname']}"
                    log_event(message)
                alert_unknown_device(
                    mac=mac,
                    ip=info['ip'],
                    hostname=info['hostname'],
                    vendor=vendor
                )
                interactive_review(unknown)
            else:
                log_event(f"Scan complete. {len(devices)} device(s) found. All trusted.")
                print("✅ All devices recognized. Network looks clean!\n")
    else:
        run_scan()