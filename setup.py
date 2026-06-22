# setup.py — first-run setup wizard for WiFi Sentinel

import os
import sys
import platform
import subprocess
import shutil


OS = platform.system()


def print_header():
    print("""
╔══════════════════════════════════════╗
║         WiFi Sentinel Setup          ║
║   Cross-platform network monitor     ║
╚══════════════════════════════════════╝
    """)


def check_python():
    """Make sure Python version is 3.8 or higher"""
    print("🔍 Checking Python version...")
    major, minor = sys.version_info[:2]
    if major < 3 or minor < 8:
        print(f"❌ Python 3.8+ required. You have {major}.{minor}")
        sys.exit(1)
    print(f"✅ Python {major}.{minor} detected")


def check_nmap():
    """Check if nmap is installed, give OS-specific install instructions"""
    print("\n🔍 Checking for nmap...")
    if shutil.which("nmap"):
        print("✅ nmap is installed")
        return True

    print("❌ nmap not found. Install it using:")
    if OS == "Darwin":
        print("   brew install nmap")
    elif OS == "Windows":
        print("   Download from: https://nmap.org/download.html")
        print("   Make sure to add nmap to your PATH during installation")
    elif OS == "Linux":
        print("   sudo apt install nmap   (Debian/Ubuntu)")
        print("   sudo dnf install nmap   (Fedora/RHEL)")
    return False


def install_packages():
    """Install required Python packages"""
    print("\n📦 Installing required packages...")
    packages = ["python-nmap", "twilio", "plyer", "schedule", "certifi", "flask", "flask-session"]

    if OS == "Darwin":
        packages.append("pyobjus")
    elif OS == "Windows":
        packages.append("win10toast")

    for package in packages:
        print(f"   Installing {package}...")
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", package],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            print(f"   ✅ {package}")
        else:
            print(f"   ⚠️  {package} failed — you may need to install manually")


def setup_config():
    """Create config.py from template if it doesn't exist"""
    print("\n⚙️  Setting up config...")
    if os.path.exists("config.py"):
        print("✅ config.py already exists — skipping")
        return

    if not os.path.exists("config-example.py"):
        print("❌ config-example.py not found. Make sure you cloned the full repo.")
        sys.exit(1)

    with open("config-example.py", "r") as f:
        content = f.read()

    # Auto-detect common network ranges by OS
    if OS == "Windows":
        content = content.replace(
            'NETWORK_RANGE = "192.168.1.0/24"',
            'NETWORK_RANGE = "192.168.1.0/24"  # Common for Windows — check ipconfig'
        )
    elif OS == "Linux":
        content = content.replace(
            'NETWORK_RANGE = "192.168.1.0/24"',
            'NETWORK_RANGE = "192.168.1.0/24"  # Common for Linux — check ip addr'
        )

    with open("config.py", "w") as f:
        f.write(content)

    print("✅ config.py created from template")
    print("⚠️  Open config.py and set your NETWORK_RANGE before running the scanner")


def print_next_steps():
    """Print OS-specific instructions for running the scanner"""
    print("""
╔══════════════════════════════════════╗
║           Setup Complete!            ║
╚══════════════════════════════════════╝
    """)
    print("📋 Next steps:\n")

    if OS == "Darwin":
        print("   1. Open config.py and set your NETWORK_RANGE")
        print("      Run: ipconfig getifaddr en0  to find your IP")
        print("   2. Run the scanner:")
        print("      sudo venv/bin/python scanner.py")
        print("   3. Run on a schedule:")
        print("      sudo venv/bin/python scheduler.py")

    elif OS == "Windows":
        print("   1. Open config.py and set your NETWORK_RANGE")
        print("      Run: ipconfig in Command Prompt to find your IP")
        print("   2. Open Command Prompt as Administrator and run:")
        print("      venv\\Scripts\\python scanner.py")
        print("   3. Run on a schedule:")
        print("      venv\\Scripts\\python scheduler.py")

    elif OS == "Linux":
        print("   1. Open config.py and set your NETWORK_RANGE")
        print("      Run: ip addr  to find your IP")
        print("   2. Run the scanner:")
        print("      sudo venv/bin/python scanner.py")
        print("   3. Run on a schedule:")
        print("      sudo venv/bin/python scheduler.py")

    print("\n🛡️  Happy monitoring!\n")


def run():
    print_header()
    check_python()
    nmap_ready = check_nmap()
    install_packages()
    setup_config()
    print_next_steps()

    if not nmap_ready:
        print("⚠️  Remember to install nmap before running the scanner!\n")


if __name__ == "__main__":
    run()