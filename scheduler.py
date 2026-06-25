import schedule
import time
from config import SCAN_INTERVAL
from scanner import run_scan

def job():
    print("\n⏰ Starting scheduled scan...")
    run_scan()
    
def start_scheduler():
    print(f"🚀 WiFi Sentinel is running - scanning every {SCAN_INTERVAL} minutes.")
    print("Press Ctrl+C to stop.\n")

    job() 

    schedule.every(SCAN_INTERVAL).minutes.do(job)
    try:
        while True:
            schedule.run_pending()
            time.sleep(30)
    except KeyboardInterrupt:
        print("\n👋 WiFi Sentinel stopped. Stay safe out there!")

if __name__ == "__main__":
    start_scheduler()