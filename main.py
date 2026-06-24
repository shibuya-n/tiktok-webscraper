import schedule
import time
from scraper import TikTokScraper
from config import SCAN_INTERVAL_MINUTES


scraper = TikTokScraper()

def job():
    try:
        scraper.run()
    except Exception as e:
        print(f"[FATAL ERROR] Something went wrong during scan: {e}")


print("=" * 55)
print("   TikTok Scam Scanner")
print(f"   Running every {SCAN_INTERVAL_MINUTES} minute(s). Press Ctrl+C to stop.")
print("=" * 55)
job()

schedule.every(SCAN_INTERVAL_MINUTES).minutes.do(job)

while True:
    schedule.run_pending()
    time.sleep(1)
    