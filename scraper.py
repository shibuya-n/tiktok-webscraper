import json
from datetime import datetime
from playwright.sync_api import sync_playwright

from scam_detector import score_video, is_scam, get_scam_reasons, get_score_label
from sheet_logger import log_to_sheet, get_log_count
from config import (
    TIKTOK_URL, VIDEOS_PER_RUN, COOKIES_FILE,
    HEADLESS, PAGE_LOAD_WAIT_MS, SCROLL_WAIT_MS
)

class TikTokScraper:

    def run(self):
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"\n[{timestamp}] ── Starting scan ──────────────────────────────")
        with sync_playwright() as p:
            browser, context, page = self._launch_browser(p)
            try:
                self._open_tiktok(page)
                self._scroll_and_scan(page)
            finally:
                browser.close()
        total = get_log_count()