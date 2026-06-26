# ─── scraper.py ───────────────────────────────────────────────────────────────
# Core browser automation for the TikTok Scam Scanner.
# Opens TikTok via Playwright, scrolls through videos, extracts metadata,
# likes flagged videos, and passes data to the scam detector and sheet logger.
# ──────────────────────────────────────────────────────────────────────────────

import json
import os
from datetime import datetime
from playwright.sync_api import sync_playwright

from scam_detector import score_video, is_scam, get_scam_reasons, get_score_label
from sheet_logger import log_to_sheet, get_log_count
from config import (
    TIKTOK_URL,
    VIDEOS_PER_RUN,
    COOKIES_FILE,
    HEADLESS,
    PAGE_LOAD_WAIT_MS,
    SCROLL_WAIT_MS,
    USER_DATA_DIR
)


class TikTokScraper:

    def run(self):
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"\n[{timestamp}] ── Starting scan ──────────────────────────────")

        with sync_playwright() as p:
            context, _, page = self._launch_browser(p)

            try:
                self._open_tiktok(page)
                self._scroll_and_scan(page)
            finally:
                context.close()  # close context, not browser

        total = get_log_count()
        print(f"[{datetime.now().strftime('%H:%M:%S')}] ── Scan complete. Total logged: {total} ────────────\n")

    def _launch_browser(self, playwright):
        context = playwright.chromium.launch_persistent_context(
            user_data_dir=USER_DATA_DIR,
            headless=HEADLESS,
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            viewport={"width": 1280, "height": 800}
        )

        self._load_cookies(context)

        page = context.new_page()
        return context, context, page  # no separate browser object

    def _open_tiktok(self, page):
        print(f"  [BROWSER] Opening {TIKTOK_URL} ...")
        page.goto(TIKTOK_URL)
        page.wait_for_timeout(PAGE_LOAD_WAIT_MS)
        print(f"  [BROWSER] Page loaded.")


    def _scroll_and_scan(self, page):
        for i in range(VIDEOS_PER_RUN):
            print(f"\n  ── Video {i + 1}/{VIDEOS_PER_RUN} ──────────────────")

            video_data = self._extract_video_data(page)

            if not video_data:
                print("  [SKIP] Could not extract video data. Moving on.")
                self._scroll_to_next(page)
                continue

            print(f"  Author : {video_data['author'] or 'Unknown'}")
            print(f"  Caption: {video_data['description'][:80] or 'No caption'}...")

            score  = score_video(video_data)
            label  = get_score_label(score)
            print(f"  Score  : {score} ({label})")

            if is_scam(video_data):
                reasons = get_scam_reasons(video_data)
                print(f"  ⚠️  FLAGGED — Reasons: {', '.join(reasons)}")
                self._like_video(page)
                log_to_sheet(video_data, score, label, reasons)
            else:
                print(f"  ✅ Clean — no action taken.")

            self._scroll_to_next(page)


    def _extract_video_data(self, page) -> dict | None:
        try:
            
            page.wait_for_selector("[data-e2e='desc-span-0']", timeout=10000)
            
            # data-e2e subject to change, if they do then inspect tiktok page
            description = self._safe_text(page, "[data-e2e='desc-span-0']")
            author      = self._safe_text(page, "[data-e2e='username']")
            likes       = self._safe_text(page, "[data-e2e='like-count']")
            comments    = self._safe_text(page, "[data-e2e='comment-count']")
            shares      = self._safe_text(page, "[data-e2e='share-count']")
            
            print(description)
            print(author)
            print(likes)

            return {
                "url":         page.url,
                "author":      author,
                "description": description,
                "likes":       likes,
                "comments":    comments,
                "shares":      shares,
                "timestamp":   datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

        except Exception as e:
            print(f"  [ERROR] Data extraction failed: {e}")
            return None


    def _like_video(self, page):
        try:
            like_btn = page.locator("[data-e2e='browse-like-icon']").first
            like_btn.click()
            page.wait_for_timeout(1000)
            print("  [LIKED] Like sent ✓")
        except Exception as e:
            print(f"  [ERROR] Could not like video: {e}")


    def _scroll_to_next(self, page):
        page.keyboard.press("ArrowDown")
        page.wait_for_timeout(SCROLL_WAIT_MS)


    def _load_cookies(self, context):
        flag_file = "./browser_profile/.cookies_loaded"
        
        # If we've already seeded cookies before, skip
        if os.path.exists(flag_file):
            print("  [AUTH] Using existing browser profile ✓")
            return

        try:
            with open(COOKIES_FILE, "r", encoding="utf-8-sig") as f:
                cookies = json.load(f)

            SAME_SITE_MAP = {
                "no_restriction": "None",
                "lax":            "Lax",
                "strict":         "Strict",
                "none":           "None",
            }

            for cookie in cookies:
                raw = (cookie.get("sameSite") or "").lower()
                cookie["sameSite"] = SAME_SITE_MAP.get(raw, "Lax")
                if cookie["sameSite"] == "None":
                    cookie["secure"] = True
                cookie.pop("storeId", None)
                cookie.pop("hostOnly", None)
                cookie.pop("session", None)

            context.add_cookies(cookies)

            # Mark that we've seeded the profile
            os.makedirs("./browser_profile", exist_ok=True)
            open(flag_file, "w").close()

            print(f"  [AUTH] Cookies seeded into browser profile ✓")
        except FileNotFoundError:
            print(f"  [WARN] '{COOKIES_FILE}' not found — running without login.")
        except json.JSONDecodeError:
            print(f"  [ERROR] '{COOKIES_FILE}' is not valid JSON.")

    def _safe_text(self, page, selector: str, timeout: int = 3000) -> str:
        try:
            return page.locator(selector).first.inner_text(timeout=timeout).strip()
        except Exception:
            return ""