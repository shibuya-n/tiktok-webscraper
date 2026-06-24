# ─── scraper.py ───────────────────────────────────────────────────────────────
# Core browser automation for the TikTok Scam Scanner.
# Opens TikTok via Playwright, scrolls through videos, extracts metadata,
# likes flagged videos, and passes data to the scam detector and sheet logger.
# ──────────────────────────────────────────────────────────────────────────────

import json
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
    SCROLL_WAIT_MS
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
        print(f"[{datetime.now().strftime('%H:%M:%S')}] ── Scan complete. Total logged: {total} ────────────\n")


    def _launch_browser(self, playwright):
        browser = playwright.chromium.launch(headless=HEADLESS)

        context = browser.new_context(
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            viewport={"width": 1280, "height": 800}
        )

        self._load_cookies(context)

        page = context.new_page()
        return browser, context, page


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
            description = self._safe_text(page, "[data-e2e='browse-video-desc']")
            author      = self._safe_text(page, "[data-e2e='browse-username']")
            likes       = self._safe_text(page, "[data-e2e='browse-like-count']")
            comments    = self._safe_text(page, "[data-e2e='browse-comment-count']")
            shares      = self._safe_text(page, "[data-e2e='browse-share-count']")

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
        try:
            with open(COOKIES_FILE, "r", encoding="utf-8-sig") as f:
                cookies = json.load(f)

            # Playwright only accepts "Strict", "Lax", or "None" — fix nulls
            for cookie in cookies:
                if cookie.get("sameSite") not in ("Strict", "Lax", "None"):
                    cookie["sameSite"] = "Lax"
                # "None" requires secure=True or Playwright rejects it
                if cookie.get("sameSite") == "None":
                    cookie["secure"] = True
            context.add_cookies(cookies)
            print(f"  [AUTH] Cookies loaded from '{COOKIES_FILE}' ✓")
        except FileNotFoundError:
            print(f"  [WARN] '{COOKIES_FILE}' not found — running without login.")
        except json.JSONDecodeError:
            print(f"  [ERROR] '{COOKIES_FILE}' is not valid JSON. Re-export your cookies.")


    def _safe_text(self, page, selector: str, timeout: int = 3000) -> str:
        try:
            return page.locator(selector).first.inner_text(timeout=timeout).strip()
        except Exception:
            return ""