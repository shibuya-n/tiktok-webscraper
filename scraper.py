# ─── scraper.py ───────────────────────────────────────────────────────────────
# Core browser automation for the TikTok Scam Scanner.
# Opens TikTok via Playwright, scrolls through videos, extracts metadata,
# likes flagged videos, and passes data to the scam detector and sheet logger.
# ──────────────────────────────────────────────────────────────────────────────

import json
import os
import time
from datetime import datetime
from playwright.sync_api import sync_playwright

from scam_detector import score_video, is_scam, get_scam_reasons, get_score_label
from sheet_logger import log_to_sheet, get_log_count
from config import (
    DELAY_BETWEEN_VIDEOS_MS,
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
        self._dismiss_popups(page, per_selector_timeout=400)

        # TikTok seems to require a genuine user gesture (a real click)
        # before it'll honor keyboard/scroll navigation on a fresh load.
        # Click on empty space beside the video, NOT on the video itself —
        # two clicks on the video in quick succession is TikTok's
        # double-tap-to-like gesture, which was liking video 1 every run.
        try:
            page.mouse.click(1100, 400)
            page.wait_for_timeout(200)
        except Exception:
            pass

        print(f"  [BROWSER] Page loaded.")

    def _dismiss_popups(self, page, per_selector_timeout: int = 1000):
        # TikTok frequently shows a login nag / cookie banner / onboarding
        # tooltip on first load. If left alone, the first ArrowDown press
        # can get "absorbed" by closing this instead of scrolling the feed.
        close_selectors = [
            "[data-e2e='modal-close-inner-button']",
            "div[role='dialog'] button[aria-label='Close']",
            "button[aria-label='Close']",
            "[data-e2e='cookie-banner-close']",
        ]
        for sel in close_selectors:
            try:
                btn = page.locator(sel).first
                if btn.is_visible(timeout=per_selector_timeout):
                    btn.click(timeout=per_selector_timeout)
                    print(f"  [INFO] Dismissed popup ({sel})")
                    page.wait_for_timeout(300)
            except Exception:
                continue


    def _scroll_and_scan(self, page):
        last_seen = None  # (author, description) of the previously logged video

        for i in range(VIDEOS_PER_RUN):
            print(f"\n  ── Video {i + 1}/{VIDEOS_PER_RUN} ──────────────────")

            video_data = self._extract_video_data(page)

            if not video_data:
                print("  [SKIP] Could not extract video data. Moving on.")
                self._scroll_to_next(page)
                continue

            fingerprint = (video_data["author"], video_data["description"])
            if fingerprint == last_seen:
                print("  [DUPLICATE] Same video as last time — scrolling again before re-extracting.")
                self._scroll_to_next(page)
                video_data = self._extract_video_data(page)
                if not video_data:
                    print("  [SKIP] Could not extract video data after retry. Moving on.")
                    continue
                fingerprint = (video_data["author"], video_data["description"])
                if fingerprint == last_seen:
                    print("  [WARN] Still the same video after retry — logging anyway.")

            last_seen = fingerprint

            print(f"  Author : {video_data['author'] or 'Unknown'}")
            print(f"  Caption: {video_data['description'][:80] or 'No caption'}...")
            print(f"  AD? : {video_data['isAd']}")

            score  = score_video(video_data)
            label  = get_score_label(score)
            print(f"  Score  : {score} ({label})")

            if is_scam(video_data):
                reasons = get_scam_reasons(video_data)
                print(f"  ⚠️  FLAGGED — Reasons: {', '.join(reasons)}")
                #self._like_video(page)
                #log_to_sheet(video_data, score, label, reasons)
            else:
                print(f"  ✅ Clean — no action taken.")

            page.wait_for_timeout(DELAY_BETWEEN_VIDEOS_MS)

            self._scroll_to_next(page)


    def _extract_video_data(self, page) -> dict | None:
        try:
            # data-e2e subject to change, if they do then inspect tiktok page
            description = self._safe_text(page, "[data-e2e='video-desc']")
            hashtags    = self._get_hashtags(page)
            author      = self._get_author(page)
            likes       = self._safe_text(page, "[data-e2e='like-count']")
            comments    = self._safe_text(page, "[data-e2e='comment-count']")
            shares      = self._safe_text(page, "[data-e2e='share-count']")
            isAd        = self._find_ad(page)

            return {
                "url":         page.url,
                "author":      author,
                "description": description,
                "hashtags": hashtags,
                "likes":       likes,
                "comments":    comments,
                "shares":      shares,
                "isAd":        isAd,
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


    def _scroll_to_next(self, page, max_attempts: int = 3):
        # Poll using the EXACT same selectors _extract_video_data relies on,
        # instead of inspecting <video> tags directly via JS. TikTok keeps
        # multiple <video> elements mounted at once (current + preloaded
        # neighbors), and "offsetParent !== null" isn't a reliable way to
        # pick out the truly active one — it was producing false positives.
        # Comparing the same author/caption text we're about to extract
        # guarantees the success check and the actual extraction agree.
        old_caption = self._safe_text(page, "[data-e2e='video-desc']")
        old_author = self._get_author_href(page)

        scrolled = False
        for attempt in range(1, max_attempts + 1):
            page.bring_to_front()

            if attempt > 1:
                # Only bother clearing stray modals on retries — the first
                # attempt already had this done once at page load, and
                # checking here on every single scroll was pure overhead.
                page.keyboard.press("Escape")
                self._dismiss_popups(page, per_selector_timeout=300)

            page.evaluate("document.body.focus()")

            if attempt == 1:
                page.keyboard.press("ArrowDown")
            else:
                # Mix in a wheel scroll on later attempts in case ArrowDown
                # alone isn't registering as real input.
                page.mouse.wheel(0, 1000)
                page.wait_for_timeout(150)
                page.keyboard.press("ArrowDown")

            # Poll for caption or author to actually change, using the same
            # selectors extraction uses — no fixed sleep, resolves as soon
            # as the change happens.
            deadline = time.time() + (SCROLL_WAIT_MS / 1000)
            changed = False
            while time.time() < deadline:
                cur_caption = self._safe_text(page, "[data-e2e='video-desc']")
                cur_author = self._get_author_href(page)

                author_changed = bool(cur_author) and cur_author != old_author
                caption_changed = bool(old_caption) and cur_caption != old_caption

                if author_changed or caption_changed:
                    changed = True
                    break
                page.wait_for_timeout(200)

            if changed:
                print(f"  [DEBUG] Scroll OK on attempt {attempt}")
                scrolled = True
                break
            else:
                print(f"  [WARN] Attempt {attempt}/{max_attempts} didn't advance the feed.")

        if not scrolled:
            print("  [WARN] Feed still hasn't changed after all attempts — may be stuck.")
            try:
                os.makedirs("./debug", exist_ok=True)
                shot_path = f"./debug/stuck_{datetime.now().strftime('%H%M%S')}.png"
                page.screenshot(path=shot_path)
                print(f"  [DEBUG] Saved screenshot to {shot_path} — check it for a blocking overlay/modal.")
            except Exception as e:
                print(f"  [DEBUG] Could not save screenshot: {e}")

        if scrolled:
            # Small settle buffer for any last-mile re-render (e.g. like
            # count animating in) before extraction reads the page.
            page.wait_for_timeout(300)

    def _load_cookies(self, context):
        flag_file = "./browser_profile/.cookies_loaded"

        if os.path.exists(flag_file):
            # Profile exists — check if session is still valid
            existing = context.cookies("https://www.tiktok.com")
            session_cookie = next((c for c in existing if c["name"] == "sessionid"), None)

            if session_cookie:
                print("  [AUTH] Browser profile loaded with valid session ✓")
            else:
                print("  [WARN] Browser profile exists but session expired — re-seeding cookies.")
                os.remove(flag_file)

                self._load_cookies(context)  # retry with fresh cookies
            return

        # First time — seed from cookie file
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

            # Drop feed cache so TikTok doesn't repeat videos
            cookies = [c for c in cookies if c.get("name") != "perf_feed_cache"]

            context.add_cookies(cookies)

            os.makedirs("./browser_profile", exist_ok=True)
            open(flag_file, "w").close()

            print(f"  [AUTH] Cookies seeded into browser profile ✓")

        except FileNotFoundError:
            print(f"  [WARN] '{COOKIES_FILE}' not found — running without login.")
            print(f"  [WARN] Run setup_profile.py to log in manually.")
        except json.JSONDecodeError:
            print(f"  [ERROR] '{COOKIES_FILE}' is not valid JSON.")

    def _safe_text(self, page, selector: str, timeout: int = 3000) -> str:
        # CSS ":visible" only checks that an element is rendered (not
        # display:none) — it does NOT mean it's the one actually on screen.
        # TikTok keeps the next video's elements rendered (just scrolled
        # out of view) before you swipe to it. When the CURRENT video has
        # no caption, ":visible" on [data-e2e='video-desc'] was matching
        # the next video's (non-empty) caption instead of correctly
        # returning empty. We check actual viewport position instead.
        try:
            text = page.evaluate(
                """(sel) => {
                    const els = [...document.querySelectorAll(sel)];
                    for (const el of els) {
                        const r = el.getBoundingClientRect();
                        const inViewport = r.width > 0 && r.height > 0 &&
                            r.top < window.innerHeight && r.bottom > 0 &&
                            r.left < window.innerWidth && r.right > 0;
                        if (inViewport) return el.innerText || "";
                    }
                    return "";
                }""",
                selector
            )
            return " ".join((text or "").split())
        except Exception:
            return ""

    def _find_ad(self, page) -> bool:
        # Fixed two bugs from the previous version:
        #   1. `self._find_ad` (no call) was passed instead of `self._find_ad(page)`
        #      — isAd was being set to a bound method object, not a result.
        #   2. `locator(...) != ""` always evaluates True (a Locator is never
        #      equal to a string), so every video was being marked an ad.
        # Now checks whether an ad-tag element is actually present on screen,
        # same viewport-position approach as the rest of the extraction.
        try:
            return bool(page.evaluate(
                """(sel) => {
                    const els = [...document.querySelectorAll(sel)];
                    return els.some(el => {
                        const r = el.getBoundingClientRect();
                        return r.width > 0 && r.height > 0 &&
                            r.top < window.innerHeight && r.bottom > 0 &&
                            r.left < window.innerWidth && r.right > 0;
                    });
                }""",
                "[data-e2e='ad-tag']"
            ))
        except Exception:
            return False

    def _get_author_href(self, page) -> str:
        try:
            href = page.evaluate(
                """() => {
                    const anchors = [...document.querySelectorAll("[class*='DivCreatorInfoContainer'] a[href^='/@']")];
                    for (const a of anchors) {
                        const r = a.getBoundingClientRect();
                        const inViewport = r.width > 0 && r.height > 0 &&
                            r.top < window.innerHeight && r.bottom > 0 &&
                            r.left < window.innerWidth && r.right > 0;
                        if (inViewport) return a.getAttribute('href') || "";
                    }
                    return "";
                }"""
            )
            return href or ""
        except Exception:
            return ""

    def _get_author(self, page) -> str:
        try:
            href = self._get_author_href(page)
            return href.split("/@")[-1].split("/")[0] if href else ""
        except Exception:
            return ""

    def _get_hashtags(self, page) -> list:
        try:
            tags = page.evaluate(
                """() => {
                    const els = [...document.querySelectorAll("[data-e2e='search-common-link']")];
                    return els.filter(el => {
                        const r = el.getBoundingClientRect();
                        return r.width > 0 && r.height > 0 &&
                            r.top < window.innerHeight && r.bottom > 0 &&
                            r.left < window.innerWidth && r.right > 0;
                    }).map(el => (el.innerText || "").trim()).filter(Boolean);
                }"""
            )
            return tags or []
        except Exception:
            return []