"""
TikTok Scraper using Obscura + Playwright
-----------------------------------------
Scrapes TikTok search results for:
  - Profile info (bio, follower count)
  - Video descriptions/captions
  - View/like/comment counts

Requirements:
  pip install playwright
  playwright install chromium

Usage:
  1. Start Obscura:
       obscura.exe serve --port 9222 --stealth

  2. Run this script:
       python tiktok_scraper.py --query "your search term" --limit 20
"""

import asyncio
import argparse
import csv
import re
import sys
from datetime import datetime
from playwright.async_api import async_playwright


# ── Config ────────────────────────────────────────────────────────────────────

OBSCURA_WS  = "ws://127.0.0.1:9222"
DEFAULT_OUT = "tiktok_results.csv"
CSV_FIELDS  = [
    "search_term", "username", "display_name", "bio",
    "followers", "following", "likes_total",
    "video_url", "description", "views", "likes", "comments", "shares",
    "scraped_at",
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def clean_number(text: str) -> str:
    """Convert TikTok shorthand numbers to integers (1.2M → 1200000)."""
    if not text:
        return ""
    text = text.strip().replace(",", "")
    m = re.match(r"([\d.]+)\s*([KkMmBb]?)", text)
    if not m:
        return text
    value, suffix = float(m.group(1)), m.group(2).upper()
    value *= {"K": 1_000, "M": 1_000_000, "B": 1_000_000_000}.get(suffix, 1)
    return str(int(value))


async def get_text(page, selector: str) -> str:
    try:
        el = page.locator(selector).first
        return (await el.inner_text(timeout=3000)).strip()
    except Exception:
        return ""


# ── Core scraping ─────────────────────────────────────────────────────────────

async def scrape_search(query: str, limit: int, output: str, ws_url: str):
    print(f"\n🔍  Searching TikTok for: '{query}'  (limit: {limit})")
    print(f"📄  Output: {output}\n")

    async with async_playwright() as pw:

        # ── Connect to Obscura via CDP ────────────────────────────────────────
        try:
            browser = await pw.chromium.connect_over_cdp(
                ws_url,
                slow_mo=100,
            )
        except Exception as e:
            print(f"❌  Could not connect to Obscura at {ws_url}")
            print(f"    Make sure it's running:  obscura.exe serve --port 9222 --stealth")
            print(f"    Error: {e}")
            sys.exit(1)

        context = await browser.new_context(
            viewport={"width": 1280, "height": 900},
            ignore_https_errors=True,
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
        )
        page = await context.new_page()
        results = []

        try:
            # ── 1. Load search results page ───────────────────────────────────
            search_url = f"https://www.tiktok.com/search?q={query.replace(' ', '%20')}"
            print(f"  → Loading {search_url}")
            await page.goto(search_url, wait_until="networkidle", timeout=30000)
            await asyncio.sleep(3)

            # ── 2. Scroll and collect video links ─────────────────────────────
            print("  → Collecting video links …")
            video_links = []
            max_scrolls  = 20

            for _ in range(max_scrolls):
                links = await page.evaluate("""
                    () => Array.from(
                        document.querySelectorAll('a[href*="/video/"]')
                    ).map(a => a.href).filter(h => /\\/video\\/\\d+/.test(h))
                """)
                for link in links:
                    if link not in video_links:
                        video_links.append(link)

                print(f"     {len(video_links)} links collected …")
                if len(video_links) >= limit:
                    break

                await page.evaluate("window.scrollBy(0, 1200)")
                await asyncio.sleep(2)

            video_links = video_links[:limit]
            print(f"  ✓ Collected {len(video_links)} video links\n")

            # ── 3. Visit each video page ──────────────────────────────────────
            for i, video_url in enumerate(video_links, 1):
                print(f"  [{i}/{len(video_links)}] {video_url}")
                try:
                    await page.goto(video_url, wait_until="networkidle", timeout=30000)
                    await asyncio.sleep(2)

                    username     = await get_text(page, 'h2[data-e2e="browse-username"], span[data-e2e="browse-username"]')
                    display_name = await get_text(page, 'h1[data-e2e="browse-nickname"], p[data-e2e="browse-nickname"]')
                    bio          = await get_text(page, 'h2[data-e2e="user-bio"], span[data-e2e="user-bio"]')
                    followers    = await get_text(page, 'strong[data-e2e="followers-count"]')
                    following    = await get_text(page, 'strong[data-e2e="following-count"]')
                    likes_total  = await get_text(page, 'strong[data-e2e="likes-count"]')
                    description  = await get_text(page, 'span[data-e2e="browse-video-desc"], div[data-e2e="video-desc"]')
                    views        = await get_text(page, 'strong[data-e2e="browse-video-views"]')
                    likes        = await get_text(page, 'strong[data-e2e="browse-like-count"]')
                    comments     = await get_text(page, 'strong[data-e2e="browse-comment-count"]')
                    shares       = await get_text(page, 'strong[data-e2e="browse-share-count"]')

                    results.append({
                        "search_term":  query,
                        "username":     username,
                        "display_name": display_name,
                        "bio":          bio,
                        "followers":    clean_number(followers),
                        "following":    clean_number(following),
                        "likes_total":  clean_number(likes_total),
                        "video_url":    video_url,
                        "description":  description,
                        "views":        clean_number(views),
                        "likes":        clean_number(likes),
                        "comments":     clean_number(comments),
                        "shares":       clean_number(shares),
                        "scraped_at":   datetime.utcnow().isoformat(),
                    })

                    print(f"     ✓  @{username or '?'}  |  views: {views or '?'}  |  likes: {likes or '?'}")

                except Exception as e:
                    print(f"     ⚠  Skipped — {e}")

                await asyncio.sleep(1.5)

        finally:
            await browser.close()

        # ── 4. Write CSV ──────────────────────────────────────────────────────
        if results:
            with open(output, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
                writer.writeheader()
                writer.writerows(results)
            print(f"\n✅  Done! {len(results)} rows saved to '{output}'")
        else:
            print("\n⚠  No results scraped. TikTok may be blocking — try --stealth in Obscura.")


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Scrape TikTok search results via Obscura."
    )
    parser.add_argument("--query",      "-q", required=True, help="Search term")
    parser.add_argument("--limit",      "-l", type=int, default=20, help="Max videos (default: 20)")
    parser.add_argument("--output",     "-o", default=DEFAULT_OUT, help="Output CSV filename")
    parser.add_argument("--obscura-ws",        default=OBSCURA_WS,  help=f"Obscura WS URL (default: {OBSCURA_WS})")
    args = parser.parse_args()

    asyncio.run(scrape_search(args.query, args.limit, args.output, args.obscura_ws))


if __name__ == "__main__":
    main()