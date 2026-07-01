from playwright.sync_api import sync_playwright

USER_DATA_DIR = "./browser_profile"

with sync_playwright() as p:
    context = p.chromium.launch_persistent_context(
        user_data_dir=USER_DATA_DIR,
        headless=False,
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        viewport={"width": 1280, "height": 800}
    )

    page = context.new_page()
    page.goto("https://www.tiktok.com/login")

    print("Log in to TikTok manually in the browser window.")
    print("Once you're logged in and can see your FYP, press Enter here.")
    input()

    context.close()
    print("Profile saved. You can now run main.py.")