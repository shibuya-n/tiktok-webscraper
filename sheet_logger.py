import gspread
from google.oauth2.service_account import Credentials
from config import GOOGLE_SHEET_NAME, CREDENTIALS_FILE, ENABLE_DRIVE_UPLOAD
from drive_uploader import upload_frame

SCOPES = [
    "https://spreadsheets.google.com/feeds",
    "https://www.googleapis.com/auth/drive"
]

HEADERS = [
    "Timestamp", "Author", "Description", "URL",
    "Hashtags", "Likes", "Comments", "Shares", "Is Ad",
    "Scam Score", "Risk Label", "Scam Reasons",
    "Bio", "Bio Link", "Total Followers", "Total Likes"
]

def get_sheet():
    creds = Credentials.from_service_account_file(CREDENTIALS_FILE, scopes=SCOPES)
    client = gspread.authorize(creds)
    try:
        return client.open(GOOGLE_SHEET_NAME).sheet1
    except gspread.SpreadsheetNotFound:
        print(f"  [ERROR] Google Sheet '{GOOGLE_SHEET_NAME}' not found.")
        print(f"  Make sure it exists and is shared with your service account email.")
        raise

def ensure_headers(sheet):
    existing = sheet.get_all_values()
    if not existing or existing[0] != HEADERS:
        sheet.update("A1", [HEADERS])
        sheet.freeze(rows=1)
        sheet.format("A1:P1", {"textFormat": {"bold": True}})
        print("  [SHEET] Header row created/corrected.")

def log_to_sheet(video_data: dict, score: int, label: str, reasons: list, frame_paths: list = None):
    try:
        sheet = get_sheet()
        ensure_headers(sheet)

        hashtags = video_data.get("hashtags", [])
        hashtags_str = ", ".join(hashtags) if hashtags else "N/A"

        frame_urls = []
        if ENABLE_DRIVE_UPLOAD:
            for path in (frame_paths or []):
                url = upload_frame(path)
                if url:
                    frame_urls.append(url)

        frame_urls_str = ", ".join(frame_urls) if frame_urls else "N/A"
        thumbnail_formula = f'=IMAGE("{frame_urls[0]}")' if frame_urls else ""

        row = [
            video_data.get("timestamp",        "N/A"),
            video_data.get("author",           "N/A"),
            video_data.get("description",      "N/A"),
            video_data.get("url",              "N/A"),
            hashtags_str,
            video_data.get("likes",            "N/A"),
            video_data.get("comments",         "N/A"),
            video_data.get("shares",           "N/A"),
            video_data.get("isAd",             False),
            score,
            label,
            ", ".join(reasons) if reasons else "N/A",
            video_data.get("bio",              "N/A"),
            video_data.get("bio_link",         "N/A"),
            video_data.get("bio_link_type",     "N/A"),
            video_data.get("total_followers",  "N/A"),
            video_data.get("total_likes",      "N/A"),
            frame_urls_str,
            thumbnail_formula,
        ]
        # USER_ENTERED so the =IMAGE(...) formula actually renders instead
        # of being written as a literal text string
        sheet.append_row(row, value_input_option="USER_ENTERED")
        print(f"  [LOGGED] Row added to '{GOOGLE_SHEET_NAME}' ✓")
    except Exception as e:
        print(f"  [ERROR] Failed to log to Google Sheets: {e}")

def get_log_count() -> int:
    try:
        sheet = get_sheet()
        return max(0, len(sheet.get_all_values()) - 1)
    except Exception as e:
        print(f"  [ERROR] Could not fetch row count: {e}")
        return 0