import gspread
from google.oauth2.service_account import Credentials
from config import GOOGLE_SHEET_NAME, CREDENTIALS_FILE

SCOPES = [
    "https://spreadsheets.google.com/feeds",
    "https://www.googleapis.com/auth/drive"
]

HEADERS = [
    "Timestamp", "Author", "Description", "URL",
    "Likes", "Scam Score", "Risk Label", "Scam Reasons"
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
    if not sheet.get_all_values():
        sheet.append_row(HEADERS)
        print("  [SHEET] Header row created.")

def log_to_sheet(video_data: dict, score: int, label: str, reasons: list):
    try:
        sheet = get_sheet()
        ensure_headers(sheet)
        row = [
            video_data.get("timestamp",   "N/A"),
            video_data.get("author",      "N/A"),
            video_data.get("description", "N/A"),
            video_data.get("url",         "N/A"),
            video_data.get("likes",       "N/A"),
            score,
            label,
            ", ".join(reasons) if reasons else "N/A"
        ]
        sheet.append_row(row)
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