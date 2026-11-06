import gspread
from google.oauth2.service_account import Credentials
from config import GOOGLE_SHEET_NAME, CREDENTIALS_FILE, ENABLE_DRIVE_UPLOAD
from drive_uploader import upload_frame

SCOPES = [
    "https://spreadsheets.google.com/feeds",
    "https://www.googleapis.com/auth/drive"
]

# Order MUST match the row built in log_to_sheet().
HEADERS = [
    "Timestamp", "Author", "Description", "URL",
    "Hashtags", "Likes", "Comments", "Shares", "Is Ad",
    "Scam Score", "Risk Label", "Scam Reasons",
    "Bio", "Bio Link", "Bio Link Type", "Total Followers", "Total Likes",
    "Frame URLs", "Thumbnail",
    "Oracle Domain", "Oracle Prob", "Oracle Fraud",
]

URL_COL = HEADERS.index("URL") + 1  # gspread columns are 1-indexed


def _col_letter(n: int) -> str:
    s = ""
    while n:
        n, r = divmod(n - 1, 26)
        s = chr(65 + r) + s
    return s


def normalize_url(url) -> str:
    """Drop the query string (?is_from_webapp=1&sender_device=pc ...) so the
    same video always compares equal."""
    return str(url or "").strip().split("?")[0].rstrip("/")


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
    first_row = sheet.row_values(1)  # cheaper than get_all_values()
    if first_row != HEADERS:
        sheet.update(range_name="A1", values=[HEADERS])  # works on old + new gspread
        sheet.freeze(rows=1)
        sheet.format(f"A1:{_col_letter(len(HEADERS))}1", {"textFormat": {"bold": True}})
        print("  [SHEET] Header row created/corrected.")


# Cache of already-logged video URLs (normalized), loaded once per process.
_seen_urls: set | None = None


def _load_seen_urls() -> set:
    global _seen_urls
    if _seen_urls is None:
        sheet = get_sheet()
        vals = sheet.col_values(URL_COL)[1:]  # skip header
        _seen_urls = {normalize_url(v) for v in vals if normalize_url(v)}
    return _seen_urls


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

        clean_url = normalize_url(video_data.get("url"))
        oracle_prob = video_data.get("oracle_prob")

        row = [
            video_data.get("timestamp",        "N/A"),
            video_data.get("author",           "N/A"),
            video_data.get("description",      "N/A"),
            clean_url or "N/A",
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
            video_data.get("bio_link_type",    "N/A"),
            video_data.get("total_followers",  "N/A"),
            video_data.get("total_likes",      "N/A"),
            frame_urls_str,
            thumbnail_formula,
            video_data.get("oracle_domain") or "N/A",
            round(oracle_prob, 4) if oracle_prob is not None else "N/A",
            video_data.get("oracle_is_fraud", False),
        ]
        assert len(row) == len(HEADERS), "row/HEADERS length mismatch"

        # USER_ENTERED so the =IMAGE(...) formula actually renders instead
        # of being written as a literal text string
        sheet.append_row(row, value_input_option="USER_ENTERED")

        if clean_url and _seen_urls is not None:
            _seen_urls.add(clean_url)

        print(f"  [LOGGED] Row added to '{GOOGLE_SHEET_NAME}' ✓")
    except Exception as e:
        print(f"  [ERROR] Failed to log to Google Sheets: {e}")


def get_log_count() -> int:
    try:
        sheet = get_sheet()
        return max(0, len(sheet.col_values(1)) - 1)  # one column is enough
    except Exception as e:
        print(f"  [ERROR] Could not fetch row count: {e}")
        return 0


def check_for_duplicates(link) -> bool:
    """True if this video URL (ignoring ?query params) is already in the sheet."""
    key = normalize_url(link)
    if not key:  # empty URL must not "match" blank cells
        return False
    try:
        return key in _load_seen_urls()
    except Exception as e:
        print(f"  [ERROR] Duplicate check failed: {e}")
        return False