# drive_uploader.py
import os
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
from google.oauth2.service_account import Credentials
from config import CREDENTIALS_FILE, DRIVE_FOLDER_ID

DRIVE_SCOPES = ["https://www.googleapis.com/auth/drive"]

def get_drive_service():
    creds = Credentials.from_service_account_file(CREDENTIALS_FILE, scopes=DRIVE_SCOPES)
    return build("drive", "v3", credentials=creds)

def upload_file(file_path: str, mimetype: str) -> str:
    """Uploads any file to Drive, makes it link-viewable, returns its URL."""
    try:
        service = get_drive_service()
        metadata = {"name": os.path.basename(file_path), "parents": [DRIVE_FOLDER_ID]}
        media = MediaFileUpload(file_path, mimetype=mimetype)
        uploaded = service.files().create(body=metadata, media_body=media, fields="id").execute()
        file_id = uploaded["id"]

        service.permissions().create(
            fileId=file_id, body={"type": "anyone", "role": "reader"}
        ).execute()

        return f"https://drive.google.com/uc?id={file_id}"
    except Exception as e:
        print(f"  [ERROR] Drive upload failed for {file_path}: {e}")
        return ""

def upload_frame(file_path: str) -> str:
    return upload_file(file_path, "image/png")

def upload_json(file_path: str) -> str:
    return upload_file(file_path, "application/json")