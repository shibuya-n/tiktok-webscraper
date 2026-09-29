from __future__ import annotations

import contextlib
import datetime
import os
import re
import socket
import sqlite3
import ssl
import sys
import tempfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin

import cv2
import dns.resolver
import numpy as np
import pandas as pd
import requests
import tldextract
import whois
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright
from tensorflow.keras.models import load_model

with contextlib.suppress(Exception):
    from google.cloud import vision  # noqa: F401


BASE_DIR = "/data/mirayrdm/scam-paper-codes/graph_implementation/"
GRAPH_IMPL_DIR = Path(__file__).resolve().parent
RESEARCH_ROOT = Path(__file__).resolve().parents[1]
VISION_API_KEY = os.environ.get("VISION_API_KEY")


def _pool_excluded_2_dir_from_env() -> Path:
    override = os.environ.get("POOL_EXCLUDED_2_DIR", "").strip()
    if override:
        return Path(override).expanduser().resolve()
    return Path("/data/mirayrdm/scam/scam_graph_data/collected_features_candidate_pool_excluded_2")


COLLECTED_POOL_EXCLUDED_2_DIR = _pool_excluded_2_dir_from_env()

DEFAULT_GRAPH_INPUT_CSV = (
    "/data/mirayrdm/scam/scam_graph_data_2/master_graph_edges_filtered_with_hop.csv"
)
DEFAULT_GRAPH_SEED_REFERENCE_CSV = (
    "/data/mirayrdm/scam/scam_graph_data_2/master_graph_edges.csv"
)
EXCLUDED_CRAWL_DOMAINS = {
    "youtube",
    "youtu",
    "tiktok",
    "facebook",
    "instagram",
    "pinterest",
    "twitter",
    "linkedin",
}


def _chrome_user_data_dir_from_env() -> Path:
    override = os.environ.get("EXTRACT_IMAGES_CHROME_PROFILE", "").strip()
    if override:
        return Path(override).expanduser().resolve()
    num = int(os.environ.get("NUM_CHUNKS", "1").strip() or "1")
    cid = int(os.environ.get("CHUNK_ID", "0").strip() or "0")
    if num > 1:
        return GRAPH_IMPL_DIR / f"chrome_profile_extract_images_chunk{cid}"
    return GRAPH_IMPL_DIR / "chrome_profile_extract_images"


DEFAULT_CRAWLER_USER_DATA_DIR = _chrome_user_data_dir_from_env()
DEFAULT_CRAWLER_HTML_DIR = GRAPH_IMPL_DIR / "collected_features_excluded_2" / "html"
SCAM_WEBSITES_ROOT = Path("/data/mirayrdm/scam/scam_graph_data_2")
SEED_HTML_POOL_DIR_NAMES = (
    "collected_features_candidate_pool_excluded",
    "collected_features_candidate_pool_full",
    "collected_features_candidate_pool_5",
    "collected_features_candidate_pool_4",
    "collected_features_candidate_pool_3",
    "collected_features_candidate_pool_2",
    "collected_features_candidate_pool",
    "collected_features_candidate_pool_excluded_2",
)


def seed_html_search_dirs() -> list[Path]:
    override = os.environ.get("SEED_HTML_DIR", "").strip()
    if override:
        return [Path(override).expanduser().resolve()]
    return [SCAM_WEBSITES_ROOT / name / "html" for name in SEED_HTML_POOL_DIR_NAMES]


def seed_html_basename(domain: str) -> str:
    raw = (domain or "").strip()
    safe = raw.replace("/", "_").replace(":", "_")
    return f"{safe}.html"


IMAGE_EXTENSIONS = (".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".svg")
IMG_URL_SKIP_SUBSTR = ("logo", "icon", "banner", "sprite")
CNN_MODEL_PATH = os.environ.get(
    "CNN_MODEL_PATH",
    "/data/mirayrdm/scam/scam_graph_data_2/spam_image_classifier/product_cnn_model.keras",
)
CNN_PROB_THRESHOLD = 0.5
MAX_CRAWL_WORKERS = int(os.environ.get("MAX_CRAWL_WORKERS", "6"))
POOL2_IO_LOCK = threading.Lock()


FREE_EMAIL_PROVIDERS = {
    "gmail.com",
    "hotmail.com",
    "outlook.com",
    "yahoo.com",
    "icloud.com",
    "protonmail.com",
    "aol.com",
    "mail.com",
}
PRIVACY_HINTS = re.compile(
    r"(redacted|privacy|proxy|whoisguard|domains by proxy|contact privacy|data protected)",
    re.I,
)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
BAD_EMAIL_HINTS = re.compile(
    r"(abuse|privacy|protect|proxy|redact|whoisguard|contactprivacy|domainsbyproxy|"
    r"registrar|support|help|hostmaster|noc@|postmaster|icann|iana)",
    re.I,
)


def to_iso_date(x, pick="max"):
    if x is None:
        return None
    if isinstance(x, (list, tuple)):
        xs = [d for d in x if d is not None]
        if not xs:
            return None
        x = max(xs) if pick == "max" else min(xs)
    if isinstance(x, datetime.datetime):
        return x.isoformat()
    return str(x)


def _to_list(x):
    if x is None:
        return []
    if isinstance(x, (list, tuple, set)):
        return [str(i) for i in x if i is not None]
    return [str(x)]


def _get_registrant_email_from_raw(raw: dict):
    candidates = []
    for k, v in (raw or {}).items():
        if v is None:
            continue
        ks = str(k).lower()
        if "registrant" in ks and "email" in ks:
            for e in EMAIL_RE.findall(str(v)):
                candidates.append((e, f"raw_key:{k}"))
    if candidates:
        for e, src in candidates:
            if not BAD_EMAIL_HINTS.search(e):
                return e, src
        return candidates[0]
    text = " ".join(str(v) for v in (raw or {}).values() if v is not None)
    emails = list(dict.fromkeys(EMAIL_RE.findall(text)))
    if not emails:
        return None, None
    good = [e for e in emails if not BAD_EMAIL_HINTS.search(e)]
    if good:
        return good[0], "raw_text_scan"
    return emails[0], "raw_text_scan_fallback"


def extract_whois(domain):
    try:
        info = whois.whois(domain)
        raw = dict(info) if hasattr(info, "__iter__") else getattr(info, "__dict__", {})
        emails = _to_list(getattr(info, "emails", None))
        registrant_email, registrant_email_src = _get_registrant_email_from_raw(raw)
        country = getattr(info, "country", None)
        raw_text = " ".join([str(v) for v in raw.values() if v is not None])
        privacy_protected = 1 if PRIVACY_HINTS.search(raw_text) else 0
        free_email_provider = 0
        for e in emails + ([registrant_email] if registrant_email else []):
            if e and "@" in e and e.split("@", 1)[1].lower().strip() in FREE_EMAIL_PROVIDERS:
                free_email_provider = 1
                break
        return {
            "domain": domain,
            "registrar": getattr(info, "registrar", None),
            "creation_date": to_iso_date(getattr(info, "creation_date", None), pick="min"),
            "expiration_date": to_iso_date(getattr(info, "expiration_date", None), pick="max"),
            "updated_date": to_iso_date(getattr(info, "updated_date", None), pick="max"),
            "whois_emails": emails,
            "registrant_email_guess": registrant_email,
            "registrant_email_source": registrant_email_src,
            "registrant_country_guess": country,
            "privacy_protected_guess": privacy_protected,
            "free_email_provider_guess": free_email_provider,
            "whois_raw": raw,
        }
    except Exception as e:
        print(f"[WHOIS] Error for {domain}: {e}")
        return {
            "domain": domain,
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
            "updated_date": None,
            "whois_emails": [],
            "registrant_email_guess": None,
            "registrant_email_source": None,
            "registrant_country_guess": None,
            "privacy_protected_guess": None,
            "free_email_provider_guess": None,
            "whois_raw": None,
        }


def extract_dns(domain):
    dns_data = {"domain": domain}
    try:
        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                dns_data[rtype] = [r.to_text() for r in answers]
            except Exception:
                dns_data[rtype] = None
    except Exception as e:
        print(f"[DNS] Error for {domain}: {e}")
    return dns_data


def extract_ssl(domain):
    ssl_data = {"domain": domain}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        ssl_data["issuer"] = cert.get("issuer")
        ssl_data["subject"] = cert.get("subject")
        ssl_data["notBefore"] = cert.get("notBefore")
        ssl_data["notAfter"] = cert.get("notAfter")
        if cert.get("notAfter"):
            not_after = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            ssl_data["days_to_expire"] = (not_after - datetime.datetime.utcnow()).days
    except Exception as e:
        print(f"[SSL] Error for {domain}: {e}")
    return ssl_data


def detect_news_links(uri):
    if not VISION_API_KEY:
        raise ValueError("VISION_API_KEY is not set")
    endpoint = f"https://vision.googleapis.com/v1/images:annotate?key={VISION_API_KEY}"
    payload = {
        "requests": [
            {
                "image": {"source": {"imageUri": uri}},
                "features": [{"type": "WEB_DETECTION", "maxResults": 10}],
            }
        ]
    }
    print(f"[DBG][vision] calling web_detection for: {uri}", flush=True)
    resp = requests.post(endpoint, json=payload, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    entities, labels, pages = [], [], []
    responses = data.get("responses", [])
    if not responses:
        return pages, "", ""
    web_detection = responses[0].get("webDetection", {})
    for label in web_detection.get("bestGuessLabels", []):
        t = label.get("label", "")
        if t:
            print(f"\nBest guess label: {t}")
            labels.append(t)
    for entity in web_detection.get("webEntities", []):
        d = entity.get("description", "")
        if d:
            print(f"\tDescription: {d}")
            entities.append(d)
    for page in web_detection.get("pagesWithMatchingImages", []):
        u = page.get("url")
        if u:
            print(f"News URL Found: {u}")
            pages.append(u)
    return pages, "; ".join(labels), "; ".join(entities)


def download_image(image_url, save_dir="downloaded_images"):
    os.makedirs(save_dir, exist_ok=True)
    filename = None
    try:
        response = requests.get(image_url, timeout=10)
        if response.status_code == 200:
            ext = image_url.split(".")[-1].split("?")[0]
            if ext.lower() not in ["jpg", "jpeg", "png", "gif", "webp"]:
                ext = "jpg"
            filename = f"{uuid.uuid4()}.{ext}"
            filepath = Path(save_dir) / filename
            with open(filepath, "wb") as f:
                f.write(response.content)
            print(f"[+] Image saved to {filepath}")
    except Exception as e:
        print(f"[!] Error downloading {image_url}: {e}")
    return filename


def preprocess_for_cnn(path, size=(128, 128)):
    if not os.path.exists(path):
        return None
    img = cv2.imread(path)
    if img is None:
        return None
    img = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
    img = cv2.resize(img, size)
    img = (img.astype("float32") / 127.5) - 1.0
    return img


def classify_local_image_cnn(model, local_path: str) -> str:
    img_data = preprocess_for_cnn(local_path)
    if img_data is None:
        return "missing"
    prob = model.predict(np.expand_dims(img_data, axis=0), verbose=0)[0][0]
    return "product" if prob > CNN_PROB_THRESHOLD else "trash"


STEALTH_INIT = r"""
(() => {
  try {
    Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
    window.chrome = window.chrome || { runtime: {} };
  } catch (e) {}
})();
"""


def scheme_attempt_urls(raw: str) -> list[str]:
    s = raw.strip()
    if not s:
        return []
    if s.startswith("https://"):
        rest = s[len("https://") :]
        return [s, f"http://{rest}"]
    if s.startswith("http://"):
        rest = s[len("http://") :]
        return [s, f"https://{rest}"]
    return [f"https://{s}", f"http://{s}"]


def is_block_page(html: str, status: Optional[int]) -> bool:
    if status in (401, 403, 429):
        return True
    if not html:
        return False
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style"]):
        tag.decompose()
    txt = soup.get_text(" ", strip=True).lower()
    return any(k in txt for k in ["just a moment", "verify you are human", "captcha"])


def fetch_html_stealth(
    domain_or_url: str,
    html_dir: str | Path | None = None,
    *,
    headed: bool | None = None,
    settle_ms: int = 2500,
    goto_timeout_ms: int = 45000,
    user_data_dir: Path | None = None,
) -> dict:
    html_dir = Path(html_dir) if html_dir is not None else DEFAULT_CRAWLER_HTML_DIR
    html_dir.mkdir(parents=True, exist_ok=True)
    raw = domain_or_url.strip()
    safe_name = raw.replace("/", "_").replace(":", "_")
    html_path = html_dir / f"{safe_name}.html"
    candidates = scheme_attempt_urls(raw)
    result: dict = {
        "reachable": 0,
        "final_url": None,
        "http_status": None,
        "error": None,
        "html_path": None,
        "attempted_url": candidates[0] if candidates else raw,
        "attempts": [],
        "blocked": 0,
    }
    if headed is None:
        headed = os.environ.get("HEADED", "").strip() in ("1", "true", "yes")
    profile = user_data_dir if user_data_dir is not None else DEFAULT_CRAWLER_USER_DATA_DIR
    profile.mkdir(parents=True, exist_ok=True)
    try:
        with sync_playwright() as p:
            context = p.chromium.launch_persistent_context(
                user_data_dir=str(profile),
                channel="chrome",
                headless=not headed,
                args=["--disable-blink-features=AutomationControlled"],
                ignore_https_errors=True,
                viewport={"width": 1365, "height": 900},
            )
            context.add_init_script(STEALTH_INIT)
            page = context.pages[0] if context.pages else context.new_page()
            resp = None
            attempts: list[dict] = []
            for candidate in candidates:
                rec: dict = {"url": candidate, "http_status": None, "error": None}
                try:
                    r = page.goto(candidate, wait_until="domcontentloaded", timeout=goto_timeout_ms)
                    page.wait_for_timeout(settle_ms)
                    rec["http_status"] = r.status if r is not None else None
                    if r is not None:
                        resp = r
                        result["attempted_url"] = candidate
                        attempts.append(rec)
                        break
                    rec["error"] = "goto returned no response"
                except Exception as e:
                    rec["error"] = repr(e)
                attempts.append(rec)
            result["attempts"] = attempts
            if resp is None:
                result["error"] = " | ".join(
                    [f"{a['url']}: {a.get('error') or 'no response'}" for a in attempts]
                )
                context.close()
                return result
            result["reachable"] = 1
            result["final_url"] = page.url
            result["http_status"] = resp.status if resp is not None else None
            html_content = page.content()
            html_path.write_text(html_content, encoding="utf-8")
            result["html_path"] = str(html_path)
            result["blocked"] = int(is_block_page(html_content, result["http_status"]))
            if result["blocked"] == 1:
                result["reachable"] = 0
            context.close()
            return result
    except Exception as e:
        result["error"] = f"Playwright error: {repr(e)}"
        return result


def _load_pool2_crawled_domains() -> set[str]:
    csv_path = COLLECTED_POOL_EXCLUDED_2_DIR / "html_data.csv"
    if not csv_path.exists():
        return set()
    try:
        df = pd.read_csv(csv_path, usecols=["domain"], low_memory=False)
        return set(df["domain"].astype(str).str.strip())
    except Exception:
        return set()


def _append_pool2_csv_row(filename: str, row: dict) -> None:
    COLLECTED_POOL_EXCLUDED_2_DIR.mkdir(parents=True, exist_ok=True)
    path = COLLECTED_POOL_EXCLUDED_2_DIR / filename
    pd.DataFrame([row]).to_csv(path, mode="a", index=False, header=not path.exists())


def crawl_discovered_domain_to_pool_excluded_2(domain: str, pool2_done: set[str], *, headed: bool | None = None) -> None:
    d = (domain or "").strip()
    if not d or d.lower() in ("nan", "none"):
        return
    with POOL2_IO_LOCK:
        if d in pool2_done:
            return
        pool2_done.add(d)
    COLLECTED_POOL_EXCLUDED_2_DIR.mkdir(parents=True, exist_ok=True)
    html_subdir = COLLECTED_POOL_EXCLUDED_2_DIR / "html"
    html_subdir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="chrome_profile_") as tmp_profile:
        fetch_res = fetch_html_stealth(
            d,
            html_subdir,
            headed=headed,
            user_data_dir=Path(tmp_profile),
        )
    with POOL2_IO_LOCK:
        _append_pool2_csv_row("html_data.csv", {"domain": d, "html_path": fetch_res, "screenshot_path": ""})
        _append_pool2_csv_row("whois_data.csv", extract_whois(d))
        _append_pool2_csv_row("dns_data.csv", extract_dns(d))
        _append_pool2_csv_row("ssl_data.csv", extract_ssl(d))


def crawl_discovered_domain_to_pool_excluded_2_timed(
    domain: str, pool2_done: set[str], *, headed: bool | None = None
) -> tuple[str, float]:
    t0 = time.perf_counter()
    crawl_discovered_domain_to_pool_excluded_2(domain, pool2_done, headed=headed)
    return domain, (time.perf_counter() - t0)


def find_seed_html_file(domain: str) -> Path | None:
    name = seed_html_basename(domain)
    for d in seed_html_search_dirs():
        p = d / name
        if p.is_file():
            return p
    return None


def _parse_dim(val: str | None) -> int | None:
    if not val:
        return None
    s = str(val).strip().lower().rstrip("px")
    try:
        return int(float(s))
    except ValueError:
        return None


def extract_product_images_from_saved_html(html_path: Path, base_url: str) -> list[dict]:
    product_data: list[dict] = []
    try:
        raw = html_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        raw = html_path.read_text(encoding="utf-8", errors="ignore")
    try:
        soup = BeautifulSoup(raw, "lxml")
    except Exception:
        soup = BeautifulSoup(raw, "html.parser")
    if not base_url.endswith("/"):
        base_url = base_url + "/"
    for img in soup.find_all("img"):
        src = img.get("data-src") or img.get("data-lazy-src") or img.get("src")
        if not src or src.startswith("data:"):
            continue
        if any(x in src.lower() for x in IMG_URL_SKIP_SUBSTR):
            continue
        srcset = img.get("srcset") or img.get("data-srcset")
        if srcset:
            candidates = [part.strip().split()[0] for part in srcset.split(",") if part.strip()]
            if candidates:
                best = candidates[-1]
                if not best.startswith("data:") and not any(x in best.lower() for x in IMG_URL_SKIP_SUBSTR):
                    src = best
        w = _parse_dim(img.get("width"))
        h = _parse_dim(img.get("height"))
        if w is not None and h is not None:
            if w < 100 or h < 100:
                continue
            ratio = w / h if h else 1.0
            if ratio > 2.0 or ratio < 0.5:
                continue
        alt = img.get("alt") or ""
        text = ""
        parent = img.find_parent(["div", "li", "article"])
        if parent:
            text = parent.get_text(separator=" ", strip=True)[:500]
        product_data.append({"image_url": urljoin(base_url, src), "alt_text": alt, "description": text})
    for a in soup.find_all("a", href=True):
        href = a.get("href")
        if not href or not href.lower().split("?", 1)[0].endswith(IMAGE_EXTENSIONS):
            continue
        if any(x in href.lower() for x in IMG_URL_SKIP_SUBSTR) or href.startswith("data:"):
            continue
        product_data.append({"image_url": urljoin(base_url, href), "alt_text": a.get_text(strip=True)[:500], "description": ""})
    return product_data


def load_seed_product_data_from_html(domain: str) -> tuple[list[dict], Path | None]:
    p = find_seed_html_file(domain)
    if p is None:
        return [], None
    d = (domain or "").strip()
    base = d.split("?", 1)[0] if d.startswith(("http://", "https://")) else f"https://{d}/"
    if not base.endswith("/"):
        base = base + "/"
    return extract_product_images_from_saved_html(p, base), p


def _is_general_other_category(cat: object) -> bool:
    if pd.isna(cat):
        return False
    s = " ".join(str(cat).strip().lower().split())
    return s in ("general / other", "general/other", "general & other")


GRAPH_EDGE_COLUMNS = [
    "seed_domain",
    "connected_domain",
    "connection_url",
    "image_url",
    "image_filename",
    "vision_label",
    "vision_entity",
    "timestamp",
    "phash_str",
    "image_cluster_id",
    "cnn_prediction",
    "seed_domain_label",
    "seed_domain_category",
    "pdqhash_hex",
    "target_fraud_prob",
    "target_is_fraud",
    "scamadviser_score",
    "connected_domain_category",
]


def _queue_db_path_from_input(input_csv: str, seed_hop: int) -> Path:
    """Per-hop crawl queue (separate from legacy unfiltered queue)."""
    base = Path(input_csv).resolve().parent
    return base / f"extract_images_url_queue_hop{int(seed_hop)}.sqlite3"


def _domains_to_crawl_from_seed_hop_edges(
    graph_df: pd.DataFrame,
    processed_seeds: set[str],
    *,
    seed_hop: int,
) -> list[str]:
    """
    Connected domains on edges whose seed is at ``seed_hop``,
    excluding social platforms, General/Other categories, and already-crawled seeds.
    """
    if "seed_hop" not in graph_df.columns:
        raise KeyError(
            "GRAPH_INPUT_CSV must contain a seed_hop column "
            f"(expected {DEFAULT_GRAPH_INPUT_CSV!r})"
        )
    if "connected_domain" not in graph_df.columns:
        raise KeyError("GRAPH_INPUT_CSV must contain connected_domain")

    hop = pd.to_numeric(graph_df["seed_hop"], errors="coerce")
    edges = graph_df.loc[hop == seed_hop].copy()
    if edges.empty:
        raise ValueError(f"No rows with seed_hop == {seed_hop} in graph input")

    if "connected_domain_category" in edges.columns:
        edges = edges[
            ~edges["connected_domain_category"].map(_is_general_other_category)
        ].copy()

    discovered = set(edges["connected_domain"].dropna().astype(str).str.strip())
    discovered.discard("")
    discovered = {
        d
        for d in discovered
        if not any(ex in d.lower() for ex in EXCLUDED_CRAWL_DOMAINS)
    }
    to_crawl = discovered - processed_seeds
    return sorted(to_crawl)


def _queue_column_names(conn: sqlite3.Connection) -> tuple[str, str, str]:
    cols = {str(r[1]) for r in conn.execute("PRAGMA table_info(url_queue)").fetchall()}
    key_col = "domain" if "domain" in cols else "url" if "url" in cols else ""
    claimed_col = "claimed_by" if "claimed_by" in cols else "owner" if "owner" in cols else ""
    err_col = "last_error" if "last_error" in cols else "error" if "error" in cols else ""
    if not key_col or not claimed_col or not err_col:
        raise RuntimeError(f"Unsupported url_queue schema columns: {sorted(cols)}")
    return key_col, claimed_col, err_col


def _init_queue(db_path: Path, domains: list[str]) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(str(db_path), timeout=30) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS url_queue (
                url TEXT PRIMARY KEY,
                status TEXT NOT NULL DEFAULT 'pending',
                owner TEXT,
                claimed_at TEXT,
                done_at TEXT,
                error TEXT
            )
            """
        )
        key_col, _, _ = _queue_column_names(conn)
        rows = [(d,) for d in domains if d]
        conn.executemany(f"INSERT OR IGNORE INTO url_queue({key_col}) VALUES (?)", rows)
        conn.commit()


def _claim_next_domain(db_path: Path, worker_id: str) -> str | None:
    with sqlite3.connect(str(db_path), timeout=30) as conn:
        key_col, claimed_col, err_col = _queue_column_names(conn)
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            f"SELECT {key_col} FROM url_queue WHERE status='pending' ORDER BY {key_col} LIMIT 1"
        ).fetchone()
        if row is None:
            conn.commit()
            return None
        domain = str(row[0])
        conn.execute(
            f"""
            UPDATE url_queue
            SET status='in_progress', {claimed_col}=?, claimed_at=?, {err_col}=NULL
            WHERE {key_col}=?
            """,
            (worker_id, datetime.datetime.utcnow().isoformat(), domain),
        )
        conn.commit()
        return domain


def _mark_done(db_path: Path, domain: str) -> None:
    with sqlite3.connect(str(db_path), timeout=30) as conn:
        key_col, _, _ = _queue_column_names(conn)
        conn.execute(
            f"UPDATE url_queue SET status='done', done_at=? WHERE {key_col}=?",
            (datetime.datetime.utcnow().isoformat(), domain),
        )
        conn.commit()


def _mark_failed(db_path: Path, domain: str, err: str) -> None:
    with sqlite3.connect(str(db_path), timeout=30) as conn:
        key_col, _, err_col = _queue_column_names(conn)
        conn.execute(
            f"""
            UPDATE url_queue
            SET status='failed', done_at=?, {err_col}=?
            WHERE {key_col}=?
            """,
            (datetime.datetime.utcnow().isoformat(), err[:4000], domain),
        )
        conn.commit()


def main() -> None:
    _raw_in = (os.environ.get("GRAPH_INPUT_CSV") or "").strip()
    graph_input_csv = _raw_in or DEFAULT_GRAPH_INPUT_CSV
    seed_hop = int(os.environ.get("SEED_HOP", "0").strip() or "0")
    num_chunks = int(os.environ.get("NUM_CHUNKS", "1").strip() or "1")
    chunk_id = int(os.environ.get("CHUNK_ID", "0").strip() or "0")
    if num_chunks < 1:
        num_chunks = 1
    if chunk_id < 0 or chunk_id >= num_chunks:
        raise ValueError(
            f"Invalid CHUNK_ID={chunk_id} for NUM_CHUNKS={num_chunks} (valid: 0..{num_chunks-1})"
        )

    queue_db_path = _queue_db_path_from_input(graph_input_csv, seed_hop)
    chunk_pool_dir = queue_db_path.parent / f"collected_features_candidate_pool_excluded_2_chunk{chunk_id}"
    default_chunk_output = queue_db_path.parent / f"master_graph_edges_queue_chunk{chunk_id}.csv"

    _raw_out = (os.environ.get("GRAPH_OUTPUT_CSV") or "").strip()
    graph_output_csv = _raw_out if _raw_out else str(default_chunk_output)

    _raw_seed_ref = (os.environ.get("GRAPH_SEED_REFERENCE_CSV") or "").strip()
    graph_seed_reference_csv = (
        _raw_seed_ref if _raw_seed_ref else DEFAULT_GRAPH_SEED_REFERENCE_CSV
    )

    graph_df_full = pd.read_csv(graph_input_csv, low_memory=False)
    label_map = dict(zip(graph_df_full["connected_domain"], graph_df_full.get("target_is_fraud", "unknown")))
    category_map = dict(zip(graph_df_full["seed_domain"], graph_df_full.get("seed_domain_category", "unknown")))
    if os.path.isfile(graph_seed_reference_csv):
        ref_df = pd.read_csv(graph_seed_reference_csv, usecols=["seed_domain"], low_memory=False)
        processed_seeds = set(ref_df["seed_domain"].dropna().astype(str).str.strip().unique())
    else:
        processed_seeds = set(graph_df_full["seed_domain"].dropna().astype(str).str.strip().unique())

    hop_vals = pd.to_numeric(graph_df_full["seed_hop"], errors="coerce")
    n_hop_rows = int((hop_vals == seed_hop).sum())
    urls = _domains_to_crawl_from_seed_hop_edges(
        graph_df_full, processed_seeds, seed_hop=seed_hop
    )
    print(
        f"[queue] seed_hop=={seed_hop} rows: {n_hop_rows:,} | "
        f"connected domains to crawl: {len(urls):,} | "
        f"already seeds (skipped): {len(processed_seeds):,}"
    )

    _pool_env = (os.environ.get("POOL_EXCLUDED_2_DIR") or "").strip()
    if not _pool_env:
        _m = sys.modules[__name__]
        _m.COLLECTED_POOL_EXCLUDED_2_DIR = chunk_pool_dir

    _init_queue(queue_db_path, urls)
    worker_id = f"chunk{chunk_id}-pid{os.getpid()}"

    print(f"[config] GRAPH_INPUT_CSV={graph_input_csv} (seed_hop=={seed_hop} only)")
    print(f"[config] SEED_HOP={seed_hop}")
    print(f"[config] GRAPH_OUTPUT_CSV={graph_output_csv}")
    print(f"[config] GRAPH_SEED_REFERENCE_CSV={graph_seed_reference_csv}")
    print(f"[config] COLLECTED_POOL_EXCLUDED_2_DIR={COLLECTED_POOL_EXCLUDED_2_DIR}")
    print(f"[config] URL_QUEUE_DB={queue_db_path}")
    print(f"[config] worker_id={worker_id}")
    print(f"Loading CNN model: {CNN_MODEL_PATH}")
    product_cnn_model = load_model(CNN_MODEL_PATH)
    pool2_done_domains = _load_pool2_crawled_domains()

    with ThreadPoolExecutor(max_workers=MAX_CRAWL_WORKERS) as crawl_executor:
        i = 0
        while True:
            url_target = _claim_next_domain(queue_db_path, worker_id)
            if url_target is None:
                print("[queue] No pending domains left. Worker exiting.")
                break
            target_url = url_target if str(url_target).startswith("http") else f"https://{url_target}"
            print(f"i: {i} url: {target_url} urls: queued")
            i += 1
            print(f"\n--- Expanding Discovery: {target_url} ---")
            product_data, html_file = load_seed_product_data_from_html(url_target)
            if not product_data:
                print(f"[skip] No saved HTML for {url_target!r}")
                _mark_done(queue_db_path, str(url_target))
                continue
            print(f"[html] Using {html_file}")
            try:
                rows_to_save = []
                product_kept = 0
                for item in product_data:
                    if product_kept >= 20:
                        break
                    img_url = item["image_url"]
                    img_dir = os.path.join(
                        "/data/mirayrdm/scam/scam_graph_data_2",
                        "images",
                        f"images_{url_target.replace('.', '_')}",
                    )
                    t0 = time.perf_counter()
                    filename = download_image(img_url, save_dir=img_dir)
                    t_download = time.perf_counter() - t0
                    print(f"[TIMER] download_image={t_download:.3f}s url={img_url}", flush=True)
                    if not filename:
                        continue
                    local_path = os.path.join(img_dir, filename)
                    t0 = time.perf_counter()
                    cnn_label = classify_local_image_cnn(product_cnn_model, local_path)
                    t_cnn = time.perf_counter() - t0
                    print(f"[TIMER] cnn={t_cnn:.3f}s label={cnn_label}", flush=True)
                    if cnn_label != "product":
                        continue
                    product_kept += 1
                    print(f"[DBG] Vision start: img_url={img_url}", flush=True)
                    img_t0 = time.perf_counter()
                    try:
                        t0 = time.perf_counter()
                        connected_urls, label, web_entity = detect_news_links(img_url)
                        t_vision = time.perf_counter() - t0
                        print(
                            f"[TIMER] vision={t_vision:.3f}s connected_urls={len(connected_urls)}",
                            flush=True,
                        )
                    except Exception as e:
                        print(f"[vision] failed for {img_url}: {e}")
                        t_vision = 0.0
                        connected_urls, label, web_entity = [], "", ""
                    print(f"[DBG] Vision done: #connected_urls={len(connected_urls)}", flush=True)
                    domains_to_crawl: set[str] = set()
                    crawl_total = 0.0
                    crawl_count = 0
                    for c_url in connected_urls:
                        ext = tldextract.extract(c_url)
                        if not ext.domain or not ext.suffix or ext.domain.lower() in EXCLUDED_CRAWL_DOMAINS:
                            continue
                        full_domain = f"{ext.domain}.{ext.suffix}"
                        print(f"full_domain: {full_domain}")
                        domains_to_crawl.add(full_domain)
                        rows_to_save.append(
                            {
                                "seed_domain": url_target,
                                "connected_domain": full_domain,
                                "connection_url": c_url,
                                "image_url": img_url,
                                "image_filename": filename,
                                "vision_label": label,
                                "vision_entity": web_entity,
                                "timestamp": datetime.datetime.now().isoformat(),
                                "cnn_prediction": "product",
                                "seed_domain_label": label_map.get(url_target, "unknown"),
                                "seed_domain_category": category_map.get(url_target, "unknown"),
                            }
                        )
                    futures = [
                        crawl_executor.submit(crawl_discovered_domain_to_pool_excluded_2_timed, d, pool2_done_domains)
                        for d in domains_to_crawl
                    ]
                    for fut in as_completed(futures):
                        try:
                            _, elapsed_s = fut.result()
                            crawl_total += elapsed_s
                            crawl_count += 1
                        except Exception as e:
                            print(f"[parallel-crawl] task failed: {e}")
                    t_image_total = time.perf_counter() - img_t0
                    print(
                        f"[TIMER] image_total={t_image_total:.3f}s "
                        f"(download={t_download:.3f}, cnn={t_cnn:.3f}, vision={t_vision:.3f}, "
                        f"crawl_total={crawl_total:.3f}, crawl_count={crawl_count})",
                        flush=True,
                    )
                if rows_to_save:
                    out_df = pd.DataFrame(rows_to_save)
                    for col in GRAPH_EDGE_COLUMNS:
                        if col not in out_df.columns:
                            out_df[col] = None
                    out_df = out_df[GRAPH_EDGE_COLUMNS]
                    file_exists = os.path.isfile(graph_output_csv)
                    if file_exists:
                        existing_cols = pd.read_csv(graph_output_csv, nrows=0).columns.tolist()
                        if existing_cols != GRAPH_EDGE_COLUMNS:
                            raise ValueError(
                                f"Schema mismatch existing={existing_cols}, expected={GRAPH_EDGE_COLUMNS}"
                            )
                    out_df.to_csv(graph_output_csv, mode="a", index=False, header=not file_exists)
                _mark_done(queue_db_path, str(url_target))
            except Exception as e:
                _mark_failed(queue_db_path, str(url_target), repr(e))
                print(f"[queue] failed domain {url_target}: {e}")


if __name__ == "__main__":
    main()
