from __future__ import annotations

import pandas as pd
import joblib
import numpy as np
import json
import ast
import os
from sklearn.preprocessing import LabelEncoder
from tqdm import tqdm
import multiprocessing
from concurrent.futures import ProcessPoolExecutor
import re
from bs4 import BeautifulSoup
from tqdm import tqdm
tqdm.pandas()
def check_domain_quality(row):
    domain = str(row["domain"])
    
    # Construct the path to the actual HTML file
    check_path = f"{BASE_DIR}/html/{domain}.html"
    
    # STAGE 1: The "Must Exist" Check
    # If the physical file does not exist, we cannot extract features.
    if not os.path.exists(check_path):
        return False
    
    # STAGE 2: The Content Check
    # Since you want to keep everything that HAS a file, we return True here.
    # We only open the file to verify it's readable.
    try:
        with open(check_path, 'r', encoding='utf-8', errors='ignore') as f:
            # We don't even need to run is_block_page_looser here if 
            # your goal is to keep 100% of existing files.
            content = f.read()
        return True 
    except Exception as e:
        print(f"Error reading {domain}: {e}")
        return False


print("="*60)
print("FEATURE EXTRACTION FROM COLLECTED DATA")
print("="*60)
BASE_DIR = os.environ.get(
    "ORACLE_FEATURE_BASE_DIR",
    "/data/mirayrdm/scam/scam_graph_data_2/collected_features_candidate_pool_excluded_2",
)
ORACLE_DOMAINS_CSV = os.environ.get(
    "ORACLE_DOMAINS_CSV",
    "/data/mirayrdm/scam/scam_graph_data_2/master_graph_edges.csv",
)
# ===================================================================
# LOAD RANKING DATA (Same as original notebook lines 65-73)
# ===================================================================

print("\n1. Loading ranking data...")
df_cisco = pd.read_csv("/data/mirayrdm/scam/top-1m.csv", names=['ranking','domain'])
dict_cisco = dict(zip(df_cisco['domain'], df_cisco['ranking']))

df_majestic = pd.read_csv("/data/mirayrdm/scam/majestic_million.csv")
dict_majestic = dict(zip(df_majestic['Domain'], df_majestic['GlobalRank']))
dict_majestic_tldrank = dict(zip(df_majestic['Domain'], df_majestic['TldRank']))
dict_majestic_refsubnets = dict(zip(df_majestic['Domain'], df_majestic['RefSubNets']))
dict_majestic_refips = dict(zip(df_majestic['Domain'], df_majestic['RefIPs']))

max_tldmajestic = max(dict_majestic_tldrank.values()) + 1
max_cisco = len(dict_cisco) + 1
max_majestic = len(dict_majestic) + 1
tranco_path = "/data/mirayrdm/scam/top-1m-tranco.csv"  
dict_tranco = {}
max_tranco = None
if os.path.exists(tranco_path):
    df_tranco = pd.read_csv(tranco_path)
    if {"domain", "rank"}.issubset(df_tranco.columns):
        dict_tranco = dict(zip(df_tranco["domain"], df_tranco["rank"]))
    elif {"Domain", "Rank"}.issubset(df_tranco.columns):
        dict_tranco = dict(zip(df_tranco["Domain"], df_tranco["Rank"]))
    else:
        if df_tranco.shape[1] >= 2:
            dict_tranco = dict(zip(df_tranco.iloc[:, 1], df_tranco.iloc[:, 0]))
    max_tranco = len(dict_tranco) + 1
    print(f"   Loaded Tranco: {len(dict_tranco)} domains")
else:
    print("   Tranco file not found; will default tranco to max-like value.")

print(f"   Loaded Cisco: {len(dict_cisco)} domains")
print(f"   Loaded Majestic: {len(dict_majestic)} domains")

# ===================================================================
# LOAD YOUR COLLECTED DATA
# ===================================================================

print("\n2. Loading your collected data...")
_domains_cols = pd.read_csv(ORACLE_DOMAINS_CSV, nrows=0).columns.tolist()
if "connected_domain" in _domains_cols:
    domains_df = pd.read_csv(ORACLE_DOMAINS_CSV, usecols=["connected_domain"])
    domains_df["domain"] = domains_df["connected_domain"]
elif "domain" in _domains_cols:
    domains_df = pd.read_csv(ORACLE_DOMAINS_CSV, usecols=["domain"])
else:
    raise ValueError(f"{ORACLE_DOMAINS_CSV} must contain connected_domain or domain column")
def parse_qwen_label(val):
    try:
        # Check if the value looks like a JSON string
        if isinstance(val, str) and val.strip().startswith('{'):
            data = json.loads(val)
            print(data.get('seed_domains_category', 'General / Other'))
            return data.get('seed_domain_category', 'General / Other')
        return val # Return as is if already clean or not JSON
    except (json.JSONDecodeError, TypeError):
        return 'General / Other'

#domains_df['domain_category'] = domains_df['seed_domain_category'].apply(parse_qwen_label)

domains_df = (
    domains_df.dropna(subset=["domain"])
              .astype({"domain": "string"})
              .drop_duplicates(subset=["domain"])
              .reset_index(drop=True)
)
print(domains_df["domain"])

dns_df = pd.read_csv(f"{BASE_DIR}/dns_data.csv")
print(f"   dns_data loaded: {len(dns_df)} rows", flush=True)

whois_df = pd.read_csv(f"{BASE_DIR}/whois_data.csv")
print(f"   whois_data loaded: {len(whois_df)} rows", flush=True)

html_df = pd.read_csv(f"{BASE_DIR}/html_data.csv")
print(f"   html_data loaded: {len(html_df)} rows", flush=True)

scam_url = os.environ.get("ORACLE_SCAM_URL", "candidate_pool_excluded_2")
import ast


def unpack_html_info(x):
    # x is either NaN, a normal path string, or a dict-string like "{'reachable': 1, ...}"
    if pd.isna(x):
        return {"reachable": 0, "html_path": None}
    if isinstance(x, str) and x.strip().startswith("{") and "reachable" in x:
        try:
            d = ast.literal_eval(x)   # works for Python dict-strings (single quotes)
            return d if isinstance(d, dict) else {"reachable": 0, "html_path": None}
        except Exception:
            return {"reachable": 0, "html_path": None}
    # fallback: treat as a direct path
    return {"reachable": 1, "html_path": x}

info = html_df["html_path"].apply(unpack_html_info)

html_df["reachable"] = info.apply(lambda d: d.get("reachable", 0))
html_df["final_url"]  = info.apply(lambda d: d.get("final_url"))
html_df["http_status"] = info.apply(lambda d: d.get("http_status"))
html_df["error"] = info.apply(lambda d: d.get("error"))
html_df["rendered_html_path"] = info.apply(lambda d: d.get("html_path"))

# IMPORTANT: overwrite html_path so the rest of your code keeps working
html_df["html_path"] = html_df["rendered_html_path"]
# ------------------------------------------------------------
# FILTER: keep ONLY reachable domains (i.e., HTML was saved)
# ------------------------------------------------------------
before = len(domains_df)

def extract_html_path_from_cell(x):
    if pd.isna(x):
        return None
    if isinstance(x, str) and x.strip().startswith("{") and "html_path" in x:
        try:
            d = ast.literal_eval(x)
            if isinstance(d, dict):
                return d.get("html_path")
        except Exception:
            return None
    # fallback: treat as direct path
    return x if isinstance(x, str) else None

html_df["rendered_html_path"] = html_df["html_path"].apply(extract_html_path_from_cell)
html_df["html_path"] = html_df["rendered_html_path"]

def html_file_exists(row):
    p = row["html_path"]
    domain = row["domain"]
    
    if not isinstance(p, str) or not p.strip():
        return False
        
    # Construct the path you actually want to check
    # (Note: Ensure BASE_DIR is defined globally)
    check_path = f"{BASE_DIR}/html/{domain}.html"
    print(check_path)
    
    return os.path.exists(check_path)

tmp = html_df.copy()
tmp["file_exists"] = tmp.progress_apply(check_domain_quality, axis=1)

# 2. Identify the domains that actually have files on disk
reachable_domains = set(tmp.loc[tmp["file_exists"], "domain"].astype(str))

# Sync all dataframes
domains_df = domains_df[domains_df["domain"].astype(str).isin(reachable_domains)].reset_index(drop=True)
dns_df     = dns_df[dns_df["domain"].astype(str).isin(reachable_domains)].reset_index(drop=True)
whois_df   = whois_df[whois_df["domain"].astype(str).isin(reachable_domains)].reset_index(drop=True)
html_df    = html_df[html_df["domain"].astype(str).isin(reachable_domains)].reset_index(drop=True)

print(f"   Domains kept after filter: {len(domains_df)} / {before}")

# Skip domains already present in predictions.csv under collected data (resume-friendly).
_PREDICTIONS_CSV = os.path.join(BASE_DIR, "predictions.csv")
_already_predicted: set[str] = set()
if os.path.isfile(_PREDICTIONS_CSV):
    try:
        _pred_df = pd.read_csv(_PREDICTIONS_CSV, low_memory=False)
        if "domain" in _pred_df.columns:
            _already_predicted = {
                str(d).strip()
                for d in _pred_df["domain"]
                if str(d).strip() and str(d).strip().lower() not in ("nan", "none")
            }
            _before_pred = len(domains_df)
            if _already_predicted:
                domains_df = domains_df[
                    ~domains_df["domain"].astype(str).isin(_already_predicted)
                ].reset_index(drop=True)
                dns_df = dns_df[
                    ~dns_df["domain"].astype(str).isin(_already_predicted)
                ].reset_index(drop=True)
                whois_df = whois_df[
                    ~whois_df["domain"].astype(str).isin(_already_predicted)
                ].reset_index(drop=True)
                html_df = html_df[
                    ~html_df["domain"].astype(str).isin(_already_predicted)
                ].reset_index(drop=True)
                print(
                    f"   Skipped {_before_pred - len(domains_df)} domains already in "
                    f"{os.path.basename(_PREDICTIONS_CSV)} ({len(_already_predicted)} rows in file)"
                )
        else:
            print(
                f"   {os.path.basename(_PREDICTIONS_CSV)} has no 'domain' column — not skipping"
            )
    except Exception as e:
        print(f"   Could not read {_PREDICTIONS_CSV} (skip filter): {e}")
else:
    print(f"   No {_PREDICTIONS_CSV} — not skipping any domains")

# ------------------------------------------------------------

df = domains_df.copy()
domain_index_map = dict(zip(df['domain'], df.index))

print(f"   Domains to process: {len(df)}")

# ===================================================================
# CONVERT CSV DATA TO MASTER DICTIONARIES (Original notebook format)
# ===================================================================

print("\n3. Converting data to original notebook format...")

# Convert DNS data
domain_master_dns = {}
for _, row in dns_df.iterrows():
    domain = row['domain']
    dns_records = []
    for col in ['A', 'MX', 'NS', 'TXT', 'AAAA', 'CNAME', 'DNAME', 'HINFO', 'RP', 'SOA']:
        if col in row.index and pd.notna(row[col]):
            try:
                records = ast.literal_eval(str(row[col]))
                if not isinstance(records, list):
                    records = [records]
                for rec in records:
                    dns_records.append({'type': col, 'data': str(rec)})
            except:
                pass
    domain_master_dns[domain] = dns_records

# Convert WHOIS data
def safe_parse_list(x):
    if pd.isna(x): 
        return []
    if isinstance(x, list):
        return x
    try:
        v = ast.literal_eval(str(x))
        return v if isinstance(v, list) else [v]
    except Exception:
        return [str(x)]

domain_master_whois = {}
for _, row in whois_df.iterrows():
    domain = row['domain']

    privacy_guess = row.get('privacy_protected_guess', np.nan)
    is_private = (not pd.isna(privacy_guess)) and float(privacy_guess) == 1.0

    emails = safe_parse_list(row.get('whois_emails', np.nan))
    email_for_features = None if is_private else (emails[0] if len(emails) > 0 else None)

    country_guess = row.get('registrant_country_guess', np.nan)
    country_for_features = None if is_private else (None if pd.isna(country_guess) else str(country_guess))

    whois_data = {
        'dates': {
            'created': row['creation_date'] if pd.notna(row.get('creation_date')) else None,
            'expiry': row['expiration_date'] if pd.notna(row.get('expiration_date')) else None,
        },
        'registrar': {
            'name': row['registrar'] if pd.notna(row.get('registrar')) else None
        },
        'contacts': {
            'registrant': {
                'country': country_for_features,
                'email': email_for_features
            } if not is_private else {}
        },
        "privacy_protected_guess": int(is_private) if not pd.isna(privacy_guess) else None,

    }
    domain_master_whois[domain] = whois_data

print(f"   Converted {len(domain_master_dns)} DNS records")
print(f"   Converted {len(domain_master_whois)} WHOIS records")

# ===================================================================
# ALL FEATURE EXTRACTION FUNCTIONS FROM ORIGINAL NOTEBOOK
# ===================================================================

from tldextract import tldextract
from dateutil.parser import parse
from datetime import datetime, timezone
import pytz
import dateparser
from pathlib import Path
import wordninja
import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse

FREE_EMAIL_PROVIDERS = ["gmail.com", "mail.com", "hotmail.com", "outlook.com", "aol.com", "aim.com", "yahoo.com",
                     "icloud.com", "protonmail.com", "pm.com", "zoho.com", "yandex.com", "titan.com", "gmx.com",
                     "hubspot.com", "tutanota.com"]

def parse_dns_records_for_features(dns_records):
    """Original function from notebook (lines 10-57)"""
    tracked_record_types = ["MX", "CNAME", "DNAME", "HINFO", "AAAA", "NS", "RP", "SOA", "TXT"]
    record_counts = {rtype: 0 for rtype in tracked_record_types}
    domain_verification_count = 0

    for record in dns_records:
        rtype = record.get("type", "").upper()
        if rtype in record_counts:
            record_counts[rtype] += 1
        if rtype == "TXT":
            txt_data = record.get("data", "")
            if "verification" in txt_data.lower():
                domain_verification_count += 1

    features = {}
    for rtype in tracked_record_types:
        features[f"dns_has_{rtype.lower()}"] = (record_counts[rtype] > 0)
        features[f"dns_num_{rtype.lower()}"] = record_counts[rtype]
    features["dns_domain_verification_count"] = domain_verification_count
    return features

def extract_whois_attributes(rootdomain, whois_record):
    """Original function from notebook (lines 293-330)"""
    created_date = -1
    expiry_date = -1
    rslt = whois_record
    if 'result' in rslt:
        for event in rslt['result']['events']:
            if event['eventAction'] == 'registration':
                created_date = event['eventDate']
            if event['eventAction'] == 'expiration':
                expiry_date = event['eventDate']
    elif 'dates' in rslt:
        created_date = rslt['dates'].get('created')
        expiry_date = rslt['dates'].get('expiry')
    else:
        raise ValueError("Unexpected data structure for WHOIS record.")
    
    if created_date == -1 or expiry_date == -1 or created_date is None or expiry_date is None:
        raise ValueError("Missing date information in WHOIS record.")
    
    created_date = dateparser.parse(created_date) if created_date else None
    expiry_date = dateparser.parse(expiry_date) if expiry_date else None
    if expiry_date is None:
        raise ValueError("Could not parse expiry_date")
    if created_date and created_date.tzinfo:
        created_date = created_date.astimezone(pytz.utc).replace(tzinfo=None)
    if expiry_date and expiry_date.tzinfo:
        expiry_date = expiry_date.astimezone(pytz.utc).replace(tzinfo=None)
    
    registration_hour = created_date.hour if created_date else None
    now = datetime.utcnow()
    domain_age_days = (now - created_date).days if created_date else None
    time_to_expiry_days = (expiry_date - now).days if expiry_date else None
    tld = tldextract.extract(rootdomain).suffix
    
    return {
        "domain_age": domain_age_days,
        "time_to_expiry": time_to_expiry_days,
        "tld": tld,
        "registration_hour": registration_hour
    }

def extract_whois_features_exhaustive(whois_data):
    CHEAP_REGISTRARS = {
        'register.ie', 'godaddy', 'namecheap', 'hostgator', 'bluehost',
        '1and1', 'ipage', 'domains.com', 'netart', 'namesilo'
    }

    COUNTRY_CODES = {
        '1': 'US/CA', '44': 'UK', '86': 'CN', '91': 'IN', '81': 'JP',
        '49': 'DE', '33': 'FR', '61': 'AU', '7': 'RU', '39': 'IT',
        '34': 'ES', '55': 'BR', '31': 'NL', '48': 'PL', '46': 'SE',
        '41': 'CH', '32': 'BE', '43': 'AT', '45': 'DK', '47': 'NO',
        '65': 'SG', '82': 'KR', '972': 'IL', '52': 'MX', '66': 'TH',
        '84': 'VN', '27': 'ZA', '971': 'AE', '351': 'PT', '353': 'IE',
        '358': 'FI', '420': 'CZ', '852': 'HK', '886': 'TW'
    }

    features = {}

    # ---- domain_registration_hour (keep like original) ----
    created_date = whois_data.get('dates', {}).get('created')
    if created_date:
        try:
            dt = dateparser.parse(created_date)
            if dt and dt.tzinfo:
                dt = dt.astimezone(pytz.utc).replace(tzinfo=None)
            features['domain_registration_hour'] = dt.hour if dt else None
        except Exception:
            features['domain_registration_hour'] = None
    else:
        features['domain_registration_hour'] = None

    # ---- registrar_name + is_cheap_registrar ----
    registrar_info = whois_data.get('registrar', {})
    features['registrar_name'] = str(registrar_info.get('name')) if registrar_info.get('name') else None
    features['is_cheap_registrar'] = any(
        cheap in str(features['registrar_name']).lower()
        for cheap in CHEAP_REGISTRARS
    ) if features['registrar_name'] else False

    # ---- registrar_country (you probably don’t have phone; keep robust) ----
    registrar_phone = (
        whois_data.get('whois', {})
        .get('whois.verisign-grs.com', {})
        .get('Registrar Abuse Contact Phone', '')
    )
    if registrar_phone:
        phone = registrar_phone.replace('+', '').replace('.', '').strip()
        features['registrar_country'] = 'Others'
        for code, country in COUNTRY_CODES.items():
            if phone.startswith(code):
                features['registrar_country'] = country
                break
    else:
        features['registrar_country'] = 'Others'

    # ---- registrant_country from contacts ----
    registrant_country = whois_data.get('contacts', {}).get('registrant', {}).get('country')
    features['registrant_country'] = str(registrant_country) if registrant_country else 'Others'

    # ---- privacy_protected: USE YOUR STORED GUESS FIRST ----
    privacy_guess = whois_data.get('privacy_protected_guess', None)
    if privacy_guess is not None:
        features['privacy_protected'] = int(float(privacy_guess) == 1.0)
    else:
        # fallback heuristic (don’t default everything to 1)
        registrant_info = whois_data.get('contacts', {}).get('registrant', {})
        features['privacy_protected'] = int(
            bool(registrant_info) and all(not v for v in registrant_info.values() if v is not None)
        )

    # ---- free_email_provider: optional guess, else compute from email ----
    free_email_guess = whois_data.get('free_email_provider_guess', None)
    if free_email_guess is not None:
        features['free_email_provider'] = int(float(free_email_guess) == 1.0)
    else:
        registrant_email = whois_data.get('contacts', {}).get('registrant', {}).get('email', '') or ''
        features['free_email_provider'] = int(any(
            f"@{provider}" in registrant_email.lower()
            for provider in FREE_EMAIL_PROVIDERS
        ))

    return features
def is_cheap_tld(domain):
    """Original function from notebook (lines 405-413)"""
    cheap_tlds_list = ['.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc', '.club',
                       '.online', '.site', '.website', '.space', '.tech', '.store', '.fun']
    domain = domain.lower()
    for tld in cheap_tlds_list:
        if domain.endswith(tld):
            return 1
    return 0

def extract_url_features(domain):
    """Original function from notebook (lines 648-681)"""
    if '//' not in domain:
        domain = 'https://' + domain
    parsed = urlparse(domain)
    full_domain = parsed.netloc.lower()
    
    if '@' in full_domain:
        full_domain = full_domain.split('@')[1]
    
    features = {}
    main_domain = full_domain.split('.')[-2] if '.' in full_domain else full_domain
    features['url_has_hyphen'] = '-' in main_domain
    features['url_has_digit'] = bool(re.search(r'\d', main_domain))
    features['url_subdomain_count'] = len(full_domain.split('.')) - 2
    if features['url_subdomain_count'] < 0:
        features['url_subdomain_count'] = 0
    
    return features

# Social media and HTML feature extraction functions
def extract_social_features_social_corrected(html, domain_name):
    soup = BeautifulSoup(html, 'html.parser')
    all_links = soup.find_all('a')
    
    # Common placeholders found in scam templates (Shopify, Wix, etc.)
    PLACEHOLDERS = {'shopify', 'wix', 'yourpage', 'facebook', 'instagram', 'twitter', 'template'}
    
    social_patterns = {
        'facebook': r'facebook\.com/(?!(marketplace|pages|groups|events|watch|search|login|recover|help|policy|privacy|terms|messages|sharer|share|policy\.php))([a-zA-Z0-9\.]{3,})/?$',
        'instagram': r'instagram\.com/(?!(p/|reel/|explore/|accounts/|tags/|directory/|login/|signup/))([a-zA-Z0-9\._]{3,30})/?$',
    }

    features = {
        'facebook_profile_linked': 0,
        'facebook_profile_valid': 0, # Heuristic check
        'instagram_profile_linked': 0,
        'instagram_profile_valid': 0,
        'social_link_matches_domain': 0 # Does the FB name match the domain?
    }

    try:
        clean_domain = domain_name.split('.')[0].lower()
        
        for a_tag in all_links:
            href = a_tag.get('href', '').strip().lower()
            if not href or 'facebook.com' not in href and 'instagram.com' not in href:
                continue

            for platform, pattern in social_patterns.items():
                match = re.search(pattern, href)
                if match:
                    username = match.group(2)
                    features[f'{platform}_profile_linked'] = 1
                    
                    # Heuristic 1: Not a common placeholder
                    if username not in PLACEHOLDERS:
                        features[f'{platform}_profile_valid'] = 1
                    
                    # Heuristic 2: Name match (e.g. facebook.com/xyz matches xyz.com)
                    if clean_domain in username or username in clean_domain:
                        features['social_link_matches_domain'] = 1
    except:
        features["error"] = 1
    
    return features

def extract_social_features_deepseek_additional(html, domain):
    """Original function from notebook (lines 506-641)"""
    soup = BeautifulSoup(html, 'html.parser')
    features = {
        'presence_of_contact_link': 0,
        'num_mailto_links': 0,
        'num_telephone_links': 0,
        'num_whatsapp_links': 0,
        'review_system_linked': 0,
        'has_app_store': 0,
        'has_review_widget': 0,
        'num_links': 0,
        'num_internal_links': 0,
        'num_external_links': 0,
        'num_h1_h6_tags': 0,
        'num_css_classes': 0,
        'num_css_ids': 0,
        'num_distinct_html_tags': 0,
        'num_img_tags': 0,
        'num_iframe_tags': 0,
        'num_external_http_links': 0,
        'num_external_https_links': 0,
        'num_links_with_ip': 0,
        'presence_work_with_us_link': 0,
        'presence_cookie_consent_notice': 0,
        'mailto_contact_free_provider': 0
    }
    
    contact_patterns = [
        re.compile(r'^mailto:', re.I),
        re.compile(r'^tel:', re.I),
        re.compile(r'^https?://(www\.)?(wa\.me|api\.whatsapp\.com)/', re.I)
    ]

    review_platform_domains = [
        'trustpilot.com', 'sitejabber.com', 'g2.com', 'capterra.com',
        'glassdoor.com', 'yelp.com', 'bbb.org', 'consumeraffairs.com',
        'resellerratings.com', 'reviews.io', 'feefo.com'
    ]
    
    review_widget_patterns = [
        re.compile(r'trustpilot', re.I),
        re.compile(r'g2[-_]review', re.I),
        re.compile(r'sitejabber[-_]widget', re.I),
        re.compile(r'rating[-_]?widget', re.I),
        re.compile(r'review(s)?[-_]?widget', re.I),
        re.compile(r'(customer|product)[-_]?reviews', re.I),
        re.compile(r'star[-_]?rating', re.I)
    ]
    
    try:
        all_links = soup.find_all('a')
        features['num_links'] = len(all_links)
        external_http, external_https = 0, 0
        ipv4_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}(:\d+)?$')

        for a_tag in all_links:
            href = a_tag.get('href', '')
            href_lower = href.lower()
            parsed_href = urlparse(href)
            parsed_domain = parsed_href.netloc.lower()

            for pattern in contact_patterns:
                if pattern.match(href):
                    features['presence_of_contact_link'] = 1

            if any(domain in parsed_domain for domain in review_platform_domains):
                features['review_system_linked'] = 1

            if href.startswith('http://'):
                external_http += 1
            elif href.startswith('https://'):
                external_https += 1

            if href.startswith(('http://', 'https://')):
                netloc = parsed_href.netloc.split(':')[0]
                if ipv4_pattern.match(netloc):
                    features['num_links_with_ip'] += 1

            if href_lower.startswith('mailto:'):
                features['num_mailto_links'] += 1
                email_content = href_lower.partition('mailto:')[2].split('?')[0]
                emails = email_content.split(',')
                for email in emails:
                    email = email.strip()
                    if "@" in email:
                        _, provider = email.split("@", 1)
                        if provider.lower() in FREE_EMAIL_PROVIDERS:
                            features['mailto_contact_free_provider'] = 1
            elif href_lower.startswith('tel:'):
                features['num_telephone_links'] += 1
            elif 'wa.me' in href_lower or 'api.whatsapp.com' in href_lower:
                features['num_whatsapp_links'] += 1

            link_text = a_tag.get_text().lower()
            if re.search(r'work\s*with\s*us|careers', link_text, re.I):
                features['presence_work_with_us_link'] = 1

        features['num_external_http_links'] = external_http
        features['num_external_https_links'] = external_https
        features['num_external_links'] = external_http + external_https
        features['num_internal_links'] = features['num_links'] - features['num_external_links']

        # Review widgets
        for iframe in soup.find_all('iframe'):
            src = iframe.get('src', '')
            if any(domain in src for domain in review_platform_domains):
                features['has_review_widget'] = 1
                break

        if not features['has_review_widget']:
            for script in soup.find_all('script'):
                src = script.get('src', '')
                if any(domain in src for domain in review_platform_domains):
                    features['has_review_widget'] = 1
                    break

        # Structural elements
        features['num_h1_h6_tags'] = len(soup.find_all(['h1', 'h2', 'h3', 'h4', 'h5', 'h6']))
        features['num_img_tags'] = len(soup.find_all('img'))
        features['num_iframe_tags'] = len(soup.find_all('iframe'))

        classes = set()
        ids = set()
        for element in soup.find_all():
            classes.update(element.get('class', []))
            element_id = element.get('id')
            if element_id:
                ids.add(element_id)
        features['num_css_classes'] = len(classes)
        features['num_css_ids'] = len(ids)
        features['num_distinct_html_tags'] = len({tag.name for tag in soup.find_all()})

        cookie_keywords = ['cookie', 'consent', 'gdpr']
        cookie_elements = soup.find_all(
            lambda tag: any(keyword in tag.get_text().lower() for keyword in cookie_keywords) or
                        any(keyword in str(tag.attrs).lower() for keyword in cookie_keywords)
        )
        features['presence_cookie_consent_notice'] = 1 if cookie_elements else 0
    except Exception as e:
        features["error"] = 1
    
    return features

def extract_social_features_enhanced(html_source):
    """Original function from notebook (lines 723-955)"""
    features = {
        'verified_purchase_badges': 0,
        'secure_payment_gateway': 0,
        'presence_privacy_policy': 0,
        'presence_terms_conditions': 0,
        'broken_images': 0,
        'has_shopping_cart': 0,
        'has_checkout_process': 0,
        'has_product_schema': 0,
        'has_price_schema': 0,
        'has_stock_indicator': 0,
        'has_size_guide': 0,
        'has_return_policy': 0,
        'has_shipping_info': 0,
        'social_share_buttons': 0,
        'social_follower_count': 0,
        'social_engagement_widgets': 0,
        'has_consistent_structure': 0,
        'ssl_trust_badges': 0,
        'payment_trust_badges': 0,
        'security_trust_badges': 0,
        'common_trust_signals': 0,
        'has_contact_form': 0,
        'has_physical_address': 0,
        'has_business_hours': 0,
        'has_valid_email': 0,
        'has_valid_phone': 0,
    }
    
    soup = BeautifulSoup(html_source, 'html.parser')
    html_text = soup.get_text().lower()

    # Verified Purchase Badges
    verified_badges = set()
    for tag in soup.find_all(['div', 'span', 'img']):
        classes = ' '.join(tag.get('class', [])).lower()
        alt_text = tag.get('alt', '').lower()
        aria_label = tag.get('aria-label', '').lower()
        tag_text = tag.get_text().lower()
        if any(kw in classes for kw in ['verified', 'purchase']):
            verified_badges.add(tag)
        elif 'verified purchase' in alt_text or 'verified buyer' in tag_text:
            verified_badges.add(tag)
        elif 'verified' in aria_label or 'purchase' in aria_label:
            verified_badges.add(tag)
    features['verified_purchase_badges'] = len(verified_badges)

    # Secure Payment Gateway
    secure_keywords = ['secure payment', 'ssl', 'https', 'encrypted']
    secure_payment_signals = []
    for keyword in secure_keywords:
        secure_payment_signals.extend(soup.find_all(string=lambda s: s and keyword in s.lower()))
    features['secure_payment_gateway'] = 1 if secure_payment_signals else 0

    # Privacy Policy
    privacy_links = soup.find_all('a', href=re.compile(r'privacy', re.I))
    privacy_links += [a for a in soup.find_all('a') if 'privacy' in a.get_text().lower()]
    features['presence_privacy_policy'] = 1 if privacy_links else 0

    # Terms & Conditions
    terms_links = soup.find_all('a', href=re.compile(r'terms|conditions', re.I))
    terms_links += [a for a in soup.find_all('a') if 'terms and conditions' in a.get_text().lower()]
    features['presence_terms_conditions'] = 1 if terms_links else 0

    # Broken Images
    broken_images = 0
    for img in soup.find_all('img'):
        src = img.get('src', '').strip().lower()
        if not src or any(bad in src for bad in ['placeholder', 'example', 'noimage']):
            broken_images += 1
    features['broken_images'] = broken_images

    # Shopping Cart
    cart_elements = soup.find_all(lambda tag: 
        ((tag.name in ['a', 'button']) and 
         ((tag.get('href') and 'cart' in tag.get('href').lower()) or ('cart' in tag.get_text().lower()))) or
        (tag.get('id') and 'cart' in tag.get('id').lower()) or
        (any('cart' in token for token in tag.get('class', [])))
    )
    features['has_shopping_cart'] = 1 if cart_elements else 0

    # Checkout Process
    checkout_elements = soup.find_all(lambda tag: 
        ((tag.name in ['a', 'button']) and 
         ((tag.get('href') and 'checkout' in tag.get('href').lower()) or ('checkout' in tag.get_text().lower()))) or
        (tag.name == 'form' and tag.get('action') and 'checkout' in tag.get('action').lower())
    )
    features['has_checkout_process'] = 1 if checkout_elements else 0

    # Product Schema
    has_product = False
    has_price = False
    for script in soup.find_all('script', {'type': 'application/ld+json'}):
        try:
            data = json.loads(script.string)
            data_list = data if isinstance(data, list) else [data]
            for item in data_list:
                if isinstance(item, dict) and item.get('@type') == 'Product':
                    has_product = True
                    offers = item.get('offers', {})
                    if isinstance(offers, list) and offers:
                        offers = offers[0]
                    if isinstance(offers, dict) and 'price' in offers:
                        has_price = True
        except Exception:
            continue
    features['has_product_schema'] = int(has_product)
    features['has_price_schema'] = int(has_price)

    # Stock Indicator
    stock_elements = soup.find_all(string=re.compile(r'in stock|out of stock|only\s*\d+\s*left', re.I))
    features['has_stock_indicator'] = 1 if stock_elements else 0

    # Size Guide
    size_guide = soup.find_all(lambda tag: 
        (tag.name == 'a' and (tag.get('href') and 'size' in tag.get('href').lower())) or
        ('size guide' in tag.get_text().lower())
    )
    features['has_size_guide'] = 1 if size_guide else 0

    # Return/Shipping
    return_policy = soup.find_all(lambda tag: (
        (tag.name == 'a' and ((tag.get('href') and 'return' in tag.get('href').lower()) or ('return policy' in tag.get_text().lower()))) or
        ('refund' in tag.get_text().lower())
    ))
    shipping_info = soup.find_all(lambda tag: (
        (tag.name == 'a' and ((tag.get('href') and 'shipping' in tag.get('href').lower()) or ('shipping info' in tag.get_text().lower()))) or
        ('delivery' in tag.get_text().lower())
    ))
    features['has_return_policy'] = 1 if return_policy else 0
    features['has_shipping_info'] = 1 if shipping_info else 0

    # Social Share Buttons
    social_share = soup.find_all('a', href=re.compile(
        r'facebook\.com/sharer|twitter\.com/intent/tweet|linkedin\.com/share|pinterest|reddit', re.I))
    features['social_share_buttons'] = len(social_share)

    # Social Follower Count
    follower_texts = soup.find_all(string=re.compile(
        r'\b\d+([.,]?\d+)?\s*(million|m|thousand|k)?\s*(followers|likes|fans)\b', re.I))
    features['social_follower_count'] = 1 if follower_texts else 0

    # Social Engagement Widgets
    social_widgets = soup.find_all(lambda tag: (
        ((tag.name in ['iframe', 'script']) and 
         any(platform in (tag.get('src') or '').lower() for platform in ['facebook', 'twitter', 'instagram', 'pinterest', 'reddit']))
    ))
    features['social_engagement_widgets'] = 1 if social_widgets else 0

    # Consistent Structure
    class_counts = {}
    for tag in soup.find_all(class_=True):
        for cls in tag.get('class'):
            cls = cls.lower()
            class_counts[cls] = class_counts.get(cls, 0) + 1
    repeated_classes = [cls for cls, count in class_counts.items() if count > 1]
    features['has_consistent_structure'] = 1 if len(repeated_classes) > 3 else 0

    # Trust Badges
    ssl_badges = soup.find_all('img', alt=re.compile(r'ssl|secure', re.I))
    features['ssl_trust_badges'] = len(ssl_badges)
    payment_badges = soup.find_all('img', alt=re.compile(r'visa|mastercard|amex|paypal', re.I))
    features['payment_trust_badges'] = len(payment_badges)
    security_badges = soup.find_all('img', alt=re.compile(r'mcafee|norton|bbb', re.I))
    features['security_trust_badges'] = len(security_badges)

    # Common Trust Signals
    trust_text = soup.find_all(string=re.compile(r'trusted by|secure checkout|100%\s*safety|money back', re.I))
    features['common_trust_signals'] = 1 if trust_text else 0

    # Contact Form
    forms = soup.find_all('form')
    for form in forms:
        inputs = form.find_all('input')
        textareas = form.find_all('textarea')
        has_email = any((input_.get('type') == 'email' or 'email' in (input_.get('name') or '').lower()) for input_ in inputs)
        has_phone = any((input_.get('type') == 'tel' or 'phone' in (input_.get('name') or '').lower()) for input_ in inputs)
        if (has_email or has_phone) and textareas:
            features['has_contact_form'] = 1
            break

    # Physical Address
    address_pattern = re.compile(r'\d{1,5}\s+\w+(\s+\w+)*\s+(st|street|rd|road|ave|avenue|blvd|boulevard|lane|ln|suite|ste|apt)\b', re.I)
    addresses = soup.find_all(string=address_pattern)
    features['has_physical_address'] = 1 if addresses else 0

    # Business Hours
    hours_pattern = re.compile(r'\b(24/7|open\s+24\s*hours|mon[-\s]?fri|hours|opening|closing)\b', re.I)
    hours_elements = soup.find_all(string=hours_pattern)
    features['has_business_hours'] = 1 if hours_elements else 0

    # Valid Email
    email_regex = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
    emails = email_regex.findall(html_text)
    valid_emails = [email for email in emails if all(substr not in email.lower() for substr in ['example', 'test'])]
    features['has_valid_email'] = 1 if valid_emails else 0

    # Valid Phone
    phone_regex = re.compile(r'(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}')
    phones = phone_regex.findall(html_text)
    valid_phones = [phone for phone in phones if not re.search(r'0{3}[-.\s]?0{3}[-.\s]?0{4}', phone)]
    features['has_valid_phone'] = 1 if valid_phones else 0

    return features

# ===================================================================
# PROCESS DNS FEATURES (Original notebook lines 242-266)
# ===================================================================

print("\n4. Processing DNS features...")

def process_dns(domain):
    try:
        parsed = parse_dns_records_for_features(domain_master_dns[domain])
        return (domain, parsed, None)
    except Exception as e:
        return (domain, None, e)

num_processes = min(20, multiprocessing.cpu_count())
dns_results = []
domains = list(df['domain'].to_list())

with multiprocessing.Pool(processes=num_processes) as pool:
    for domain, parsed, error in tqdm(pool.imap(process_dns, domains), total=len(domains)):
        dns_results.append((domain, parsed, error))

err_domains_dns = []
for domain, parsed, error in dns_results:
    if error is None:
        for feature in parsed:
            row_idx = domain_index_map[domain]
            df.at[row_idx, feature] = parsed[feature]
    else:
        err_domains_dns.append(domain)

print(f"   DNS errors: {len(err_domains_dns)}")

# ===================================================================
# PROCESS WHOIS FEATURES (Original notebook lines 333-365)
# ===================================================================

print("\n5. Processing WHOIS features...")

def process_whois(domain):
    try:
        parsed = extract_whois_attributes(domain, domain_master_whois[domain])
        return (domain, parsed, None)
    except Exception as e:
        return (domain, None, e)

whois_results = []
with multiprocessing.Pool(processes=num_processes) as pool:
    for domain, parsed, error in tqdm(pool.imap(process_whois, domains), total=len(domains)):
        whois_results.append((domain, parsed, error))

err_domains_whois = []
for domain, parsed, error in whois_results:
    if error is None:
        for feature in parsed:
            row_idx = domain_index_map[domain]
            df.at[row_idx, feature] = parsed[feature]
    else:
        err_domains_whois.append(domain)

print(f"   WHOIS errors: {len(err_domains_whois)}")

df['whois_data_missing'] = 0
df.loc[df['domain'].isin(err_domains_whois), 'whois_data_missing'] = 1
# Add exhaustive WHOIS features (Original notebook lines 1166-1170)
print("\n6. Adding exhaustive WHOIS features...")
for domain in tqdm(df['domain'].to_list()):
    if domain in domain_master_whois:
        parsed = extract_whois_features_exhaustive(domain_master_whois[domain])
        for feature in parsed:
            row_idx = domain_index_map[domain]
            df.at[row_idx, feature] = parsed[feature]

# ===================================================================
# PROCESS URL FEATURES (Original notebook lines 684-688)
# ===================================================================

print("\n7. Processing URL features...")

for domain in tqdm(df['domain'].to_list()):
    row_idx = domain_index_map[domain]
    parsed = extract_url_features(domain)
    for feature in parsed:
        df.loc[row_idx, feature] = parsed[feature]
    
    # Add cheap TLD (lines 414-416)
    cheap = is_cheap_tld(domain)
    df.loc[row_idx, 'cheap_tld'] = cheap
    
    # Add domain subwords (lines 636-639)
    domain_words = len(wordninja.split(domain)) - 1
    df.loc[row_idx, 'domain_subwords'] = domain_words

# ===================================================================
# PROCESS HTML FEATURES (Original notebook lines 650-722, 744-784, 957-1000)
# ===================================================================

print("\n8. Processing HTML social media features...")
import re
from urllib.parse import urlparse

TRUSTPILOT_DOMAINS = {"trustpilot.com", "www.trustpilot.com"}

def extract_trustpilot_present(html: str) -> int:
    if not html or not isinstance(html, str):
        return 0

    h = html.lower()

    # Fast substring checks (catches widgets too)
    if "trustpilot" not in h:
        return 0

    # href="https://www.trustpilot.com/review/..."
    for m in re.finditer(r'href\s*=\s*["\']([^"\']+)["\']', h):
        url = m.group(1)
        try:
            netloc = urlparse(url).netloc.lower()
            if netloc in TRUSTPILOT_DOMAINS or netloc.endswith(".trustpilot.com"):
                return 1
        except Exception:
            continue

    widget_markers = [
        "trustpilot-widget",
        "tp-widget",
        "widget.trustpilot.com",
        "trustbox",
        "data-trustpilot",
    ]
    if any(x in h for x in widget_markers):
        return 1

    return 0

def process_html_social(domain):
    # Check if domain exists in html_df
    matching_rows = html_df[html_df['domain'] == domain]
    
    if matching_rows.empty:
        # Domain not found in html_df
        return domain, {"error": 2}
    
    html_path = matching_rows['html_path'].values[0]
    html_path =f"{BASE_DIR}/html/{domain}.html"
    # Check if html_path is valid (not NaN)
    if pd.isna(html_path) or not isinstance(html_path, str):
        return domain, {"error": 2}
    
    # Check if file exists
    if not os.path.exists(html_path):
        return domain, {"error": 2}
    
    # Rest of your existing code
    with open(html_path, "r", encoding='utf-8', errors='ignore') as file:
        html = file.read()
    
    parsed = extract_social_features_social_corrected(html, domain)
    return domain, parsed

error_html_social = []
with ProcessPoolExecutor(max_workers=24) as executor:
    for domain, parsed in tqdm(executor.map(process_html_social, domains), total=len(domains)):
        if 'error' in parsed:
            error_html_social.append(domain)
            continue
        row_idx = domain_index_map[domain]
        for feature, value in parsed.items():
            df.loc[row_idx, feature] = value

print(f"   HTML social errors: {len(error_html_social)}")

print("\n9. Processing HTML additional content features...")

def process_html_additional(domain):
    matching_rows = html_df[html_df['domain'] == domain]
    if matching_rows.empty:
        return domain, {"error": 2}
    
    html_path = matching_rows['html_path'].values[0]
    html_path = f"{BASE_DIR}/html/{domain}.html"


    # --- Validate path type ---
    if pd.isna(html_path) or not isinstance(html_path, str):
        return domain, {"error": 2}

    if not os.path.exists(html_path):
        return domain, {"error": 2}

    try:
        with open(html_path, "r", encoding="utf-8", errors="ignore") as file:
            html = file.read()
        parsed = extract_social_features_deepseek_additional(html, domain)
        parsed["trustpilot_present"] = extract_trustpilot_present(html)

        return domain, parsed
    except Exception as e:
        return domain, {"error": str(e)}

error_html_additional = []
with ProcessPoolExecutor(max_workers=24) as executor:
    for domain, parsed in tqdm(executor.map(process_html_additional, domains), total=len(domains)):
        if 'error' in parsed:
            error_html_additional.append(domain)
            continue
        row_idx = domain_index_map[domain]
        for feature, value in parsed.items():
            df.loc[row_idx, feature] = value

print(f"   HTML additional errors: {len(error_html_additional)}")

print("\n10. Processing HTML enhanced trust features...")

def process_html_enhanced(domain):
    matching_rows = html_df[html_df['domain'] == domain]
    if matching_rows.empty:
        return domain, {"error": 2}
    
    html_path = matching_rows['html_path'].values[0]
    html_path = f"{BASE_DIR}/html/{domain}.html"
    # --- Validate path type ---
    if pd.isna(html_path) or not isinstance(html_path, str):
        return domain, {"error": 2}

    if not os.path.exists(html_path):
        return domain, {"error": 2}

    try:
        with open(html_path, "r", encoding="utf-8", errors="ignore") as file:
            html = file.read()
        parsed = extract_social_features_enhanced(html)
        return domain, parsed
    except Exception as e:
        return domain, {"error": str(e)}

error_html_enhanced = []
with ProcessPoolExecutor(max_workers=24) as executor:
    for domain, parsed in tqdm(executor.map(process_html_enhanced, domains), total=len(domains)):
        if 'error' in parsed:
            error_html_enhanced.append(domain)
            continue
        row_idx = domain_index_map[domain]
        for feature, value in parsed.items():
            df.loc[row_idx, feature] = value

print(f"   HTML enhanced errors: {len(error_html_enhanced)}")

# ===================================================================
# ADD RANKING FEATURES (Original notebook lines 1173-1178)
# ===================================================================

print("\n11. Adding ranking features...")

for domain in tqdm(df['domain'].to_list()):
    row_idx = domain_index_map[domain]
    df.at[row_idx, 'majestic_refips'] = dict_majestic_refips[domain] if domain in dict_majestic_refips else 1
    df.at[row_idx, 'majestic_refsubnets'] = dict_majestic_refsubnets[domain] if domain in dict_majestic_refsubnets else 1
    df.at[row_idx, 'majestic_tldrank'] = dict_majestic_tldrank[domain] if domain in dict_majestic_tldrank else max_tldmajestic
    df.at[row_idx, 'majestic'] = dict_majestic[domain] if domain in dict_majestic else max_majestic
    df.at[row_idx, 'cisco'] = dict_cisco[domain] if domain in dict_cisco else max_cisco
    if dict_tranco:
        df.at[row_idx, 'tranco'] = dict_tranco[domain] if domain in dict_tranco else max_tranco
    else:
        df.at[row_idx, 'tranco'] = 1000001
# ===================================================================
# ADD TRUSTPILOT FEATURE (Original notebook lines 1187-1194)
# ===================================================================

print("\n12. Adding trustpilot_present feature...")
df['trustpilot_present'] = 0  # Default to 0


# ===================================================================
# 13. SAVE RAW FEATURE TABLE (NO ENCODING HERE)
# ===================================================================

print("\n13. Saving raw features (no encoding)...")

# Optional: enforce types for common boolean flags (safe to keep)
boolean_cols = [
    'dns_has_mx', 'dns_has_cname', 'dns_has_dname', 'dns_has_hinfo',
    'dns_has_aaaa', 'dns_has_ns', 'dns_has_rp', 'dns_has_soa', 'dns_has_txt',
    'url_has_hyphen', 'url_has_digit', 'is_cheap_registrar',
    'privacy_protected', 'free_email_provider'
]
for col in boolean_cols:
    if col in df.columns:
        df[col] = df[col].fillna(0).astype(int)

# Keep raw categoricals as strings (DO NOT encode)
for col in ["tld", "registrar_name", "registrar_country", "registrant_country", "domain_category"]:
    if col in df.columns:
        df[col] = df[col].fillna("UnKnown").astype(str)
    else:
        df[col] = "UnKnown"
df["label"] = 0
# Save full raw table (includes domain + raw features)
raw_out = f"{BASE_DIR}/raw_features_{scam_url}.csv"
df.to_csv(raw_out, index=False)
print(f"   ✓ Saved raw features to: {raw_out}")

# Stop here for Path A. Training/prediction happens in a separate script.
print("\nDONE (feature extraction only).")



'''
print("\n13. Encoding categorical features...")

# Load model to get expected feature names
model = joblib.load('/data/ppaudeldata/Fraud/Oracle/random_forest_model.pkl')
expected_features = list(model.feature_names_in_)
# ---- Global feature importance (built-in RF) ----
importances = pd.Series(model.feature_importances_, index=expected_features) \
               .sort_values(ascending=False)

print("\nTop 30 features by RF importance:")
print(importances.head(30))

# Encode categorical features
categorical_mappings = {}

# TLD encoding
if 'tld' in df.columns:
    try:
        tld_encoder = joblib.load('tld_encoder.pkl')
        print("   Using saved TLD encoder")
        df['tld_encoded'] = df['tld'].apply(
            lambda x: tld_encoder.transform([x])[0] if x in tld_encoder.classes_ else len(tld_encoder.classes_)
        )
    except FileNotFoundError:
        print("   Creating new TLD encoder")
        df['tld'] = df['tld'].fillna('unknown')
        tld_encoder = LabelEncoder()
        df['tld_encoded'] = tld_encoder.fit_transform(df['tld'])

# Registrar name encoding
if 'registrar_name' in df.columns:
    try:
        registrar_encoder = joblib.load('registrar_name_encoder.pkl')
        print("   Using saved registrar_name encoder")
        df['registrar_name'] = df['registrar_name'].apply(
            lambda x: registrar_encoder.transform([str(x)])[0] if str(x) in registrar_encoder.classes_ else len(registrar_encoder.classes_)
        )
    except FileNotFoundError:
        print("   Creating new registrar_name encoder")
        df['registrar_name'] = df['registrar_name'].fillna('Unknown')
        registrar_encoder = LabelEncoder()
        df['registrar_name'] = registrar_encoder.fit_transform(df['registrar_name'].astype(str))

# Registrar country encoding
if 'registrar_country' in df.columns:
    try:
        reg_country_encoder = joblib.load('registrar_country_encoder.pkl')
        print("   Using saved registrar_country encoder")
        df['registrar_country'] = df['registrar_country'].apply(
            lambda x: reg_country_encoder.transform([str(x)])[0] if str(x) in reg_country_encoder.classes_ else len(reg_country_encoder.classes_)
        )
    except FileNotFoundError:
        print("   Creating new registrar_country encoder")
        df['registrar_country'] = df['registrar_country'].fillna('Others')
        reg_country_encoder = LabelEncoder()
        df['registrar_country'] = reg_country_encoder.fit_transform(df['registrar_country'].astype(str))

# Registrant country encoding
if 'registrant_country' in df.columns:
    try:
        rant_country_encoder = joblib.load('registrant_country_encoder.pkl')
        print("   Using saved registrant_country encoder")
        df['registrant_country'] = df['registrant_country'].apply(
            lambda x: rant_country_encoder.transform([str(x)])[0] if str(x) in rant_country_encoder.classes_ else len(rant_country_encoder.classes_)
        )
    except FileNotFoundError:
        print("   Creating new registrant_country encoder")
        df['registrant_country'] = df['registrant_country'].fillna('Others')
        rant_country_encoder = LabelEncoder()
        df['registrant_country'] = rant_country_encoder.fit_transform(df['registrant_country'].astype(str))

# Convert boolean columns to int
boolean_cols = [
    'dns_has_mx', 'dns_has_cname', 'dns_has_dname', 'dns_has_hinfo', 
    'dns_has_aaaa', 'dns_has_ns', 'dns_has_rp', 'dns_has_soa', 'dns_has_txt',
    'url_has_hyphen', 'url_has_digit', 'is_cheap_registrar', 
    'privacy_protected', 'free_email_provider'
]

for col in boolean_cols:
    if col in df.columns:
        df[col] = df[col].fillna(0).astype(int)

# ===================================================================
# SELECT FEATURES IN CORRECT ORDER
# ===================================================================

print("\n14. Selecting features in model's expected order...")

# Check for missing features
your_features = set(df.columns)
missing_features = set(expected_features) - your_features

if missing_features:
    print(f"   ⚠ Missing {len(missing_features)} features, adding with default 0:")
    for feat in sorted(missing_features):
        print(f"      - {feat}")
        df[feat] = 0

# Select in correct order
X_test = df[expected_features].fillna(0)

# write a CSV that includes domain_id (and optionally domain) alongside features
#test_set_out = pd.concat([df[['domain_id']], X_test], axis=1)
# (optional but useful)
#test_set_out = pd.concat([df[['domain_id', 'domain']], X_test], axis=1)

X_test.to_csv(f"test_set_{scam_url}.csv", index=False)
for c in ["privacy_protected", "registrant_country", "free_email_provider", "registrar_name"]:
    print(c, X_test[c].value_counts(dropna=False).head(10))
# Keep domains for results
domains_series = df['domain'].copy()

print(f"   ✓ Final shape: {X_test.shape}")
print(f"   ✓ Missing values after fill: {X_test.isna().sum().sum()}")

# ===================================================================
# MAKE PREDICTIONS
# ===================================================================

print("\n15. Making predictions...")

predictions = model.predict(X_test)

probabilities = model.predict_proba(X_test)[:, 1]

results_df = pd.DataFrame({
    'domain': domains_series,
    'is_fraud': predictions,
    'fraud_probability': probabilities
})
results_df.to_csv(f'fraud_predictions_{scam_url}.csv', index=False)

print("\n" + "="*60)
print("PREDICTION RESULTS")
print("="*60)
print(f"\nTotal domains: {len(results_df)}")
print(f"Predicted FRAUDULENT: {predictions.sum()} ({predictions.sum()/len(predictions)*100:.1f}%)")
print(f"Predicted LEGITIMATE: {len(predictions) - predictions.sum()} ({(len(predictions) - predictions.sum())/len(predictions)*100:.1f}%)")

print("\n" + "-"*60)
print("Top 10 Most Suspicious Domains:")
print("-"*60)
for _, row in results_df.head(10).iterrows():
    label = "🚨 FRAUD" if row['is_fraud'] == 1 else "✓ LEGIT"
    print(f"{label:12s} {row['fraud_probability']:6.2%}  {row['domain']}")

print(f"\n✓ Results saved to: fraud_predictions.csv")
print("\n" + "="*60)
print("DONE")
print("="*60)
'''