"""
bio_link_classifier.py
Classifies a TikTok bio link into one of:
    - E-commerce (own store)
    - Link Aggregator
    - Messaging App
    - Social Media
    - Other / Unknown
    - None (no bio link at all)

Handles TikTok's own redirect wrapper
(tiktok.com/link/v2?...&target=<real-destination>), which is what most
raw Bio Link values actually are — the real destination is URL-encoded
inside the `target` query param.
"""

import re
from urllib.parse import urlparse, parse_qs, unquote

# ── Category → domain keyword lists ─────────────────────────────────────
# Keep these lowercase. Match against the *unwrapped* destination domain.

LINK_AGGREGATORS = [
    "linktr.ee", "linktree.com", "bio.link", "beacons.ai", "beacons.page",
    "campsite.bio", "lnk.bio", "carrd.co", "linkin.bio", "milkshake.app",
    "solo.to", "taplink.cc", "shorby.com", "koji.to", "linkpop.com",
    "znlnk.com", "ffm.to",  # ffm.to = feature.fm, used a lot for
                            # "link in bio" hub pages -> treat as aggregator
    "tr.ee",  # Linktree's own short-link domain
]

# App store / download links — not e-commerce in the fraud sense
APP_STORE_LINKS = [
    "apps.apple.com", "play.google.com", "itunes.apple.com",
]

MESSAGING_APPS = [
    "wa.me", "whatsapp.com", "api.whatsapp.com", "t.me", "telegram.me",
    "telegram.org", "m.me",  # Messenger short-link
    "line.me", "snapchat.com", "zalo.me", "viber.com", "kakao.com",
]

SOCIAL_MEDIA = [
    "instagram.com", "facebook.com", "fb.com", "youtube.com", "youtu.be",
    "twitter.com", "x.com", "pinterest.com", "reddit.com", "twitch.tv",
    "discord.gg", "discord.com",
]

# Common e-commerce PLATFORM domains (own store built on these) —
# distinct from a custom domain, which we infer heuristically below.
ECOMMERCE_PLATFORMS = [
    "shopify.com", "myshopify.com", "etsy.com", "amazon.com", "amzn.to",
    "ebay.com", "aliexpress.com", "temu.com", "shein.com", "wish.com",
    "bigcartel.com", "square.site", "gumroad.com",
]

# TikTok's own redirect wrapper host — needs unwrapping, not classifying directly
TIKTOK_REDIRECT_HOSTS = {"www.tiktok.com", "tiktok.com", "vm.tiktok.com"}

# Generic shortener domains — flag separately since they *hide* the real
# destination and are themselves a moderate risk signal
LINK_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly",
    "rebrand.ly", "shorturl.at", "buff.ly",
]


def _extract_domain(url: str) -> str:
    """Return the lowercase registrable-ish host for a URL, stripping www."""
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        host = urlparse(url).netloc.lower()
    except Exception:
        return ""
    host = host.split("@")[-1]          # strip any userinfo
    host = host.split(":")[0]           # strip port
    if host.startswith("www."):
        host = host[4:]
    return host


def _unwrap_tiktok_redirect(url: str) -> str:
    """
    If the link is a TikTok bio-link redirect wrapper
    (tiktok.com/link/v2?...&target=<encoded-destination>), extract and
    return the real destination URL. Otherwise return the url unchanged.
    """
    host = _extract_domain(url)
    if host not in TIKTOK_REDIRECT_HOSTS:
        return url

    try:
        query = parse_qs(urlparse(url).query)
    except Exception:
        return url

    target = query.get("target", [None])[0]
    if not target:
        return url

    target = unquote(target)
    # target sometimes omits the scheme (e.g. "luxuneryshop.com")
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    return target


def classify_bio_link(raw_url) -> dict:
    """
    Classify a single Bio Link value.

    Returns a dict:
        {
            "category": str,          # one of the categories below
            "resolved_domain": str,   # domain after unwrapping redirects
            "was_wrapped": bool,      # True if it went through tiktok.com/link/v2
            "is_shortener": bool,     # True if resolved domain is a known shortener
            "has_utm_tracking": bool  # True if utm_* params present
        }
    """
    if raw_url is None or (isinstance(raw_url, float)):  # NaN
        return {
            "category": "None",
            "resolved_domain": "",
            "was_wrapped": False,
            "is_shortener": False,
            "has_utm_tracking": False,
        }

    raw_url = str(raw_url).strip()
    if not raw_url:
        return {
            "category": "None",
            "resolved_domain": "",
            "was_wrapped": False,
            "is_shortener": False,
            "has_utm_tracking": False,
        }

    original_host = _extract_domain(raw_url)
    was_wrapped = original_host in TIKTOK_REDIRECT_HOSTS
    resolved_url = _unwrap_tiktok_redirect(raw_url)
    domain = _extract_domain(resolved_url)

    has_utm = bool(re.search(r"[?&]utm_[a-z]+=", resolved_url, re.IGNORECASE))
    is_shortener = any(domain == d or domain.endswith("." + d) for d in LINK_SHORTENERS)

    def _matches(domain: str, domain_list) -> bool:
        return any(domain == d or domain.endswith("." + d) for d in domain_list)

    if not domain:
        category = "None"
    elif _matches(domain, LINK_AGGREGATORS):
        category = "Link Aggregator"
    elif _matches(domain, MESSAGING_APPS):
        category = "Messaging App"
    elif _matches(domain, SOCIAL_MEDIA):
        category = "Social Media"
    elif _matches(domain, ECOMMERCE_PLATFORMS):
        category = "E-commerce (platform)"
    elif _matches(domain, APP_STORE_LINKS):
        category = "Other"
    elif is_shortener:
        category = "Link Shortener"
    else:
        # Anything else with its own custom domain (e.g. "luxuneryshop.com")
        # is treated as a self-hosted storefront — the most common pattern
        # for counterfeit-goods sellers in this dataset.
        category = "E-commerce (own domain)"

    return {
        "category": category,
        "resolved_domain": domain,
        "was_wrapped": was_wrapped,
        "is_shortener": is_shortener,
        "has_utm_tracking": has_utm,
    }


def classify_bio_links_series(series):
    """
    Vectorized helper for a pandas Series of raw Bio Link strings.
    Returns a DataFrame with columns: category, resolved_domain,
    was_wrapped, is_shortener, has_utm_tracking.
    """
    import pandas as pd
    return pd.DataFrame([classify_bio_link(v) for v in series])


if __name__ == "__main__":
    # Quick smoke test with examples pulled from the actual dataset
    examples = [
        "https://www.tiktok.com/link/v2?aid=1988&lang=en&scene=bio_url&target=Instagram.com%2Fmewsttv",
        "https://www.tiktok.com/link/v2?aid=1988&lang=en&scene=bio_url&target=wa.me%2F8613929543793",
        "https://www.tiktok.com/link/v2?aid=1988&lang=en&scene=bio_url&target=luxuneryshop.com",
        "www.wetracked.io?utm_source=tiktok&utm_medium=paid&utm_id=123",
        "https://linktr.ee/somecreator",
        None,
        "",
    ]
    for ex in examples:
        print(f"{str(ex)[:70]:70s} -> {classify_bio_link(ex)}")