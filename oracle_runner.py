# ─── oracle_runner.py ─────────────────────────────────────────────────────────
# Glue between the TikTok scraper and the domain-level "oracle" fraud model.
#
# This version uses a fast heuristic-based scorer for real-time use,
# with optional caching. The full ML pipeline (extract_images.py + feature_prep.py)
# is too slow for per-video scoring and requires sklearn 1.2.1 (incompatible
# with current version). This module provides a lightweight alternative.
#
# Usage from scraper.py:
#     runner = OracleRunner()
#     results = runner.score({"example.com", "shop-deals.xyz"})
#     results["example.com"]  ->  {"prob": 0.93, "is_fraud": True}  or  None
# ──────────────────────────────────────────────────────────────────────────────

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

import tldextract

# ── Configuration ──────────────────────────────────────────────────────────────
CACHE_FILE = Path(os.environ.get("ORACLE_CACHE", "./oracle_cache.json"))
CACHE_TTL_S = 14 * 24 * 3600     # re-score a domain after two weeks
THRESHOLD = 0.85                 # fraud threshold

# Domains the oracle should never be pointed at (social platforms etc.).
SKIP_DOMAINS = {
    "youtube", "youtu", "tiktok", "facebook", "instagram",
    "pinterest", "twitter", "x", "linkedin",
}

# Cheap TLDs often used by scammers (from feature_prep.py)
CHEAP_TLDS = {
    '.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc', '.club',
    '.online', '.site', '.website', '.space', '.tech', '.store', '.fun',
    '.buzz', '.live', '.click', '.bid', '.loan', '.racing', '.win', '.work',
    '.party', '.date', '.trade', '.review', '.science', '.stream', '.download',
}

# Known legitimate platforms (low risk)
LEGIT_PLATFORMS = {
    'shopify.com', 'myshopify.com', 'etsy.com', 'amazon.com', 'amzn.to',
    'ebay.com', 'aliexpress.com', 'temu.com', 'shein.com', 'wish.com',
    'bigcartel.com', 'square.site', 'gumroad.com',
    'linktr.ee', 'linktree.com', 'bio.link', 'beacons.ai', 'beacons.page',
    'campsite.bio', 'lnk.bio', 'carrd.co', 'linkin.bio', 'milkshake.app',
    'solo.to', 'taplink.cc', 'shorby.com', 'koji.to', 'linkpop.com',
    'znlnk.com', 'ffm.to', 'tr.ee',
    'instagram.com', 'facebook.com', 'fb.com', 'youtube.com', 'youtu.be',
    'twitter.com', 'x.com', 'pinterest.com', 'reddit.com', 'twitch.tv',
    'discord.gg', 'discord.com',
    'wa.me', 'whatsapp.com', 'api.whatsapp.com', 't.me', 'telegram.me',
    'telegram.org', 'm.me', 'line.me', 'snapchat.com', 'zalo.me', 'viber.com', 'kakao.com',
}

# URL shorteners (moderate risk - hide destination)
URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'cutt.ly',
    'rebrand.ly', 'shorturl.at', 'buff.ly',
}

# Suspicious keywords in domain
SUSPICIOUS_KEYWORDS = {
    'shop', 'store', 'buy', 'sale', 'discount', 'deal', 'offer', 'cheap',
    'free', 'win', 'prize', 'gift', 'reward', 'bonus', 'cash', 'money',
    'invest', 'profit', 'earn', 'income', 'rich', 'wealth', 'luxury',
    'brand', 'original', 'authentic', 'genuine', 'official', 'verified',
    'limited', 'exclusive', 'vip', 'premium', 'pro', 'max', 'ultra',
    'crypto', 'bitcoin', 'btc', 'eth', 'nft', 'token', 'coin', 'wallet',
    'forex', 'trading', 'signal', 'binary', 'option', 'investment',
}


def oracle_domain(video_data: dict) -> str:
    """Registered domain (example.com, not www.example.com) to score, or ''.

    The ranking tables in feature_prep.py (Cisco/Majestic/Tranco) are keyed by
    registered domain, so hostnames with subdomains would silently miss them.
    """
    link = (video_data.get("bio_link") or "").strip()
    if not link:
        return ""
    if video_data.get("bio_link_shortener"):
        return ""  # scoring bit.ly tells you nothing; resolve the redirect first
    if "://" not in link:
        link = "http://" + link
    ext = tldextract.extract(link)
    if not ext.domain or not ext.suffix:
        return ""
    if ext.domain.lower() in SKIP_DOMAINS:
        return ""
    return f"{ext.domain}.{ext.suffix}".lower()


def _heuristic_score(domain: str) -> tuple[float, dict]:
    """
    Fast heuristic scoring for a domain.
    Returns (probability, details_dict).
    """
    ext = tldextract.extract(domain)
    domain_name = ext.domain.lower()
    tld = ext.suffix.lower()
    full_domain = f"{domain_name}.{tld}".lower()

    score = 0.0
    details = {
        "domain": full_domain,
        "tld": tld,
        "domain_name": domain_name,
        "factors": [],
    }

    # 1. Cheap TLD (strong signal)
    if f".{tld}" in CHEAP_TLDS:
        score += 0.35
        details["factors"].append(f"cheap_tld:{tld}")

    # 2. Known legitimate platform (negative signal)
    if full_domain in LEGIT_PLATFORMS:
        score -= 0.5
        details["factors"].append("legit_platform")

    # 3. URL shortener (moderate positive signal)
    if full_domain in URL_SHORTENERS:
        score += 0.25
        details["factors"].append("url_shortener")

    # 4. Suspicious keywords in domain name
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in domain_name:
            score += 0.1
            details["factors"].append(f"keyword:{kw}")
            break  # only count once

    # 5. Domain length (very long = suspicious)
    if len(domain_name) > 20:
        score += 0.15
        details["factors"].append("long_domain")
    elif len(domain_name) > 15:
        score += 0.08
        details["factors"].append("medium_domain")

    # 6. Hyphens in domain (often used for typosquatting)
    if domain_name.count('-') >= 2:
        score += 0.15
        details["factors"].append("multi_hyphen")
    elif domain_name.count('-') == 1:
        score += 0.05
        details["factors"].append("single_hyphen")

    # 7. Digits in domain (can indicate generated domains)
    digit_count = sum(c.isdigit() for c in domain_name)
    if digit_count >= 3:
        score += 0.1
        details["factors"].append("many_digits")
    elif digit_count > 0:
        score += 0.03
        details["factors"].append("has_digits")

    # 8. Subdomain count (many subdomains = suspicious)
    subdomain_count = ext.subdomain.count('.') + (1 if ext.subdomain else 0)
    if subdomain_count >= 3:
        score += 0.1
        details["factors"].append("many_subdomains")
    elif subdomain_count > 0:
        score += 0.03
        details["factors"].append("has_subdomains")

    # 9. Common brand names being spoofed (very suspicious)
    brand_keywords = ['nike', 'adidas', 'gucci', 'louis', 'vuitton', 'rolex', 'omega',
                      'chanel', 'hermes', 'prada', 'dior', 'versace', 'balenciaga',
                      'rayban', 'oakley', 'michael', 'kors', 'coach', 'kate', 'spade',
                      'tiffany', 'cartier', 'pandora', 'swarovski']
    for brand in brand_keywords:
        if brand in domain_name and brand != domain_name:
            score += 0.3
            details["factors"].append(f"brand_spoof:{brand}")
            break

    # Clamp to [0, 1]
    prob = max(0.0, min(1.0, score))

    return prob, details


class OracleRunner:
    def __init__(self):
        self._cache = None

    # ── public ────────────────────────────────────────────────────────────────
    def score(self, domains) -> dict:
        """domain -> {"prob", "is_fraud"} or None (unreachable / failed)."""
        domains = sorted({d for d in domains if d})
        if not domains:
            return {}

        cache = self._load_cache()
        now = time.time()
        results, todo = {}, []
        for d in domains:
            hit = cache.get(d)
            if hit and now - hit["ts"] < CACHE_TTL_S:
                results[d] = hit["result"]
            else:
                todo.append(d)

        if todo:
            print(f"  [ORACLE] Scoring {len(todo)} new domain(s): {', '.join(todo)}")
            try:
                fresh = self._score_heuristic(todo)
            except Exception as e:  # never let the oracle break a scan
                print(f"  [ORACLE ERROR] {e}")
                fresh = {}
            for d in todo:
                results[d] = fresh.get(d)           # None = no score
                if results[d] is not None:          # only cache real scores
                    cache[d] = {"ts": now, "result": results[d]}
            self._save_cache(cache)

        return results

    # ── heuristic scoring ─────────────────────────────────────────────────────
    def _score_heuristic(self, domains: list[str]) -> dict:
        """Fast heuristic scoring without external dependencies."""
        results = {}
        for domain in domains:
            try:
                prob, details = _heuristic_score(domain)
                is_fraud = prob >= THRESHOLD
                results[domain] = {"prob": prob, "is_fraud": is_fraud}
                verdict = "FRAUD" if is_fraud else "benign"
                factors = ", ".join(details["factors"]) if details["factors"] else "none"
                print(f"  [ORACLE] {domain}: p={prob:.3f} -> {verdict} ({factors})")
            except Exception as e:
                print(f"  [ORACLE ERROR] {domain}: {e}")
                results[domain] = None
        return results

    # ── cache ─────────────────────────────────────────────────────────────────
    def _load_cache(self) -> dict:
        try:
            return json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _save_cache(self, cache: dict) -> None:
        try:
            CACHE_FILE.write_text(json.dumps(cache, indent=2), encoding="utf-8")
        except Exception as e:
            print(f"  [ORACLE] Could not write cache: {e}")


if __name__ == "__main__":
    # Quick test
    runner = OracleRunner()
    test_domains = {
        "example.com",
        "shop-deals.xyz",
        "nike-sale.top",
        "linktr.ee",
        "bit.ly",
        "luxury-watches.shop",
    }
    results = runner.score(test_domains)
    for d, r in results.items():
        if r:
            print(f"{d}: prob={r['prob']:.3f}, fraud={r['is_fraud']}")
        else:
            print(f"{d}: no score")