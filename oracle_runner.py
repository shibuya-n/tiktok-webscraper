# ─── oracle_runner.py ─────────────────────────────────────────────────────────
# Glue between the TikTok scraper and the domain-level "oracle" fraud model.
#
# extract_images.py and feature_prep.py are batch SCRIPTS (module-level code,
# env-var config, CSVs in/out), not importable libraries. So this module runs
# them as subprocesses in a throwaway work dir, then does the final predict
# step itself (same logic as predict_oracle_model.py, minus the confusion
# matrix / classification report, which need ground-truth labels).
#
# Usage from scraper.py:
#     runner = OracleRunner()
#     results = runner.score({"example.com", "shop-deals.xyz"})
#     results["example.com"]  ->  {"prob": 0.93, "is_fraud": True}  or  None
# ──────────────────────────────────────────────────────────────────────────────

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import joblib
import pandas as pd
import tldextract

# Folder containing extract_images.py, feature_prep.py, oracle_pipeline.pkl
ORACLE_CODE_DIR = Path(os.environ.get("ORACLE_CODE_DIR", Path(__file__).parent / "oracle")).resolve()
MODEL_PATH = Path(os.environ.get("ORACLE_MODEL_PATH", ORACLE_CODE_DIR / "oracle_pipeline.pkl"))
CACHE_FILE = Path(os.environ.get("ORACLE_CACHE", "./oracle_cache.json"))

CACHE_TTL_S = 14 * 24 * 3600     # re-score a domain after two weeks
THRESHOLD = 0.85                 # same cutoff as predict_oracle_model.py
CRAWL_TIMEOUT_S = 900
FEATURE_TIMEOUT_S = 900

# Domains the oracle should never be pointed at (social platforms etc.).
SKIP_DOMAINS = {
    "youtube", "youtu", "tiktok", "facebook", "instagram",
    "pinterest", "twitter", "x", "linkedin",
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


class OracleRunner:
    def __init__(self):
        self._bundle = None  # lazy-loaded (pipeline, feature_cols)

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
                fresh = self._run_pipeline(todo)
            except Exception as e:  # never let the oracle break a scan
                print(f"  [ORACLE ERROR] {e}")
                fresh = {}
            for d in todo:
                results[d] = fresh.get(d)           # None = no score
                if results[d] is not None:          # only cache real scores
                    cache[d] = {"ts": now, "result": results[d]}
            self._save_cache(cache)

        return results

    # ── pipeline ──────────────────────────────────────────────────────────────
    def _run_pipeline(self, domains: list[str]) -> dict:
        work = Path(tempfile.mkdtemp(prefix="oracle_"))
        try:
            (work / "urls.txt").write_text("\n".join(domains), encoding="utf-8")
            pd.DataFrame({"domain": domains}).to_csv(work / "domains.csv", index=False)

            env = {
                **os.environ,
                # extract_images.py writes html/, html_data.csv, whois/dns/ssl csvs here
                "OUTPUT_DIR": str(work),
                "MAX_CRAWL_WORKERS": os.environ.get("MAX_CRAWL_WORKERS", "3"),
                # feature_prep.py reads those same files and writes raw_features_live.csv
                "ORACLE_FEATURE_BASE_DIR": str(work),
                "ORACLE_DOMAINS_CSV": str(work / "domains.csv"),
                "ORACLE_SCAM_URL": "live",
            }

            # 1) crawl: HTML + WHOIS + DNS + SSL
            self._run_script("extract_images.py", [str(work / "urls.txt")], env, CRAWL_TIMEOUT_S)
            # 2) features
            self._run_script("feature_prep.py", [], env, FEATURE_TIMEOUT_S)
            # 3) predict (last)
            return self._predict(work / "raw_features_live.csv")
        finally:
            if not os.environ.get("ORACLE_KEEP_WORKDIR"):
                shutil.rmtree(work, ignore_errors=True)

    @staticmethod
    def _run_script(script: str, args: list[str], env: dict, timeout: int) -> None:
        proc = subprocess.run(
            [sys.executable, str(ORACLE_CODE_DIR / script), *args],
            env=env,
            cwd=str(ORACLE_CODE_DIR),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"{script} exited {proc.returncode}:\n{proc.stderr[-2000:]}")

    def _predict(self, features_csv: Path) -> dict:
        if not features_csv.exists():
            # feature_prep drops domains whose HTML couldn't be fetched
            print("  [ORACLE] No feature file produced (all domains unreachable?).")
            return {}

        if self._bundle is None:
            bundle = joblib.load(MODEL_PATH)
            self._bundle = (bundle["pipeline"], bundle["feature_cols"])
        pipeline, feature_cols = self._bundle

        df = pd.read_csv(features_csv)
        for c in feature_cols:
            if c not in df.columns:
                df[c] = 0
        proba = pipeline.predict_proba(df[feature_cols])[:, 1]

        return {
            str(d): {"prob": float(p), "is_fraud": bool(p >= THRESHOLD)}
            for d, p in zip(df["domain"], proba)
        }

    # ── cache ─────────────────────────────────────────────────────────────────
    @staticmethod
    def _load_cache() -> dict:
        try:
            return json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        except Exception:
            return {}

    @staticmethod
    def _save_cache(cache: dict) -> None:
        try:
            CACHE_FILE.write_text(json.dumps(cache, indent=2), encoding="utf-8")
        except Exception as e:
            print(f"  [ORACLE] Could not write cache: {e}")
