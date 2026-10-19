#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ZoomEye v2 API scraper (zoomeye.ai).
POST https://api.zoomeye.ai/v2/search   header: API-KEY
body: {"qbase64": base64(query), "page": n, "pagesize": m, "sub_type": "v4"}
"""

import os
import time
import base64
import requests
from typing import List, Dict, Any

API_BASE = os.getenv("ZOOMEYE_API_BASE", "https://api.zoomeye.ai").rstrip("/")
API_KEY = os.getenv("ZOOMEYE_API_KEY", "")
PAGESIZE = int(os.getenv("ZOOMEYE_PAGESIZE", "100"))

MAX_RETRIES = 4
BACKOFF = 3.0


def _b64(q: str) -> str:
    return base64.b64encode(q.encode("utf-8")).decode("ascii")


def search_page(query: str, page: int = 1, pagesize: int = PAGESIZE,
                sub_type: str = "v4", session: requests.Session = None) -> Dict[str, Any]:
    """One page of /v2/search. Raises on hard failure."""
    if not API_KEY:
        raise RuntimeError("ZOOMEYE_API_KEY is not set (free plan has no API access)")

    sess = session or requests
    payload = {
        "qbase64": _b64(query),
        "page": page,
        "pagesize": pagesize,
        "sub_type": sub_type,                       # v4 = IPv4 only
        "fields": "ip,port,url,service",
    }
    headers = {"API-KEY": API_KEY, "content-type": "application/json"}

    last_err = None
    for attempt in range(MAX_RETRIES):
        try:
            r = sess.post(f"{API_BASE}/v2/search", headers=headers,
                          json=payload, timeout=30)
            if r.status_code == 429:                 # rate limited
                time.sleep(BACKOFF * (attempt + 1))
                continue
            if r.status_code == 401:
                raise RuntimeError("ZoomEye 401 Unauthorized - bad API key")
            r.raise_for_status()
            return r.json()
        except requests.RequestException as e:
            last_err = e
            time.sleep(BACKOFF * (attempt + 1))
    if last_err:
        raise last_err
    return {}


def collect_ips(query: str, max_pages: int = 3, pagesize: int = PAGESIZE,
                sub_type: str = "v4") -> List[str]:
    """Walk pages, return de-duplicated plain IP strings."""
    found: List[str] = []
    seen = set()
    sess = requests.Session()

    for page in range(1, max_pages + 1):
        data = search_page(query, page=page, pagesize=pagesize,
                           sub_type=sub_type, session=sess)
        rows = data.get("data") or []
        if not rows:
            break
        for row in rows:
            ip = (row.get("ip") or "").strip()
            if not ip or ip in seen:
                continue
            seen.add(ip)
            found.append(ip)
        if len(rows) < pagesize:
            break
        time.sleep(0.6)                              # be gentle with rate limits

    return found
