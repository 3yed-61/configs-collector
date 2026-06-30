"""
Networking utilities — HTTP fetching and live TLS checking.
"""

from __future__ import annotations

import logging
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple

from .config import (
    DEFAULT_FETCH_RETRIES,
    DEFAULT_FETCH_TIMEOUT,
    DEFAULT_LIVE_TIMEOUT,
    MAX_DOWNLOAD_WORKERS,
    MAX_LIVECHECK_WORKERS,
)

import urllib.request

try:
    import requests as _requests
except ImportError:
    _requests = None

log = logging.getLogger(__name__)

# ────────────────────────── HTTP Fetch ──────────────────────────

_USER_AGENT = "configs-collector/2.0"


def fetch_url(
    url: str,
    timeout: int = DEFAULT_FETCH_TIMEOUT,
    retries: int = DEFAULT_FETCH_RETRIES,
) -> str:
    """Download text content from a URL with retries."""
    log.info("Downloading: %s", url)
    headers = {"User-Agent": _USER_AGENT}

    for attempt in range(retries):
        try:
            if _requests:
                with _requests.Session() as session:
                    resp = session.get(url, timeout=timeout, headers=headers)
                    resp.raise_for_status()
                    return resp.text
            else:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    return resp.read().decode("utf-8", errors="ignore")
        except Exception as exc:
            if attempt == retries - 1:
                raise RuntimeError(f"Fetch failed: {url} → {exc}") from exc
            wait = 1.5 ** attempt
            log.warning("Retry %d/%d for %s (wait %.1fs)", attempt + 1, retries, url, wait)
            time.sleep(wait)

    return ""  # unreachable


def fetch_all(urls: List[str], timeout: int = DEFAULT_FETCH_TIMEOUT) -> Dict[str, str]:
    """
    Download multiple URLs in parallel using a thread pool.

    Returns a dict mapping URL → text content (empty string on failure).
    """
    results: Dict[str, str] = {}

    def _download(url: str) -> Tuple[str, str]:
        try:
            return url, fetch_url(url, timeout=timeout)
        except Exception as exc:
            log.error("Failed to fetch %s: %s", url, exc)
            return url, ""

    workers = min(MAX_DOWNLOAD_WORKERS, len(urls)) or 1
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_download, u): u for u in urls}
        for future in as_completed(futures):
            url, text = future.result()
            results[url] = text

    return results


# ────────────────────────── Live TLS Check ──────────────────────────

_live_cache: Dict[Tuple[str, int, str], Tuple[bool, str]] = {}


def live_check(
    host: str,
    port: int,
    sni: str | None = None,
    timeout: float = DEFAULT_LIVE_TIMEOUT,
) -> Tuple[bool, str]:
    """Perform a TLS handshake to verify a host is reachable."""
    key = (host, port, sni or "")
    if key in _live_cache:
        return _live_cache[key]

    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            with ctx.wrap_socket(sock, server_hostname=sni or host):
                result = (True, "tls-handshake-ok")
    except socket.timeout:
        result = (False, "timeout")
    except Exception as exc:
        result = (False, f"{type(exc).__name__}:{exc}")

    _live_cache[key] = result
    return result


def live_check_batch(
    targets: List[Tuple[str, int, str | None]],
) -> Dict[Tuple[str, int], Tuple[bool, str]]:
    """
    Check multiple host:port targets in parallel.

    Args:
        targets: list of (host, port, sni) tuples.

    Returns:
        dict mapping (host, port) → (ok, message).
    """
    results: Dict[Tuple[str, int], Tuple[bool, str]] = {}

    def _check(t: Tuple[str, int, str | None]) -> Tuple[Tuple[str, int], Tuple[bool, str]]:
        host, port, sni = t
        ok, msg = live_check(host, port, sni)
        return (host, port), (ok, msg)

    workers = min(MAX_LIVECHECK_WORKERS, len(targets)) or 1
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_check, t) for t in targets]
        for future in as_completed(futures):
            key, val = future.result()
            results[key] = val

    return results
