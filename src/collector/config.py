"""
Global constants and configuration for the collector.
"""

import os
import re
from pathlib import Path

# ────────────────────────── Paths ──────────────────────────

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
SOURCES_FILE = PROJECT_ROOT / "sources.txt"
DEFAULT_OUTDIR = PROJECT_ROOT / "classified_output"

# ────────────────────────── Default Sources ──────────────────────────

DEFAULT_URLS: list[str] = [
    "https://raw.githubusercontent.com/hamedp-71/Sub_Checker_Creator/refs/heads/main/final.txt",
    "https://raw.githubusercontent.com/M-logique/Proxies/refs/heads/main/proxies/regular/socks5.txt",
]

# ────────────────────────── Regex Patterns ──────────────────────────

URI_RE = re.compile(
    r"\b(?:vmess|vless|trojan|ss|socks5|socks|hysteria2|hysteria)://[^\s'\"]+",
    re.IGNORECASE,
)

FLAG_RE = re.compile(r"([\U0001F1E6-\U0001F1FF]{2})")

# ────────────────────────── Ciphers ──────────────────────────

SECURE_SS_CIPHERS: set[str] = {
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
    "aes-128-gcm",
    "aes-256-gcm",
    "aead_chacha20_ietf_poly1305",
}

WEAK_SS_CIPHERS: set[str] = {
    "rc4-md5",
    "aes-128-cfb",
    "aes-192-cfb",
}

# ────────────────────────── Scheme Normalization ──────────────────────────

SCHEME_MAP: dict[str, str] = {
    "socks5": "socks",
}

# ────────────────────────── Supported Protocols ──────────────────────────

PROTOCOLS: list[str] = [
    "vmess",
    "vless",
    "trojan",
    "ss",
    "socks",
    "hysteria",
    "hysteria2",
    "other",
]

# ────────────────────────── Concurrency ──────────────────────────

MAX_DOWNLOAD_WORKERS = int(os.environ.get("COLLECTOR_DL_WORKERS", "8"))
MAX_LIVECHECK_WORKERS = int(os.environ.get("COLLECTOR_LC_WORKERS", "32"))

# ────────────────────────── Defaults ──────────────────────────

DEFAULT_TAG = "3λΞĐ"
DEFAULT_FETCH_TIMEOUT = 30
DEFAULT_FETCH_RETRIES = 3
DEFAULT_LIVE_TIMEOUT = 3.0

# ────────────────────────── Lite Mode ──────────────────────────

LITE_MAX = int(os.environ.get("COLLECTOR_LITE_MAX", "50"))


def load_sources() -> list[str]:
    """Load source URLs from sources.txt, falling back to DEFAULT_URLS."""
    if SOURCES_FILE.exists():
        lines = SOURCES_FILE.read_text(encoding="utf-8").splitlines()
        urls = [
            line.strip()
            for line in lines
            if line.strip() and not line.strip().startswith("#")
        ]
        if urls:
            return urls
    return list(DEFAULT_URLS)
