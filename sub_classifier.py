#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import logging
import os
import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qs, quote, unquote, urlsplit

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util import Retry
except Exception:
    requests = None

# ---------------- Config ----------------

DEFAULT_URLS = [
    "https://raw.githubusercontent.com/hamedp-71/Sub_Checker_Creator/refs/heads/main/final.txt",
    "https://raw.githubusercontent.com/M-logique/Proxies/refs/heads/main/proxies/regular/socks5.txt",
]

URI_RE = re.compile(
    r"\b(?:vmess|vless|trojan|ss|socks5|socks|hysteria2|hysteria)://[^\s'\"\)\]]+",
    re.IGNORECASE,
)

FLAG_RE = re.compile(r"([\U0001F1E6-\U0001F1FF]{2})")

SECURE_SS_CIPHERS = {
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
    "aes-128-gcm",
    "aes-256-gcm",
}

WEAK_SS = {"rc4-md5", "aes-128-cfb", "aes-192-cfb"}

# ---------------- Logging ----------------

logger = logging.getLogger("sub-classifier")
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# ---------------- Base64 subscription detection ----------------


def try_decode_subscription_base64(text: str, force: bool = False) -> str:
    sample = text.strip()

    looks_base64 = (
        len(sample) > 100
        and "\n" not in sample[:200]
        and all(
            c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n\r"
            for c in sample[:500]
        )
    )

    if not (force or looks_base64):
        return text

    try:
        padded = sample + "=" * (-len(sample) % 4)
        decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")

        if any(p in decoded for p in ("vmess://", "vless://", "trojan://", "ss://")):
            logger.info("[+] Base64 subscription detected and decoded")
            return decoded
    except Exception:
        pass

    return text


# ---------------- JSON extraction ----------------


def extract_json_segments(text: str) -> List[str]:
    results = []
    stack = []
    start = None
    in_str = False
    esc = False

    for i, ch in enumerate(text):
        if in_str:
            if esc:
                esc = False
                continue
            if ch == "\\":
                esc = True
                continue
            if ch == '"':
                in_str = False
            continue

        if ch == '"':
            in_str = True
            continue

        if ch in "{[":
            if not stack:
                start = i
            stack.append(ch)

        elif ch in "}]":
            if stack:
                stack.pop()
                if not stack and start is not None:
                    results.append(text[start : i + 1])
                    start = None

    return results


# ---------------- URI helpers ----------------


def normalize_fragment(fragment: str, tag: str) -> str:
    if not fragment:
        return tag

    frag = fragment.strip()
    if tag in frag:
        return frag

    for d in ("::", "-", "_"):
        if d in frag:
            suffix = frag.split(d, 1)[1].strip()
            return f"{tag}::{suffix}"

    m = FLAG_RE.search(frag)
    if m:
        return f"{tag}::{m.group(1)}"

    return tag


def normalize_tag_in_uri(uri: str, tag: str) -> str:
    if "#" not in uri:
        return f"{uri}#{quote(tag, safe='')}"

    main, frag = uri.split("#", 1)
    decoded = unquote(frag)
    new_frag = normalize_fragment(decoded, tag)
    return f"{main}#{quote(new_frag, safe='')}"


def decode_vmess(uri: str) -> Optional[dict]:
    try:
        payload = uri.split("://", 1)[1].split("#")[0]
        padded = payload + "=" * (-len(payload) % 4)
        raw = base64.urlsafe_b64decode(padded)
        return json.loads(raw.decode("utf-8", errors="ignore"))
    except Exception:
        return None


def encode_vmess(j: dict) -> str:
    raw = json.dumps(j, ensure_ascii=False, separators=(",", ":"))
    encoded = base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")
    return f"vmess://{encoded}"


# ---------------- Security checks ----------------


def is_shadowsocks_secure(uri: str) -> Tuple[bool, List[str]]:
    try:
        blob = uri.split("://", 1)[1].split("#")[0].split("?")[0]
        if "@" in blob:
            method = blob.split(":", 1)[0].lower()
            if method in WEAK_SS:
                return False, [f"weak:{method}"]
            if method in SECURE_SS_CIPHERS:
                return True, [f"secure:{method}"]
    except Exception:
        pass
    return False, ["unknown"]


def is_vless_secure(uri: str) -> Tuple[bool, List[str]]:
    q = parse_qs(urlsplit(uri).query)
    if q.get("insecure", ["0"])[0] == "1":
        return False, ["insecure=1"]

    reasons = []
    if "security" in q and "tls" in q["security"][0].lower():
        reasons.append("tls")
    if "sni" in q:
        reasons.append("sni")

    return (True, reasons) if reasons else (False, ["no-tls"])


def is_trojan_secure(uri: str) -> Tuple[bool, List[str]]:
    q = parse_qs(urlsplit(uri).query)
    if q.get("insecure", ["0"])[0] == "1":
        return False, ["insecure=1"]
    return True, ["tls"]


# ---------------- Live TLS check ----------------


def live_check(host: str, port: int, timeout=5) -> Tuple[bool, str]:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True, "ok"
    except Exception as e:
        return False, str(e)


# ---------------- Networking ----------------


def build_session():
    if not requests:
        return None

    session = requests.Session()
    retry = Retry(total=2, backoff_factor=0.5)
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def fetch_all(urls: List[str], concurrency: int) -> Dict[str, Optional[str]]:
    session = build_session()

    def fetch(u):
        try:
            if session:
                r = session.get(u, timeout=20)
                r.raise_for_status()
                return u, r.text
            else:
                import urllib.request

                with urllib.request.urlopen(u, timeout=20) as r:
                    return u, r.read().decode("utf-8", errors="ignore")
        except Exception as e:
            logger.warning("Fetch failed %s: %s", u, e)
            return u, None

    results = {}
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futures = [ex.submit(fetch, u) for u in urls]
        for f in as_completed(futures):
            u, txt = f.result()
            results[u] = txt

    return results


# ---------------- Main processing ----------------


def find_uris(text: str) -> List[str]:
    return URI_RE.findall(text)


def atomic_write(path: Path, lines: Iterable[str]):
    tmp = path.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")
    tmp.replace(path)


# ---------------- Main ----------------


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--outdir", default="./classified_output")
    p.add_argument("--tag", default="3λΞĐ")
    p.add_argument("--decode-vmess", action="store_true")
    p.add_argument("--live-check", action="store_true")
    p.add_argument("--concurrency", type=int, default=4)
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    outdir = Path(args.outdir)
    outdir.mkdir(exist_ok=True)

    urls = DEFAULT_URLS
    fetched = fetch_all(urls, args.concurrency)

    classified = {"vmess": [], "vless": [], "trojan": [], "ss": []}

    for txt in fetched.values():
        if not txt:
            continue

        txt = try_decode_subscription_base64(txt, args.decode_vmess)
        uris = find_uris(txt)

        if not uris:
            logger.warning("No URIs found in source")

        for uri in uris:
            scheme = uri.split("://")[0].lower()

            if scheme == "vmess":
                j = decode_vmess(uri)
                if j:
                    uri = encode_vmess(j)
                classified["vmess"].append(uri)

            elif scheme == "vless":
                classified["vless"].append(normalize_tag_in_uri(uri, args.tag))

            elif scheme == "trojan":
                classified["trojan"].append(uri)

            elif scheme == "ss":
                classified["ss"].append(uri)

    for k, v in classified.items():
        atomic_write(outdir / f"{k}.txt", sorted(set(v)))

    logger.info("Done.")


if __name__ == "__main__":
    main()
