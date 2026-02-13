#!/usr/bin/env python3
# ---------- BEGIN FINAL SCRIPT ----------

import os
import re
import argparse
import json
import base64
import socket
import ssl
import time
import logging
from dataclasses import dataclass
from urllib.parse import unquote, quote, urlsplit, parse_qs
from typing import List, Iterable, Tuple, Dict

try:
    import requests
except Exception:
    requests = None
    import urllib.request

# ---------------- Logging ----------------

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s"
)
log = logging.getLogger(__name__)

# ---------------- Constants ----------------

DEFAULT_URLS = [
    "https://raw.githubusercontent.com/hamedp-71/Sub_Checker_Creator/refs/heads/main/final.txt",
    "https://raw.githubusercontent.com/M-logique/Proxies/refs/heads/main/proxies/regular/socks5.txt"
]

URI_RE = re.compile(
    r"\b(?:vmess|vless|trojan|ss|socks5|socks|hysteria2|hysteria)://[^\s'\"]+",
    re.IGNORECASE
)

FLAG_RE = re.compile(r'([\U0001F1E6-\U0001F1FF]{2})')

SECURE_SS_CIPHERS = {
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
    "aes-128-gcm",
    "aes-256-gcm",
    "aead_chacha20_ietf_poly1305",
}

WEAK_SS = {"rc4-md5", "aes-128-cfb", "aes-192-cfb"}

# Normalize equivalent schemes
SCHEME_MAP = {
    "socks5": "socks",
}

# Live check cache
_live_cache: Dict[Tuple[str, int, str], Tuple[bool, str]] = {}

# ---------------- Data Model ----------------

@dataclass
class ConfigEntry:
    protocol: str
    uri: str
    secure: bool
    reasons: List[str]
    original: str

# ---------------- Networking ----------------

def fetch_url(url: str, timeout: int = 30, retries: int = 3) -> str:
    log.info(f"Downloading: {url}")
    headers = {"User-Agent": "config-classifier/1.0"}

    for attempt in range(retries):
        try:
            if requests:
                with requests.Session() as s:
                    r = s.get(url, timeout=timeout, headers=headers)
                    r.raise_for_status()
                    return r.text
            else:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    return r.read().decode("utf-8", errors="ignore")

        except Exception as e:
            if attempt == retries - 1:
                raise RuntimeError(f"Fetch failed: {url} → {e}") from e
            time.sleep(1.5 ** attempt)

# ---------------- Live TLS Check ----------------

def live_check(host: str, port: int, sni: str = None,
               timeout: float = 3.0) -> Tuple[bool, str]:
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
    except Exception as e:
        result = (False, f"{type(e).__name__}:{e}")

    _live_cache[key] = result
    return result

# ---------------- JSON Extraction ----------------

def find_json_configs(text: str) -> List[dict]:
    results = []
    decoder = json.JSONDecoder()
    idx = 0
    length = len(text)

    while idx < length:
        if text[idx] == "{":
            try:
                obj, end = decoder.raw_decode(text[idx:])
                if isinstance(obj, dict):
                    results.append(obj)
                idx += end
                continue
            except Exception:
                pass
        idx += 1

    return results

# ---------------- URI Helpers ----------------

def find_uris(text: str) -> List[str]:
    return [u.strip() for u in URI_RE.findall(text)]

def classify_uri_scheme(uri: str) -> str:
    return uri.split("://", 1)[0].lower()

def parse_query(uri: str) -> dict:
    return {k: v for k, v in parse_qs(urlsplit(uri).query).items()}

# ---------------- Tag Normalization (UNCHANGED) ----------------

def normalize_fragment(fragment: str, new_tag: str) -> str:
    if not fragment:
        return new_tag

    frag = fragment.strip()
    if new_tag in frag:
        return frag

    delimiters = ["::", "-", "_"]
    suffix = None

    for d in delimiters:
        if d in frag:
            suffix = frag.split(d, 1)[1].strip()
            break

    if suffix is None:
        m = FLAG_RE.search(frag)
        if m:
            suffix = m.group(1)

    if suffix:
        if new_tag in suffix:
            return suffix
        return f"{new_tag}::{suffix}"

    return new_tag

def normalize_tag_in_uri(uri: str, new_tag: str) -> str:
    if "#" not in uri:
        return f"{uri}#{quote(new_tag, safe='')}"

    main, frag = uri.split("#", 1)
    decoded = unquote(frag)
    new_frag = normalize_fragment(decoded, new_tag)
    return f"{main}#{quote(new_frag, safe='')}"

def normalize_tag_in_json_obj(j: dict, new_tag: str) -> dict:
    obj = dict(j)

    for key in ("ps", "remarks", "name"):
        if key in obj and isinstance(obj[key], str):
            decoded = unquote(obj[key])
            obj[key] = normalize_fragment(decoded, new_tag)

    return obj

# ---------------- VMess ----------------

def decode_vmess_base64(uri: str):
    try:
        payload = uri.split("://", 1)[1].split("#", 1)[0]
        payload = payload.replace("-", "+").replace("_", "/")
        padded = payload + "=" * (-len(payload) % 4)

        raw = base64.b64decode(padded, validate=False)
        return json.loads(raw.decode("utf-8", errors="strict"))

    except Exception as e:
        log.debug(f"VMess decode failed: {e}")
        return None

def encode_vmess_json_to_uri(j: dict) -> str:
    raw = json.dumps(j, ensure_ascii=False, separators=(",", ":"))
    encoded = base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")
    return f"vmess://{encoded}"

# ---------------- Security Checks ----------------

def is_shadowsocks_secure(uri: str):
    try:
        blob = uri.split("://", 1)[1].split("#")[0].split("?")[0]

        if "@" in blob and ":" in blob:
            method = blob.split("@", 1)[0].split(":", 1)[0].lower()

            if method in WEAK_SS:
                return False, [f"weak-cipher:{method}"]
            if method in SECURE_SS_CIPHERS:
                return True, [f"secure-cipher:{method}"]

            return False, [f"cipher:{method}"]

    except Exception as e:
        log.debug(f"SS parse error: {e}")

    return False, ["unknown-ss-method"]

def is_vless_secure(uri: str):
    q = parse_query(uri)
    reasons = []

    if q.get("insecure", ["0"])[0] == "1":
        return False, ["insecure=1"]

    if "tls" in uri.lower() or "reality" in uri.lower():
        reasons.append("tls-or-reality")

    return (bool(reasons), reasons or ["no-tls-or-reality"])

def is_trojan_secure(uri: str):
    if parse_query(uri).get("insecure", ["0"])[0] == "1":
        return False, ["insecure=1"]

    return True, ["tls-based"]

def is_vmess_secure_from_json(j: dict):
    if j.get("allowInsecure"):
        return False, ["allowInsecure"]

    reasons = []
    if j.get("tls"):
        reasons.append("tls")
    if j.get("sni"):
        reasons.append("sni")

    return (bool(reasons), reasons or ["no-tls"])

def is_secure(protocol: str, data):
    if protocol == "ss":
        return is_shadowsocks_secure(data)
    if protocol == "vless":
        return is_vless_secure(data)
    if protocol == "trojan":
        return is_trojan_secure(data)
    if protocol == "vmess":
        return is_vmess_secure_from_json(data)

    return False, ["unknown-protocol"]

# ---------------- Output ----------------

def save_list_to_file(lst: Iterable[str], path: str):
    with open(path, "w", encoding="utf-8") as f:
        for item in lst:
            f.write(str(item) + "\n")
    log.info(f"Written: {path}")

# ---------------- Core Pipeline ----------------

def process_text(text: str, tag: str,
                 classified: dict,
                 seen: dict,
                 jsonl_fh,
                 only_secure: bool,
                 live_flag: bool):

    def add(entry: ConfigEntry):
        proto = entry.protocol if entry.protocol in seen else "other"

        if entry.uri in seen[proto]:
            return

        entry.protocol = proto
        seen[proto].add(entry.uri)
        classified[proto].append(entry)

        if not only_secure or entry.secure:
            jsonl_fh.write(
                json.dumps(entry.__dict__, ensure_ascii=False) + "\n"
            )

    for uri in find_uris(text):
        scheme = classify_uri_scheme(uri)
        scheme = SCHEME_MAP.get(scheme, scheme)

        normalized = normalize_tag_in_uri(uri, tag)

        if scheme == "vmess":
            j = decode_vmess_base64(uri)
            if not j:
                continue

            j = normalize_tag_in_json_obj(j, tag)
            normalized = encode_vmess_json_to_uri(j)
            secure, reasons = is_secure("vmess", j)

        elif scheme == "vless":
            secure, reasons = is_secure("vless", normalized)

        elif scheme == "trojan":
            secure, reasons = is_secure("trojan", normalized)

        elif scheme == "ss":
            secure, reasons = is_secure("ss", normalized)

        elif scheme in ("socks", "hysteria", "hysteria2"):
            secure, reasons = False, ["no-crypto-or-unsupported"]

        else:
            scheme = "other"
            secure, reasons = False, ["unsupported"]

        if live_flag and secure:
            parts = urlsplit(normalized)
            hostport = parts.netloc.split("@")[-1]

            if ":" in hostport:
                host, port = hostport.rsplit(":", 1)
                try:
                    ok, msg = live_check(host, int(port))
                    secure &= ok
                    reasons.append(f"live:{msg}")
                except Exception as e:
                    log.debug(f"Live check failed: {e}")

        add(ConfigEntry(scheme, normalized, secure, reasons, uri))

    # Also process standalone JSON objects (e.g. VMess blobs)
    for obj in find_json_configs(text):
        try:
            j = normalize_tag_in_json_obj(obj, tag)
            secure, reasons = is_vmess_secure_from_json(j)
            uri = encode_vmess_json_to_uri(j)
            add(ConfigEntry("vmess", uri, secure, reasons, json.dumps(obj)))
        except Exception as e:
            log.debug(f"JSON config skipped: {e}")

# ---------------- CLI ----------------

def main():
    p = argparse.ArgumentParser(
        description="Classify subscription configs and normalize tags"
    )
    p.add_argument("--url", "-u", action="append")
    p.add_argument("--infile")
    p.add_argument("-o", "--outdir", default="./classified_output")
    p.add_argument("--tag", default="3λΞĐ")
    p.add_argument("--only-secure", action="store_true")
    p.add_argument("--live-check", action="store_true")

    args = p.parse_args()

    urls = args.url or DEFAULT_URLS
    os.makedirs(args.outdir, exist_ok=True)

    protocols = [
        "vmess",
        "vless",
        "trojan",
        "ss",
        "socks",
        "hysteria",
        "hysteria2",
        "other",
    ]

    classified = {k: [] for k in protocols}
    seen = {k: set() for k in protocols}

    jsonl_path = os.path.join(args.outdir, "classified.jsonl")

    with open(jsonl_path, "w", encoding="utf-8") as fh:

        if args.infile:
            with open(args.infile, encoding="utf-8") as f:
                process_text(
                    f.read(),
                    args.tag,
                    classified,
                    seen,
                    fh,
                    args.only_secure,
                    args.live_check,
                )

        for u in urls:
            text = fetch_url(u)
            process_text(
                text,
                args.tag,
                classified,
                seen,
                fh,
                args.only_secure,
                args.live_check,
            )

    for proto, entries in classified.items():
        save_list_to_file(
            sorted({
                e.uri for e in entries
                if not args.only_secure or e.secure
            }),
            os.path.join(args.outdir, f"{proto}.txt"),
        )

    log.info("Done.")

if __name__ == "__main__":
    main()

# ---------- END FINAL SCRIPT ----------
