#!/usr/bin/env python3
# Improved and refactored version of the original script
# - logging, pathlib, concurrent fetch, requests.Session with retries
# - more robust JSON extraction (objects + arrays)
# - atomic file writes
# - CLI: concurrency option
from __future__ import annotations

import argparse
import base64
import json
import logging
import os
import re
import ssl
import socket
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util import Retry
except Exception:
    requests = None

from urllib.parse import unquote, quote, urlsplit, parse_qs

# --- Configuration / defaults ------------------------------------------------
DEFAULT_URLS = [
    "https://raw.githubusercontent.com/hamedp-71/Sub_Checker_Creator/refs/heads/main/final.txt",
    "https://raw.githubusercontent.com/M-logique/Proxies/refs/heads/main/proxies/regular/socks5.txt"
]

# Regex to capture URIs like vmess://..., vless://..., trojan://..., ss://..., socks5://...
URI_RE = re.compile(r"\b(?:vmess|vless|trojan|ss|socks5|socks|hysteria2|hysteria)://[^\s'\"\)\]]+", re.IGNORECASE)

# two-letter emoji flags
FLAG_RE = re.compile(r'([\U0001F1E6-\U0001F1FF]{2})')

SECURE_SS_CIPHERS = {
    'chacha20-ietf-poly1305',
    'xchacha20-ietf-poly1305',
    'aes-128-gcm',
    'aes-256-gcm',
    'aead_chacha20_ietf_poly1305',
}

WEAK_SS = {'rc4-md5', 'aes-128-cfb', 'aes-192-cfb'}

# --- Logging -----------------------------------------------------------------
logger = logging.getLogger("sub-classifier")
handler = logging.StreamHandler()
formatter = logging.Formatter("[%(levelname)s] %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# --- Utility functions -------------------------------------------------------
def extract_json_objects_and_arrays(text: str) -> List[str]:
    """
    Extract JSON objects and arrays robustly. Returns list of JSON text segments.
    Handles nested braces/brackets and quoted strings.
    """
    results = []
    stack = []
    start = None
    in_str = False
    esc = False
    str_char = None
    for i, ch in enumerate(text):
        if in_str:
            if esc:
                esc = False
                continue
            if ch == "\\":
                esc = True
                continue
            if ch == str_char:
                in_str = False
            continue
        else:
            if ch == '"' or ch == "'":
                in_str = True
                str_char = ch
                continue
            if ch in "{[":
                if not stack:
                    start = i
                stack.append(ch)
            elif ch in "}]":
                if not stack:
                    continue
                last = stack[-1]
                if (last == "{" and ch == "}") or (last == "[" and ch == "]"):
                    stack.pop()
                    if not stack and start is not None:
                        results.append(text[start:i+1])
                        start = None
                else:
                    # mismatched bracket -- reset
                    stack = []
                    start = None
    return results

def normalize_fragment(fragment: str, new_tag: str) -> str:
    if not fragment:
        return new_tag
    frag = fragment.strip()
    if new_tag in frag:
        return frag
    # try common delimiters
    for d in ('::', '-', '_'):
        if d in frag:
            parts = frag.split(d, 1)
            suffix = parts[1].strip()
            if new_tag in suffix:
                return suffix
            return f"{new_tag}::{suffix}"
    # try flag emoji
    m = FLAG_RE.search(frag)
    if m:
        suffix = m.group(1)
        if new_tag in suffix:
            return suffix
        return f"{new_tag}::{suffix}"
    return new_tag

def normalize_tag_in_uri(uri: str, new_tag: str) -> str:
    if '#' not in uri:
        encoded_frag = quote(new_tag, safe='')
        return f"{uri}#{encoded_frag}"
    main, frag = uri.split('#', 1)
    try:
        decoded = unquote(frag)
    except Exception:
        decoded = frag
    new_frag_raw = normalize_fragment(decoded, new_tag)
    encoded = quote(new_frag_raw, safe='')
    return f"{main}#{encoded}"

def normalize_tag_in_json_obj(j: dict, new_tag: str) -> dict:
    obj = dict(j)
    for key in ('ps', 'remarks', 'name'):
        if key in obj and isinstance(obj[key], str):
            try:
                decoded = unquote(obj[key])
            except Exception:
                decoded = obj[key]
            obj[key] = normalize_fragment(decoded, new_tag)
    return obj

def decode_vmess_base64(uri: str) -> Optional[dict]:
    try:
        payload = uri.split('://', 1)[1]
        payload = payload.split('#')[0].strip()
        # strip potential URL query or newline
        payload = payload.split('?')[0]
        padded = payload + '=' * ((4 - len(payload) % 4) % 4)
        b = base64.urlsafe_b64decode(padded)
        j = json.loads(b.decode('utf-8', errors='ignore'))
        return j
    except Exception:
        return None

def encode_vmess_json_to_uri(j: dict) -> str:
    raw = json.dumps(j, ensure_ascii=False, separators=(',', ':'))
    b = raw.encode('utf-8')
    encoded = base64.urlsafe_b64encode(b).decode('ascii').rstrip('=')
    return f"vmess://{encoded}"

def parse_query(uri: str) -> Dict[str, List[str]]:
    parts = urlsplit(uri)
    return {k: v for k, v in parse_qs(parts.query).items()}

# --- Security checks --------------------------------------------------------
def is_shadowsocks_secure(uri: str) -> Tuple[bool, List[str]]:
    reasons = []
    try:
        blob = uri.split('://', 1)[1].split('#')[0].split('?')[0]
        # attempt base64-decoded form (ss://<base64>)
        if blob and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=' for c in blob):
            try:
                padded = blob + '=' * ((4 - len(blob) % 4) % 4)
                dec = base64.urlsafe_b64decode(padded).decode('utf-8', errors='ignore')
                # possible forms: method:password@host:port or method:password
                if ':' in dec:
                    method = dec.split(':', 1)[0]
                    method_l = method.lower()
                    if method_l in WEAK_SS:
                        return False, [f'weak-cipher:{method}']
                    if method_l in SECURE_SS_CIPHERS:
                        return True, [f'secure-cipher:{method}']
                    # unknown cipher
                    return False, [f'cipher:{method}']
            except Exception:
                pass
        # attempt ss://method:password@host:port
        if '@' in blob and ':' in blob:
            left = blob.split('@', 1)[0]
            if ':' in left:
                method = left.split(':', 1)[0]
                method_l = method.lower()
                if method_l in WEAK_SS:
                    return False, [f'weak-cipher:{method}']
                if method_l in SECURE_SS_CIPHERS:
                    return True, [f'secure-cipher:{method}']
                return False, [f'cipher:{method}']
    except Exception:
        pass
    return False, ['unknown-ss-method']

def is_vless_secure(uri: str) -> Tuple[bool, List[str]]:
    q = parse_query(uri)
    reasons = []
    sec = q.get('security') or q.get('security[]')
    if sec and any('tls' in s.lower() for s in sec):
        reasons.append('security=tls')
    if 'pbk' in q or 'flow' in q:
        reasons.append('reality/pbk/flow')
    if 'sni' in q:
        reasons.append('sni')
    if 'tls' in uri.lower() or 'reality' in uri.lower():
        reasons.append('tls-or-reality-in-uri')
    if q.get('insecure', ['0'])[0] == '1':
        return False, ['insecure=1']
    if reasons:
        return True, reasons
    return False, ['no-tls-or-reality']

def is_hysteria_secure(uri: str) -> Tuple[bool, List[str]]:
    q = parse_query(uri)
    reasons = []
    security = q.get('security', [''])[0].lower() if q.get('security') else ''
    if security == 'tls':
        reasons.append('security=tls')
    if q.get('insecure', ['0'])[0] == '1':
        return False, ['insecure=1']
    if 'pinSHA256' in q:
        reasons.append('pinned-cert')
    if 'obfs' in q:
        reasons.append('obfs')
    if 'tls' in uri.lower() or 'quic' in uri.lower() or 'http3' in uri.lower():
        reasons.append('tls-or-quic-indicator')
    if reasons:
        return True, reasons
    return False, ['no-tls']

def is_trojan_secure(uri: str) -> Tuple[bool, List[str]]:
    q = parse_query(uri)
    if q.get('insecure', ['0'])[0] == '1':
        return False, ['insecure=1']
    reasons = ['tls-based']
    if 'sni' in q:
        reasons.append('sni')
    if 'tls' in uri.lower() or 'https' in uri.lower():
        reasons.append('tls-in-uri')
    return True, reasons

def is_vmess_secure_from_json(j: dict) -> Tuple[bool, List[str]]:
    reasons = []
    if j.get('tls'):
        reasons.append('tls')
    if j.get('sni'):
        reasons.append('sni')
    if 'pbk' in j or 'flow' in j:
        reasons.append('reality/pbk/flow')
    if j.get('allowInsecure'):
        return False, ['allowInsecure']
    if reasons:
        return True, reasons
    return False, ['no-tls-or-reality-detected']

def is_secure(protocol: str, uri_or_json, live_check_hostport: Optional[Tuple[str, int]] = None) -> Tuple[bool, List[str]]:
    protocol = protocol.lower()
    try:
        if protocol == 'ss':
            return is_shadowsocks_secure(uri_or_json)
        if protocol == 'vless':
            return is_vless_secure(uri_or_json)
        if protocol in ('hysteria', 'hysteria2'):
            return is_hysteria_secure(uri_or_json)
        if protocol == 'trojan':
            return is_trojan_secure(uri_or_json)
        if protocol == 'vmess':
            if isinstance(uri_or_json, dict):
                return is_vmess_secure_from_json(uri_or_json)
            else:
                j = decode_vmess_base64(uri_or_json)
                if j:
                    return is_vmess_secure_from_json(j)
                return False, ['vmess-not-decodable']
    except Exception as e:
        return False, [f'error:{e}']
    return False, ['unknown-protocol']

# --- Networking: fetch with optional requests + retries ----------------------
def build_requests_session(retries: int = 2, backoff: float = 0.5, status_forcelist=(429, 500, 502, 503, 504)):
    if not requests:
        return None
    session = requests.Session()
    retry = Retry(total=retries, read=retries, connect=retries,
                  backoff_factor=backoff, status_forcelist=status_forcelist,
                  allowed_methods=frozenset(['GET', 'POST']))
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('https://', adapter)
    session.mount('http://', adapter)
    return session

def fetch_url_sync(url: str, timeout: int = 20, session=None) -> str:
    logger.debug("Downloading: %s", url)
    try:
        if session:
            resp = session.get(url, timeout=timeout)
            resp.raise_for_status()
            return resp.text
        else:
            # fallback using urllib
            import urllib.request
            with urllib.request.urlopen(url, timeout=timeout) as r:
                return r.read().decode('utf-8', errors='ignore')
    except Exception as e:
        raise RuntimeError(f"Failed to fetch {url}: {e}") from e

def fetch_all(urls: List[str], concurrency: int = 4, timeout: int = 20, use_requests: bool = True) -> Dict[str, Optional[str]]:
    results: Dict[str, Optional[str]] = {}
    session = build_requests_session() if (use_requests and requests) else None
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futures = {ex.submit(fetch_url_sync, u, timeout, session): u for u in urls}
        for fut in as_completed(futures):
            u = futures[fut]
            try:
                txt = fut.result()
                results[u] = txt
                logger.info("[+] Fetched: %s (len=%d)", u, len(txt) if txt else 0)
            except Exception as e:
                results[u] = None
                logger.warning("[!] Failed to fetch %s: %s", u, e)
    return results

# --- TLS live check ---------------------------------------------------------
def live_check(host: str, port: int, sni: Optional[str] = None, timeout: float = 5.0) -> Tuple[bool, str]:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni or host) as ssock:
                # if handshake OK, return success message
                return True, 'tls-handshake-ok'
    except Exception as e:
        return False, repr(e)

# --- I/O --------------------------------------------------------------------
def atomic_write_lines(path: Path, lines: Iterable[str]):
    tmp = path.with_suffix(path.suffix + '.tmp')
    with tmp.open('w', encoding='utf-8') as fh:
        count = 0
        for item in lines:
            fh.write((json.dumps(item, ensure_ascii=False) + '\n') if isinstance(item, (dict, list)) else (str(item) + '\n'))
            count += 1
    tmp.replace(path)
    logger.info("[+] Written: %s (%d lines)", path, count)

# --- Main processing logic --------------------------------------------------
def find_uris(text: str) -> List[str]:
    return [m.strip() for m in URI_RE.findall(text)]

def find_json_configs(text: str) -> List[dict]:
    results = []
    for s in extract_json_objects_and_arrays(text):
        try:
            parsed = json.loads(s)
            # if array of objects, extend
            if isinstance(parsed, list):
                for it in parsed:
                    if isinstance(it, dict):
                        results.append(it)
            elif isinstance(parsed, dict):
                results.append(parsed)
        except Exception:
            continue
    return results

def process_text_and_classify(text: str, new_tag: str, classified: Dict[str, List[dict]],
                              seen: Dict[str, set], jsonl_fh, only_secure: bool, live_check_flag: bool):
    """
    Process one large text (from file or URL) and append entries into classified + jsonl file.
    jsonl_fh must be an open file handle in append mode. This function will write lines to it.
    """
    def add_entry(protocol: str, uri: str, secure: bool, reasons: List[str], original: str):
        if uri in seen[protocol]:
            return
        seen[protocol].add(uri)
        entry = {'protocol': protocol, 'uri': uri, 'secure': secure, 'reasons': reasons, 'original': original}
        classified.setdefault(protocol, []).append(entry)
        if (not only_secure) or entry['secure']:
            jsonl_fh.write(json.dumps(entry, ensure_ascii=False) + '\n')

    for uri in find_uris(text):
        scheme = uri.split('://', 1)[0].lower()
        if scheme == 'vmess':
            j = decode_vmess_base64(uri)
            if j is not None:
                j2 = normalize_tag_in_json_obj(j, new_tag)
                try:
                    new_uri = encode_vmess_json_to_uri(j2)
                    secure, reasons = is_secure('vmess', j2)
                    if live_check_flag and secure:
                        host = j2.get('add') or j2.get('host')
                        try:
                            port = int(j2.get('port') or j2.get('p') or 0)
                        except Exception:
                            port = 0
                        if host and port:
                            ok, msg = live_check(host, port, sni=j2.get('sni'))
                            reasons = reasons + [f'live_check:{ok}:{msg}']
                            secure = secure and ok
                    add_entry('vmess', new_uri, secure, reasons, uri)
                except Exception:
                    add_entry('vmess', uri.split('#', 1)[0], False, ['vmess-encode-failed'], uri)
            else:
                add_entry('vmess', uri.split('#', 1)[0], False, ['vmess-not-decodable'], uri)
        else:
            normalized = normalize_tag_in_uri(uri, new_tag)
            if scheme == 'vless':
                secure, reasons = is_vless_secure(normalized)
            elif scheme in ('hysteria2', 'hysteria'):
                secure, reasons = is_hysteria_secure(normalized)
            elif scheme == 'trojan':
                secure, reasons = is_trojan_secure(normalized)
            elif scheme == 'ss':
                secure, reasons = is_shadowsocks_secure(normalized)
            elif scheme in ('socks5', 'socks'):
                secure, reasons = (False, ['socks-no-crypto'])
            else:
                secure, reasons = (False, ['unknown-protocol'])

            if live_check_flag and secure and scheme in ('vless', 'trojan'):
                parts = urlsplit(normalized)
                net = parts.netloc
                if '@' in net:
                    hostport = net.split('@', 1)[1]
                else:
                    hostport = net
                if ':' in hostport:
                    host, port_s = hostport.rsplit(':', 1)
                    try:
                        port = int(port_s)
                        ok, msg = live_check(host, port, sni=parse_qs(parts.query).get('sni', [None])[0])
                        reasons = reasons + [f'live_check:{ok}:{msg}']
                        secure = secure and ok
                    except Exception:
                        reasons = reasons + ['live_check-failed-parse']

            if scheme == 'vless' and not secure:
                add_entry('vless_invalid', normalized, secure, reasons, uri)
            elif scheme in ('vless', 'trojan', 'ss', 'socks', 'hysteria', 'hysteria2'):
                add_entry(scheme, normalized, secure, reasons, uri)
            else:
                add_entry('other', normalized, secure, reasons, uri)

    for jb in find_json_configs(text):
        obj = normalize_tag_in_json_obj(jb, new_tag)
        js_text = json.dumps(obj, ensure_ascii=False)
        # heuristics: presence of vmess-like keys
        if any(k in obj for k in ('ps', 'add', 'port', 'id', 'aid', 'net', 'type', 'v')):
            try:
                new_uri = encode_vmess_json_to_uri(obj)
                secure_flag, reasons = is_vmess_secure_from_json(obj)
                if live_check_flag and secure_flag:
                    host = obj.get('add') or obj.get('host')
                    try:
                        port = int(obj.get('port') or obj.get('p') or 0)
                    except Exception:
                        port = 0
                    if host and port:
                        ok, msg = live_check(host, port, sni=obj.get('sni'))
                        reasons = reasons + [f'live_check:{ok}:{msg}']
                        secure_flag = secure_flag and ok
                add_entry('vmess', new_uri, secure_flag, reasons, js_text)
            except Exception:
                add_entry('vmess', js_text, False, ['vmess-encode-failed'], js_text)
        else:
            if 'protocol' in obj and isinstance(obj['protocol'], str) and obj['protocol'].lower() == 'vless':
                if 'tls' in js_text.lower() or 'reality' in js_text.lower():
                    add_entry('vless', js_text, True, ['tls-or-reality'], js_text)
                else:
                    add_entry('vless_invalid', js_text, False, ['no-tls-or-reality'], js_text)
            else:
                add_entry('other', js_text, False, ['json-non-vmess'], js_text)

# --- CLI / main -------------------------------------------------------------
def gather_urls_from_args(args) -> List[str]:
    urls: List[str] = []
    if args.url:
        urls.extend(args.url)
    if args.urls_file:
        try:
            p = Path(args.urls_file)
            with p.open('r', encoding='utf-8') as fh:
                for line in fh:
                    u = line.strip()
                    if u:
                        urls.append(u)
        except Exception as e:
            logger.warning("Could not read urls file '%s': %s", args.urls_file, e)
    if not urls:
        urls = DEFAULT_URLS.copy()
    # deduplicate while preserving order
    seen = set()
    uniq = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            uniq.append(u)
    return uniq

def main():
    p = argparse.ArgumentParser(description='Classify subscription configs and normalize fragments/tags (optionally only secure)')
    p.add_argument('--url', '-u', action='append')
    p.add_argument('--urls-file', help='Path to file with URLs, one per line')
    p.add_argument('--infile', help='Path to a local file to process (optional)')
    p.add_argument('--outdir', '-o', help='Output directory (default ./classified_output)', default='./classified_output')
    p.add_argument('--tag', help='Replacement tag (default "3λΞĐ")', default='3λΞĐ')
    p.add_argument('--only-secure', action='store_true', help='Only write secure configs to outputs (text and JSONL)')
    p.add_argument('--live-check', action='store_true', help='Attempt a simple TLS live-check for secure entries')
    p.add_argument('--concurrency', type=int, default=4, help='Number of concurrent fetch workers (default 4)')
    p.add_argument('--verbose', action='store_true', help='Enable debug logging')
    args = p.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    urls = gather_urls_from_args(args)
    logger.info("Using %d URL(s). Infile: %s", len(urls), bool(args.infile))

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    classified: Dict[str, List[dict]] = {
        'vmess': [], 'vless': [], 'vless_invalid': [], 'trojan': [], 'ss': [],
        'socks': [], 'hysteria2': [], 'hysteria': [], 'other': []
    }
    seen = {k: set() for k in classified.keys()}

    jsonl_path = outdir / 'classified.jsonl'
    # open once for append
    with jsonl_path.open('w', encoding='utf-8') as jsonl_fh:
        # process local infile first (if provided)
        if args.infile:
            try:
                with open(args.infile, 'r', encoding='utf-8') as fh:
                    text = fh.read()
                process_text_and_classify(text, args.tag, classified, seen, jsonl_fh, args.only_secure, args.live_check)
            except Exception as e:
                logger.warning("Failed to read infile '%s': %s", args.infile, e)

        # fetch URLs concurrently and process results sequentially
        fetched = fetch_all(urls, concurrency=args.concurrency, timeout=20, use_requests=True)
        for u, txt in fetched.items():
            if not txt:
                logger.debug("Skipping empty fetch result for %s", u)
                continue
            try:
                process_text_and_classify(txt, args.tag, classified, seen, jsonl_fh, args.only_secure, args.live_check)
            except Exception as e:
                logger.warning("Failed to process content from %s: %s", u, e)

    # helper to extract URIs (respect only-secure)
    def extract_uris(entries: List[dict]) -> List[str]:
        if args.only_secure:
            return [e['uri'] for e in entries if e.get('secure')]
        return [e['uri'] for e in entries]

    # atomic writes for each list
    atomic_write_lines(outdir / 'vmess.txt', sorted(set(extract_uris(classified.get('vmess', [])))))
    atomic_write_lines(outdir / 'vless.txt', sorted(set(extract_uris(classified.get('vless', [])))))
    atomic_write_lines(outdir / 'vless_invalid.txt', sorted(set(extract_uris(classified.get('vless_invalid', [])))))
    atomic_write_lines(outdir / 'trojan.txt', sorted(set(extract_uris(classified.get('trojan', [])))))
    atomic_write_lines(outdir / 'shadowsocks.txt', sorted(set(extract_uris(classified.get('ss', [])))))
    atomic_write_lines(outdir / 'socks.txt', sorted(set(extract_uris(classified.get('socks', [])))))
    atomic_write_lines(outdir / 'hysteria2.txt', sorted(set(extract_uris(classified.get('hysteria2', [])))))
    atomic_write_lines(outdir / 'hysteria.txt', sorted(set(extract_uris(classified.get('hysteria', [])))))
    atomic_write_lines(outdir / 'other.txt', sorted(set(extract_uris(classified.get('other', [])))))

    # summary
    logger.info("=== SUMMARY ===")
    for k in ('vmess', 'vless', 'vless_invalid', 'trojan', 'ss', 'socks', 'hysteria2', 'hysteria', 'other'):
        count = len([e for e in classified.get(k, []) if (not args.only_secure) or e.get('secure')])
        logger.info("%-15s: %d", k, count)
    logger.info("Output directory: %s", outdir.resolve())
    logger.info("Structured output (JSONL): %s", jsonl_path.resolve())
    logger.info("Done.")

if __name__ == '__main__':
    main()
