#!/usr/bin/env python3
# ---------- BEGIN SCRIPT ----------
import os
import re
import argparse
import json
import base64
import socket
import ssl
from urllib.parse import unquote, quote, urlsplit, parse_qs
from typing import List, Iterable, Tuple

try:
    import requests
except Exception:
    requests = None
    import urllib.request

DEFAULT_URLS = [
    "https://raw.githubusercontent.com/hamedp-71/Sub_Checker_Creator/refs/heads/main/final.txt#xsfilternet",
    "https://raw.githubusercontent.com/M-logique/Proxies/refs/heads/main/proxies/regular/socks5.txt"
]

URI_RE = re.compile(r"\b(?:vmess|vless|trojan|ss|socks5|socks|hysteria2|hysteria)://[^\s'\"]+", re.IGNORECASE)
FLAG_RE = re.compile('([\\U0001F1E6-\\U0001F1FF]{2})')

SECURE_SS_CIPHERS = {
    'chacha20-ietf-poly1305',
    'xchacha20-ietf-poly1305',
    'aes-128-gcm',
    'aes-256-gcm',
    'aead_chacha20_ietf_poly1305',
}

def extract_json_objects(text: str) -> List[str]:
    objs = []
    start = None
    stack = 0
    in_str = False
    str_char = None
    esc = False
    for i, ch in enumerate(text):
        if in_str:
            if esc:
                esc = False
                continue
            if ch == '\\\\':
                esc = True
                continue
            if ch == str_char:
                in_str = False
                str_char = None
            continue
        else:
            if ch == '\"' or ch == "'":
                in_str = True
                str_char = ch
                continue
            if ch == '{':
                if stack == 0:
                    start = i
                stack += 1
            elif ch == '}':
                if stack > 0:
                    stack -= 1
                    if stack == 0 and start is not None:
                        objs.append(text[start:i+1])
                        start = None
    return objs

def normalize_fragment(fragment: str, new_tag: str) -> str:
    if not fragment:
        return new_tag
    frag = fragment.strip()
    if new_tag in frag:
        return frag
    delimiters = ['::', '-', '_']
    suffix = None
    for d in delimiters:
        if d in frag:
            parts = frag.split(d, 1)
            suffix = parts[1].strip()
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
            new = normalize_fragment(decoded, new_tag)
            obj[key] = new
    return obj

def decode_vmess_base64(uri: str):
    try:
        payload = uri.split('://', 1)[1]
        payload = payload.split('#')[0].strip()
        padded = payload + '=' * (-len(payload) % 4)
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

def fetch_url(url: str, timeout: int = 30) -> str:
    print(f"[+] Downloading from: {url}")
    try:
        if requests:
            resp = requests.get(url, timeout=timeout)
            resp.raise_for_status()
            return resp.text
        else:
            with urllib.request.urlopen(url, timeout=timeout) as r:
                return r.read().decode('utf-8', errors='ignore')
    except Exception as e:
        raise RuntimeError(f"Failed to fetch {url}: {e}") from e

def find_uris(text: str) -> List[str]:
    found = URI_RE.findall(text)
    return [u.strip() for u in found]

def find_json_configs(text: str) -> List[dict]:
    results = []
    for s in extract_json_objects(text):
        try:
            j = json.loads(s)
            results.append(j)
        except Exception:
            continue
    return results

def classify_uri_scheme(uri: str) -> str:
    return uri.split('://', 1)[0].lower()

def parse_query(uri: str) -> dict:
    parts = urlsplit(uri)
    return {k: v for k, v in parse_qs(parts.query).items()}

WEAK_SS = {'rc4-md5', 'aes-128-cfb', 'aes-192-cfb'}

def is_shadowsocks_secure(uri: str) -> Tuple[bool, List[str]]:
    reasons = []
    try:
        blob = uri.split('://', 1)[1].split('#')[0].split('?')[0]
        if blob and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=' for c in blob):
            try:
                padded = blob + '=' * (-len(blob) % 4)
                dec = base64.urlsafe_b64decode(padded).decode('utf-8', errors='ignore')
                if ':' in dec:
                    method = dec.split(':', 1)[0]
                    if method.lower() in WEAK_SS:
                        return False, [f'weak-cipher:{method}']
                    if method.lower() in SECURE_SS_CIPHERS:
                        return True, [f'secure-cipher:{method}']
            except Exception:
                pass
        if '@' in blob and ':' in blob:
            left = blob.split('@', 1)[0]
            if ':' in left:
                method = left.split(':', 1)[0]
                if method.lower() in WEAK_SS:
                    return False, [f'weak-cipher:{method}']
                if method.lower() in SECURE_SS_CIPHERS:
                    return True, [f'secure-cipher:{method}']
                reasons.append(f'cipher:{method}')
                return False, reasons
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
        if 'tls' not in reasons:
            reasons.append('tls-or-reality-in-uri')
    insecure = q.get('insecure', ['0'])[0]
    if insecure == '1':
        return False, ['insecure=1']
    if reasons:
        return True, reasons
    return False, ['no-tls-or-reality']

def is_hysteria_secure(uri: str) -> Tuple[bool, List[str]]:
    q = parse_query(uri)
    reasons = []
    security = q.get('security', [''])[0].lower()
    if security == 'tls':
        reasons.append('security=tls')
    if q.get('insecure', ['0'])[0] == '1':
        return False, ['insecure=1']
    if 'pinSHA256' in q:
        reasons.append('pinned-cert')
    if 'obfs' in q:
        reasons.append('obfs')
    if 'tls' in uri.lower() or 'http3' in uri.lower() or 'quic' in uri.lower():
        if 'security=tls' not in reasons:
            reasons.append('tls-or-quic-indicator')
    if reasons:
        return True, reasons
    return False, ['no-tls']

def is_trojan_secure(uri: str) -> Tuple[bool, List[str]]:
    q = parse_query(uri)
    if q.get('insecure', ['0'])[0] == '1':
        return False, ['insecure=1']
    reasons = []
    if 'sni' in q:
        reasons.append('sni')
    if 'tls' in uri.lower() or 'https' in uri.lower():
        reasons.append('tls-in-uri')
    reasons.insert(0, 'tls-based')
    return True, reasons

def is_vmess_secure_from_json(j: dict) -> Tuple[bool, List[str]]:
    reasons = []
    if 'tls' in j and j.get('tls'):
        reasons.append('tls')
    if 'sni' in j and j.get('sni'):
        reasons.append('sni')
    if 'pbk' in j or 'flow' in j:
        reasons.append('reality/pbk/flow')
    if j.get('allowInsecure'):
        return False, ['allowInsecure']
    if reasons:
        return True, reasons
    return False, ['no-tls-or-reality-detected']

def is_secure(protocol: str, uri_or_json, live_check_hostport: Tuple[str, int] = None) -> Tuple[bool, List[str]]:
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

def live_check(host: str, port: int, sni: str = None, timeout: float = 5.0) -> Tuple[bool, str]:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni or host) as ssock:
                cert = ssock.getpeercert()
                return True, 'tls-handshake-ok'
    except Exception as e:
        return False, str(e)

def save_list_to_file(lst: Iterable[str], path: str):
    with open(path, 'w', encoding='utf-8') as f:
        count = 0
        for item in lst:
            if isinstance(item, (dict, list)):
                f.write(json.dumps(item, ensure_ascii=False) + '\n')
            else:
                f.write(str(item) + '\n')
            count += 1
    print(f"[+] Written: {path} ({count})")

def process_text_and_classify(text: str, new_tag: str, classified: dict, seen: dict, jsonl_fh, only_secure: bool, live_check_flag: bool):
    def add_entry(protocol: str, uri: str, secure: bool, reasons: List[str], original: str):
        if uri in seen[protocol]:
            return
        seen[protocol].add(uri)
        entry = {'protocol': protocol, 'uri': uri, 'secure': secure, 'reasons': reasons, 'original': original}
        classified[protocol].append(entry)
        if not only_secure or entry['secure']:
            jsonl_fh.write(json.dumps(entry, ensure_ascii=False) + '\n')

    for uri in find_uris(text):
        scheme = classify_uri_scheme(uri)
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
                    base = uri.split('#', 1)[0]
                    add_entry('vmess', base, False, ['vmess-encode-failed'], uri)
            else:
                base = uri.split('#', 1)[0]
                add_entry('vmess', base, False, ['vmess-not-decodable'], uri)
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
                    host, port = hostport.rsplit(':', 1)
                    try:
                        port = int(port)
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
        lowered_keys = {k.lower(): k for k in obj.keys()}
        js_text = json.dumps(obj, ensure_ascii=False)
        if any(k in lowered_keys for k in ('ps', 'add', 'port', 'id', 'aid', 'net', 'type', 'v')):
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

def gather_urls_from_args(args) -> List[str]:
    urls = []
    if args.url:
        urls.extend(args.url)
    if args.urls_file:
        try:
            with open(args.urls_file, 'r', encoding='utf-8') as fh:
                for line in fh:
                    u = line.strip()
                    if u:
                        urls.append(u)
        except Exception as e:
            print(f"[!] Could not read urls file '{args.urls_file}': {e}")
    if not urls:
        urls = DEFAULT_URLS.copy()
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
    p.add_argument('--decode-vmess', action='store_true')
    p.add_argument('--tag', help='Replacement tag (default \"3λΞĐ\")', default='3λΞĐ')
    p.add_argument('--only-secure', action='store_true', help='Only write secure configs to outputs (text and JSONL)')
    p.add_argument('--live-check', action='store_true', help='Attempt a simple TLS live-check for secure entries')
    args = p.parse_args()

    urls = gather_urls_from_args(args)
    print(f"[+] Using {len(urls)} URL(s). Infile: {args.infile is not None}")

    os.makedirs(args.outdir, exist_ok=True)

    classified = {
        'vmess': [],
        'vless': [],
        'vless_invalid': [],
        'trojan': [],
        'ss': [],
        'socks': [],
        'hysteria2': [],
        'hysteria': [],
        'other': []
    }
    seen = {k: set() for k in classified.keys()}

    jsonl_path = os.path.join(args.outdir, 'classified.jsonl')
    with open(jsonl_path, 'w', encoding='utf-8') as jsonl_fh:
        if args.infile:
            try:
                with open(args.infile, 'r', encoding='utf-8') as fh:
                    text = fh.read()
                process_text_and_classify(text, args.tag, classified, seen, jsonl_fh, args.only_secure, args.live_check)
            except Exception as e:
                print(f"[!] Failed to read infile '{args.infile}': {e}")

        for u in urls:
            try:
                txt = fetch_url(u)
                process_text_and_classify(txt, args.tag, classified, seen, jsonl_fh, args.only_secure, args.live_check)
            except Exception as e:
                print(f"[!] Warning: {e}")
                continue

    def extract_uris(entries):
        if args.only_secure:
            return [e['uri'] for e in entries if e.get('secure')]
        return [e['uri'] for e in entries]

    save_list_to_file(sorted(set(extract_uris(classified['vmess']))), os.path.join(args.outdir, 'vmess.txt'))
    save_list_to_file(sorted(set(extract_uris(classified['vless']))), os.path.join(args.outdir, 'vless.txt'))
    save_list_to_file(sorted(set(extract_uris(classified['vless_invalid']))), os.path.join(args.outdir, 'vless_invalid.txt'))
    save_list_to_file(sorted(set(extract_uris(classified['trojan']))), os.path.join(args.outdir, 'trojan.txt'))
    save_list_to_file(sorted(set(extract_uris(classified['ss']))), os.path.join(args.outdir, 'shadowsocks.txt'))
    save_list_to_file(sorted(set(extract_uris(classified['socks']))), os.path.join(args.outdir, 'socks.txt'))
    save_list_to_file(sorted(set(extract_uris(classified['hysteria2']))), os.path.join(args.outdir, 'hysteria2.txt'))
    save_list_to_file(sorted(set(extract_uris(classified['hysteria']))), os.path.join(args.outdir, 'hysteria.txt'))
    save_list_to_file(sorted(set(extract_uris(classified['other']))), os.path.join(args.outdir, 'other.txt'))

    print('\\n=== SUMMARY ===')
    for k in ['vmess', 'vless', 'vless_invalid', 'trojan', 'ss', 'socks', 'hysteria2', 'hysteria', 'other']:
        count = len([e for e in classified[k] if (not args.only_secure) or e.get('secure')])
        print(f"{k:15s}: {count}")
    print(f"\\nOutput directory: {os.path.abspath(args.outdir)}")
    print(f"Structured output (JSONL): {jsonl_path}")
    print('Done.')

if __name__ == '__main__':
    main()
# ---------- END SCRIPT ----------
