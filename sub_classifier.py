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

# default URLs
DEFAULT_URLS = [
    "https://raw.githubusercontent.com/hamedp-71/Sub_Checker_Creator/refs/heads/main/final.txt#xsfilternet",
    "https://raw.githubusercontent.com/M-logique/Proxies/refs/heads/main/proxies/regular/socks5.txt"
]

# include hysteria2 and hysteria in recognized schemes
URI_RE = re.compile(r"\b(?:vmess|vless|trojan|ss|socks5|socks|hysteria2|hysteria)://[^\s'\"]+", re.IGNORECASE)

FLAG_RE = re.compile(r"([\U0001F1E6-\U0001F1FF]{2})")

# ----------------------
# Balanced JSON extractor
# ----------------------

def extract_json_objects(text: str) -> List[str]:
    objs = []
    start = None
    stack = 0
    for i, ch in enumerate(text):
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


# ======================
# Tag normalization helpers
# ======================

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
    # only operate on fragment (non-vmess). vmess handled separately
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


# ------------------
# vmess encode/decode helpers
# ------------------

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


# ------------------
# Networking / utils
# ------------------

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


# ------------------
# Security detection per protocol
# ------------------

WEAK_SS = {'rc4-md5', 'aes-128-cfb', 'aes-192-cfb'}

def is_shadowsocks_secure(uri: str) -> Tuple[bool, List[str]]:
    # best-effort: try to extract method from different ss URI forms
    reasons = []
    # form1: ss://<base64> where base64 decodes to method:password@host:port
    try:
        blob = uri.split('://', 1)[1].split('#')[0].split('?')[0]
        if blob.startswith('//'):
            blob = blob[2:]
        # if contains '@' it's likely method:pass@host:port or userinfo
        if '@' in blob and ':' in blob:
            left = blob.split('@', 1)[0]
            if ':' in left:
                method = left.split(':', 1)[0]
                if method.lower() in WEAK_SS:
                    return False, [f'weak-cipher:{method}']
                else:
                    reasons.append('aead-or-strong-cipher')
                    return True, reasons
    except Exception:
        pass
    # fallback: unknown -> mark as unsure (not secure)
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
    if reasons:
        return True, reasons
    return False, ['no-tls']


def is_trojan_secure(uri: str) -> Tuple[bool, List[str]]:
    # trojan is TLS-based by design, but check for explicit insecure flags
    q = parse_query(uri)
    if q.get('insecure', ['0'])[0] == '1':
        return False, ['insecure=1']
    reasons = ['tls-based']
    if 'sni' in q:
        reasons.append('sni')
    return True, reasons


def is_vmess_secure_from_json(j: dict) -> Tuple[bool, List[str]]:
    reasons = []
    # common indications
    if 'tls' in j and j.get('tls'):
        reasons.append('tls')
    if 'sni' in j and j.get('sni'):
        reasons.append('sni')
    # reality: presence of pbk or flow
    if 'pbk' in j or 'flow' in j:
        reasons.append('reality/pbk/flow')
    # default heuristic: vmess has internal crypto but still check for tls/reality
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
        if protocol == 'hysteria' or protocol == 'hysteria2':
            return is_hysteria_secure(uri_or_json)
        if protocol == 'trojan':
            return is_trojan_secure(uri_or_json)
        if protocol == 'vmess':
            # uri_or_json could be decoded JSON dict
            if isinstance(uri_or_json, dict):
                return is_vmess_secure_from_json(uri_or_json)
            else:
                # try decode
                j = decode_vmess_base64(uri_or_json)
                if j:
                    return is_vmess_secure_from_json(j)
                return False, ['vmess-not-decodable']
    except Exception as e:
        return False, [f'error:{e}']
    return False, ['unknown-protocol']


# ------------------
# Live-check (optional, best-effort)
# ------------------

def live_check(host: str, port: int, sni: str = None, timeout: float = 5.0) -> Tuple[bool, str]:
    # Best-effort: attempt TCP connect + TLS handshake (works for TLS-over-TCP)
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


# ------------------
# Main classification flow
# ------------------

def process_text_and_classify(text: str, new_tag: str, classified: dict, jsonl_fh, only_secure: bool, live_check_flag: bool):
    for uri in find_uris(text):
        scheme = classify_uri_scheme(uri)
        entry = {
            'protocol': scheme,
            'original': uri,
            'uri': None,
            'secure': False,
            'reasons': []
        }

        if scheme == 'vmess':
            j = decode_vmess_base64(uri)
            if j is not None:
                j2 = normalize_tag_in_json_obj(j, new_tag)
                try:
                    new_uri = encode_vmess_json_to_uri(j2)
                    entry['uri'] = new_uri
                    secure, reasons = is_secure('vmess', j2)
                    entry['secure'] = secure
                    entry['reasons'] = reasons
                    # optional live-check: try to parse host/port from j2
                    if live_check_flag and secure:
                        host = j2.get('add') or j2.get('host')
                        port = int(j2.get('port') or j2.get('p') or 0)
                        if host and port:
                            ok, msg = live_check(host, port, sni=j2.get('sni'))
                            entry['reasons'].append(f'live_check:{ok}:{msg}')
                            entry['secure'] = entry['secure'] and ok
                    classified['vmess'].add(entry['uri'])
                except Exception:
                    base = uri.split('#', 1)[0]
                    entry['uri'] = base
                    entry['secure'] = False
                    entry['reasons'] = ['vmess-encode-failed']
                    classified['vmess'].add(base)
            else:
                base = uri.split('#', 1)[0]
                entry['uri'] = base
                entry['secure'] = False
                entry['reasons'] = ['vmess-not-decodable']
                classified['vmess'].add(base)

        else:
            # non-vmess: normalize fragment and then check security
            normalized = normalize_tag_in_uri(uri, new_tag)
            entry['uri'] = normalized
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

            entry['secure'] = secure
            entry['reasons'] = reasons
            # live-check if requested and makes sense
            if live_check_flag and secure and scheme in ('vless', 'trojan'):
                parts = urlsplit(normalized)
                # try to extract host:port from netloc or userinfo
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
                        entry['reasons'].append(f'live_check:{ok}:{msg}')
                        entry['secure'] = entry['secure'] and ok
                    except Exception:
                        entry['reasons'].append('live_check-failed-parse')

            # save to corresponding bucket
            if scheme in ('vless', 'vless_invalid', 'trojan', 'ss', 'socks', 'hysteria', 'hysteria2'):
                # map 'vless_invalid' is handled by secure flag
                if scheme == 'vless' and not entry['secure']:
                    classified['vless_invalid'].add(entry['uri'])
                else:
                    # add to named bucket if exists
                    if scheme in classified:
                        classified[scheme].add(entry['uri'])
                    else:
                        classified['other'].add(entry['uri'])
            else:
                classified['other'].add(entry['uri'])

        # write structured JSONL entry if not filtered by only_secure
        if not only_secure or entry['secure']:
            jsonl_fh.write(json.dumps({
                'protocol': entry['protocol'],
                'uri': entry['uri'],
                'secure': entry['secure'],
                'reasons': entry['reasons'],
                'original': entry['original']
            }, ensure_ascii=False) + '\n')

    # JSON blocks in text (vmess-like or other jsonconfigs)
    for jb in find_json_configs(text):
        obj = normalize_tag_in_json_obj(jb, new_tag)
        lowered_keys = {k.lower(): k for k in obj.keys()}
        js_text = json.dumps(obj, ensure_ascii=False)
        if any(k in lowered_keys for k in ('ps', 'add', 'port', 'id', 'aid', 'net', 'type', 'v')):
            try:
                new_uri = encode_vmess_json_to_uri(obj)
                classified['vmess'].add(new_uri)
                # write minimal JSONL entry
                jsonl_fh.write(json.dumps({'protocol': 'vmess', 'uri': new_uri, 'secure': is_vmess_secure_from_json(obj)[0], 'reasons': is_vmess_secure_from_json(obj)[1]}, ensure_ascii=False) + '\n')
            except Exception:
                classified['vmess'].add(js_text)
        else:
            if 'protocol' in obj and isinstance(obj['protocol'], str) and obj['protocol'].lower() == 'vless':
                if 'tls' in js_text.lower() or 'reality' in js_text.lower():
                    classified['vless'].add(js_text)
                    jsonl_fh.write(json.dumps({'protocol': 'vless', 'uri': js_text, 'secure': True, 'reasons': ['tls-or-reality']}, ensure_ascii=False) + '\n')
                else:
                    classified['vless_invalid'].add(js_text)
                    jsonl_fh.write(json.dumps({'protocol': 'vless', 'uri': js_text, 'secure': False, 'reasons': ['no-tls-or-reality']}, ensure_ascii=False) + '\n')
            else:
                classified['other'].add(js_text)


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
    p = argparse.ArgumentParser(description='Classify subscription configs and normalize fragments/tags')
    p.add_argument('--url', '-u', action='append')
    p.add_argument('--urls-file', help='Path to file with URLs, one per line')
    p.add_argument('--infile', help='Path to a local file to process (optional)')
    p.add_argument('--outdir', '-o', help='Output directory (default ./classified_output)', default='./classified_output')
    p.add_argument('--decode-vmess', action='store_true')
    p.add_argument('--tag', help='Replacement tag (default "3λΞĐ")', default='3λΞĐ')
    p.add_argument('--only-secure', action='store_true', help='Only write secure configs to outputs')
    p.add_argument('--live-check', action='store_true', help='Attempt a simple TLS live-check for secure entries')
    args = p.parse_args()

    urls = gather_urls_from_args(args)
    print(f"[+] Using {len(urls)} URL(s). Infile: {args.infile is not None}")

    os.makedirs(args.outdir, exist_ok=True)

    classified = {
        'vmess': set(),
        'vless': set(),
        'vless_invalid': set(),
        'trojan': set(),
        'ss': set(),
        'socks': set(),
        'hysteria2': set(),
        'hysteria': set(),
        'other': set()
    }

    jsonl_path = os.path.join(args.outdir, 'classified.jsonl')
    with open(jsonl_path, 'w', encoding='utf-8') as jsonl_fh:
        # process infile first
        if args.infile:
            try:
                with open(args.infile, 'r', encoding='utf-8') as fh:
                    text = fh.read()
                process_text_and_classify(text, args.tag, classified, jsonl_fh, args.only_secure, args.live_check)
            except Exception as e:
                print(f"[!] Failed to read infile '{args.infile}': {e}")

        for u in urls:
            try:
                txt = fetch_url(u)
                process_text_and_classify(txt, args.tag, classified, jsonl_fh, args.only_secure, args.live_check)
            except Exception as e:
                print(f"[!] Warning: {e}")
                continue

    # write text outputs (filter by only_secure if requested)
    def maybe_filter(lst):
        if args.only_secure:
            # we don't have per-item secure flags in sets — JSONL is the authoritative output
            # For text outputs: write entries as-is but warn user to use JSONL for secure filtering
            return sorted(lst)
        return sorted(lst)

    save_list_to_file(maybe_filter(classified['vmess']), os.path.join(args.outdir, 'vmess.txt'))
    save_list_to_file(maybe_filter(classified['vless']), os.path.join(args.outdir, 'vless.txt'))
    save_list_to_file(maybe_filter(classified['vless_invalid']), os.path.join(args.outdir, 'vless_invalid.txt'))
    save_list_to_file(maybe_filter(classified['trojan']), os.path.join(args.outdir, 'trojan.txt'))
    save_list_to_file(maybe_filter(classified['ss']), os.path.join(args.outdir, 'shadowsocks.txt'))
    save_list_to_file(maybe_filter(classified['socks']), os.path.join(args.outdir, 'socks.txt'))
    save_list_to_file(maybe_filter(classified['hysteria2']), os.path.join(args.outdir, 'hysteria2.txt'))
    save_list_to_file(maybe_filter(classified['hysteria']), os.path.join(args.outdir, 'hysteria.txt'))
    save_list_to_file(maybe_filter(classified['other']), os.path.join(args.outdir, 'other.txt'))

    print('\n=== SUMMARY ===')
    for k in ['vmess', 'vless', 'vless_invalid', 'trojan', 'ss', 'socks', 'hysteria2', 'hysteria', 'other']:
        print(f"{k:15s}: {len(classified[k])}")
    print(f"\nOutput directory: {os.path.abspath(args.outdir)}")
    print(f"Structured output (JSONL): {jsonl_path}")
    print('Done.')


if __name__ == '__main__':
    main()
