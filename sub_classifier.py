import os
import re
import argparse
import json
import base64
from urllib.parse import unquote, quote
from typing import List, Tuple, Iterable

try:
    import requests
except Exception:
    requests = None
    import urllib.request

# default URLs (you can add more)
DEFAULT_URLS = [
    "https://raw.githubusercontent.com/hamedp-71/Sub_Checker_Creator/refs/heads/main/final.txt#xsfilternet",
    "https://raw.githubusercontent.com/M-logique/Proxies/refs/heads/main/proxies/regular/socks5.txt"
]

# include hysteria2 and hysteria in recognized schemes
URI_RE = re.compile(
    r'\b(?:vmess|vless|trojan|ss|socks5|socks|hysteria2|hysteria)://[^\s\'\"]+',
    re.IGNORECASE
)

FLAG_RE = re.compile(r"([\U0001F1E6-\U0001F1FF]{2})")

# ----------------------
# Balanced JSON extractor
# ----------------------

def extract_json_objects(text: str) -> List[str]:
    """Extract balanced JSON objects from text. Returns list of JSON string fragments.
    This uses a small stack to find matching braces, so it avoids greedy regex pitfalls.
    """
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
# 🔹 تابع نرمال‌سازی تگ
# ======================

def normalize_fragment(fragment: str, new_tag: str) -> str:
    """Given a decoded fragment (e.g. 'hamedp71::🇵🇰' or 'hamedp71'),
    return a new fragment text with username replaced by new_tag while preserving
    suffix (especially 2-letter flag emoji).
    The returned value is the raw fragment (not percent-encoded).
    """
    if not fragment:
        return new_tag

    frag = fragment.strip()

    # If the new_tag is already present, keep as-is
    if new_tag in frag:
        return frag

    # Try to extract suffix after common delimiters
    delimiters = ['::', '-', '_']
    suffix = None
    for d in delimiters:
        if d in frag:
            parts = frag.split(d, 1)
            # parts[0] is the old name, parts[1] is the suffix
            suffix = parts[1].strip()
            break

    # If no delimiter found, try to detect flag directly in the fragment
    if suffix is None:
        m = FLAG_RE.search(frag)
        if m:
            suffix = m.group(1)

    if suffix:
        # If suffix already contains the new_tag (unlikely) avoid duplication
        if new_tag in suffix:
            return suffix
        return f"{new_tag}::{suffix}"

    # Otherwise return just the new_tag
    return new_tag


def normalize_tag_in_uri(uri: str, new_tag: str) -> str:
    """Replace the fragment part (after '#') of a URI with new_tag while preserving flags/suffixes.
    Properly decodes percent-encoding, operates on text, then re-encodes the fragment portion.
    If the URI has no fragment, appends one with new_tag.
    """
    if '#' not in uri:
        # append fragment
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
    """If JSON object has a 'ps' (or common alias) field used as a human-friendly name,
    normalize it by replacing the username while preserving flags.
    Returns possibly modified object (a shallow copy will be created).
    """
    obj = dict(j)  # shallow copy
    # possible keys: 'ps', 'remarks', 'name'
    for key in ('ps', 'remarks', 'name'):
        if key in obj and isinstance(obj[key], str):
            try:
                decoded = unquote(obj[key])
            except Exception:
                decoded = obj[key]
            new = normalize_fragment(decoded, new_tag)
            # store raw new value (not percent-encoded) so downstream tools can read it
            obj[key] = new
    return obj


# ------------------
# Networking / utils
# ------------------

def fetch_url(url: str, timeout: int = 30) -> str:
    """Fetch URL and return text. Raises on unrecoverable HTTP error."""
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
    scheme = uri.split('://', 1)[0].lower()
    return scheme


def vless_valid(uri: str) -> bool:
    """Check if vless contains tls or reality (in query or uri). Kept for compatibility.
    """
    low = uri.lower()
    if 'tls' in low or 'reality' in low:
        return True
    un = unquote(uri).lower()
    if 'tls' in un or 'reality' in un:
        return True
    return False


def decode_vmess_base64(uri: str):
    try:
        payload = uri.split('://', 1)[1]
        payload = payload.split('#')[0].strip()
        b = base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4))
        j = json.loads(b.decode('utf-8', errors='ignore'))
        return j
    except Exception:
        return None


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
# Main flow
# ------------------

def process_text_and_classify(text: str, new_tag: str, classified: dict):
    # find URIs and normalize them immediately
    for uri in find_uris(text):
        normalized = normalize_tag_in_uri(uri, new_tag)
        scheme = classify_uri_scheme(normalized)
        if scheme == 'vmess':
            classified['vmess'].add(normalized)
        elif scheme == 'vless':
            if vless_valid(normalized):
                classified['vless'].add(normalized)
            else:
                classified['vless_invalid'].add(normalized)
        elif scheme == 'trojan':
            classified['trojan'].add(normalized)
        elif scheme == 'ss':
            classified['ss'].add(normalized)
        elif scheme in ('socks5', 'socks'):
            classified['socks'].add(normalized)
        elif scheme == 'hysteria2':
            classified['hysteria2'].add(normalized)
        elif scheme == 'hysteria':
            classified['hysteria'].add(normalized)
        else:
            classified['other'].add(normalized)

    # find json blocks, normalize ps/remarks/name and classify
    for jb in find_json_configs(text):
        obj = normalize_tag_in_json_obj(jb, new_tag)
        lowered_keys = {k.lower(): k for k in obj.keys()}
        js_text = json.dumps(obj, ensure_ascii=False)
        if any(k in lowered_keys for k in ('ps', 'add', 'port', 'id', 'aid', 'net', 'type', 'v')):
            # treat as vmess-like if keys present
            classified['vmess'].add(js_text)
        else:
            if 'protocol' in obj and isinstance(obj['protocol'], str) and obj['protocol'].lower() == 'vless':
                if 'tls' in js_text.lower() or 'reality' in js_text.lower():
                    classified['vless'].add(js_text)
                else:
                    classified['vless_invalid'].add(js_text)
            else:
                classified['other'].add(js_text)


def main():
    p = argparse.ArgumentParser(description='Classify subscription configs and normalize fragments/tags')
    p.add_argument('--url', '-u', action='append', help='URL to fetch (can be repeated)')
    p.add_argument('--urls-file', help='Path to file with URLs, one per line')
    p.add_argument('--infile', help='Path to a local file to process (optional)')
    p.add_argument('--outdir', '-o', help='Output directory (default ./classified_output)', default='./classified_output')
    p.add_argument('--decode-vmess', action='store_true', help='Attempt to decode vmess base64 payloads into JSON')
    p.add_argument('--tag', help='Replacement tag (default \"3λΞĐ\")', default='3λΞĐ')
    args = p.parse_args()

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

    if not urls and not args.infile:
        urls = DEFAULT_URLS.copy()

    # ensure unique and maintain order
    seen = set()
    uniq_urls = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            uniq_urls.append(u)

    print(f"[+] Using {len(uniq_urls)} URL(s). Infile: {args.infile is not None}")

    os.makedirs(args.outdir, exist_ok=True)

    # use sets for deduplication
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

    # process local infile first (if provided)
    if args.infile:
        try:
            with open(args.infile, 'r', encoding='utf-8') as fh:
                text = fh.read()
            process_text_and_classify(text, args.tag, classified)
        except Exception as e:
            print(f"[!] Failed to read infile '{args.infile}': {e}")

    # fetch each URL and process immediately to avoid huge memory spikes
    for u in uniq_urls:
        try:
            txt = fetch_url(u)
            process_text_and_classify(txt, args.tag, classified)
        except Exception as e:
            print(f"[!] Warning: {e}")
            continue

    # write outputs (convert sets to sorted lists for reproducibility)
    save_list_to_file(sorted(classified['vmess']), os.path.join(args.outdir, 'vmess.txt'))
    save_list_to_file(sorted(classified['vless']), os.path.join(args.outdir, 'vless.txt'))
    save_list_to_file(sorted(classified['vless_invalid']), os.path.join(args.outdir, 'vless_invalid.txt'))
    save_list_to_file(sorted(classified['trojan']), os.path.join(args.outdir, 'trojan.txt'))
    save_list_to_file(sorted(classified['ss']), os.path.join(args.outdir, 'shadowsocks.txt'))
    save_list_to_file(sorted(classified['socks']), os.path.join(args.outdir, 'socks.txt'))
    save_list_to_file(sorted(classified['hysteria2']), os.path.join(args.outdir, 'hysteria2.txt'))
    save_list_to_file(sorted(classified['hysteria']), os.path.join(args.outdir, 'hysteria.txt'))
    save_list_to_file(sorted(classified['other']), os.path.join(args.outdir, 'other.txt'))

    # optionally decode vmess entries
    if args.decode_vmess:
        decoded = []
        for u in classified['vmess']:
            if isinstance(u, str) and u.lower().startswith('vmess://'):
                j = decode_vmess_base64(u)
                if j:
                    # normalize ps/name inside decoded vmess JSON
                    j = normalize_tag_in_json_obj(j, args.tag)
                    decoded.append(j)
        if decoded:
            path = os.path.join(args.outdir, 'vmess_decoded.json')
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(decoded, f, ensure_ascii=False, indent=2)
            print(f"[+] vmess decoded to: {path} ({len(decoded)})")
        else:
            print('[!] No vmess decodable found or all were miscellaneous.')

    print('\n=== SUMMARY ===')
    for k in ['vmess', 'vless', 'vless_invalid', 'trojan', 'ss', 'socks', 'hysteria2', 'hysteria', 'other']:
        print(f"{k:15s}: {len(classified[k])}")
    print(f"\nOutput directory: {os.path.abspath(args.outdir)}")
    print('Done.')


if __name__ == '__main__':
    main()
