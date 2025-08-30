import os
import re
import argparse
import json
import base64
from urllib.parse import unquote
from typing import List

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

# include hysteria2 in recognized schemes
URI_RE = re.compile(
    r'\b(?:vmess|vless|trojan|ss|socks5|socks|hysteria2)://[^\s\'"]+',
    re.IGNORECASE
)
JSON_OBJ_RE = re.compile(r'\{.*?\}', re.DOTALL)

# ======================
# 🔹 تابع نرمال‌سازی تگ
# ======================
def normalize_tag(config: str, new_tag="3λΞĐ") -> str:
    """پاک کردن نام قدیمی و اضافه کردن تگ جدید (پرچم یا پسوند نگه داشته می‌شود)."""
    if "#" not in config:
        return f"{config}#{new_tag}"

    before, after = config.split("#", 1)
    after = after.strip()

    # بررسی جداکننده‌های رایج
    for d in ["::", "-", "_"]:
        if d in after:
            parts = after.split(d, 1)
            suffix = parts[1].strip() if len(parts) > 1 else ""
            if suffix:
                return f"{before}#{new_tag}{d}{suffix}"
            return f"{before}#{new_tag}"

    # بررسی پرچم (دو ایموجی یونیکد پشت هم)
    match = re.search(r"([\U0001F1E6-\U0001F1FF]{2})", after)
    if match:
        flag = match.group(1)
        return f"{before}#{new_tag}::{flag}"

    # اگر هیچ چیزی نبود
    return f"{before}#{new_tag}"
# ======================


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
    """Return list of URIs found by regex."""
    found = URI_RE.findall(text)
    return [u.strip() for u in found]


def find_json_configs(text: str) -> List[dict]:
    """Find JSON blocks and return list of dicts that can be parsed."""
    results = []
    for m in JSON_OBJ_RE.finditer(text):
        s = m.group(0)
        try:
            j = json.loads(s)
            results.append(j)
        except Exception:
            continue
    return results


def classify_uri(uri: str) -> str:
    """Return the scheme portion (lowercased) of a URI."""
    scheme = uri.split("://", 1)[0].lower()
    return scheme


def vless_valid(uri: str) -> bool:
    """Check if vless contains tls or reality (in query or uri)."""
    low = uri.lower()
    if "tls" in low or "reality" in low:
        return True
    un = unquote(uri).lower()
    if "tls" in un or "reality" in un:
        return True
    return False


def decode_vmess_base64(uri: str):
    """If vmess://<base64>, try to decode and return JSON dict, otherwise None."""
    try:
        payload = uri.split("://", 1)[1]
        payload = payload.split('#')[0].strip()
        b = base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4))
        j = json.loads(b.decode('utf-8', errors='ignore'))
        return j
    except Exception:
        return None


def save_list_to_file(lst: List[str], path: str):
    """Write list to file (each entry in its own line)."""
    with open(path, "w", encoding="utf-8") as f:
        for item in lst:
            if isinstance(item, (dict, list)):
                f.write(json.dumps(item, ensure_ascii=False) + "\n")
            else:
                f.write(str(item) + "\n")
    print(f"[+] Written: {path} ({len(lst)})")


def gather_urls_from_args(args) -> List[str]:
    urls = []
    if args.url:
        urls.extend(args.url)
    if args.urls_file:
        try:
            with open(args.urls_file, "r", encoding="utf-8") as fh:
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
    p = argparse.ArgumentParser(description="Classify subscription configs into separate files (hysteria2 supported).")
    p.add_argument("--url", "-u", action="append")
    p.add_argument("--urls-file", help="Path to file with URLs, one per line")
    p.add_argument("--outdir", "-o", help="Output directory (default ./classified_output)", default="./classified_output")
    p.add_argument("--decode-vmess", action="store_true")
    args = p.parse_args()

    urls = gather_urls_from_args(args)
    print(f"[+] Using {len(urls)} URL(s).")

    os.makedirs(args.outdir, exist_ok=True)

    combined_text_parts = []
    for u in urls:
        try:
            txt = fetch_url(u)
            combined_text_parts.append(txt)
        except Exception as e:
            print(f"[!] Warning: {e}")
            continue

    if not combined_text_parts:
        print("[!] No content downloaded from any URL. Exiting.")
        return

    combined_text = "\n".join(combined_text_parts)

    uris = find_uris(combined_text)
    print(f"[+] Number of URIs found by regex: {len(uris)}")

    json_blocks = find_json_configs(combined_text)
    print(f"[+] Number of JSON blocks parsable: {len(json_blocks)}")

    classified = {
        "vmess": [],
        "vless": [],
        "vless_invalid": [],
        "trojan": [],
        "ss": [],
        "socks": [],
        "hysteria": [],
        "other": []
    }

    for uri in uris:
        uri = normalize_tag(uri)   # 🔹 اینجا تگ‌ها اصلاح میشن
        scheme = classify_uri(uri)
        if scheme == "vmess":
            classified["vmess"].append(uri)
        elif scheme == "vless":
            if vless_valid(uri):
                classified["vless"].append(uri)
            else:
                classified["vless_invalid"].append(uri)
        elif scheme == "trojan":
            classified["trojan"].append(uri)
        elif scheme == "ss":
            classified["ss"].append(uri)
        elif scheme in ("socks5", "socks"):
            classified["socks"].append(uri)
        elif scheme in ("hysteria2", "hysteria"):
            classified["hysteria"].append(uri)
        else:
            classified["other"].append(uri)

    for jb in json_blocks:
        lowered_keys = {k.lower(): k for k in jb.keys()}
        js_text = json.dumps(jb, ensure_ascii=False)
        if any(k in lowered_keys for k in ("ps", "add", "port", "id", "aid", "net", "type", "v")):
            classified["vmess"].append(js_text)
        else:
            if "protocol" in jb and isinstance(jb["protocol"], str) and jb["protocol"].lower() == "vless":
                sj = js_text
                if "tls" in sj.lower() or "reality" in sj.lower():
                    classified["vless"].append(sj)
                else:
                    classified["vless_invalid"].append(sj)
            else:
                classified["other"].append(js_text)

    save_list_to_file(classified["vmess"], os.path.join(args.outdir, "vmess.txt"))
    save_list_to_file(classified["vless"], os.path.join(args.outdir, "vless.txt"))
    save_list_to_file(classified["vless_invalid"], os.path.join(args.outdir, "vless_invalid.txt"))
    save_list_to_file(classified["trojan"], os.path.join(args.outdir, "trojan.txt"))
    save_list_to_file(classified["ss"], os.path.join(args.outdir, "shadowsocks.txt"))
    save_list_to_file(classified["socks"], os.path.join(args.outdir, "socks.txt"))
    save_list_to_file(classified["hysteria"], os.path.join(args.outdir, "hysteria.txt"))
    save_list_to_file(classified["other"], os.path.join(args.outdir, "other.txt"))

    if args.decode_vmess:
        decoded = []
        for u in classified["vmess"]:
            if isinstance(u, str) and u.lower().startswith("vmess://"):
                j = decode_vmess_base64(u)
                if j:
                    decoded.append(j)
        if decoded:
            path = os.path.join(args.outdir, "vmess_decoded.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(decoded, f, ensure_ascii=False, indent=2)
            print(f"[+] vmess decoded to: {path} ({len(decoded)})")
        else:
            print("[!] No vmess decodable found or all were miscellaneous.")

    print("\n=== SUMMARY ===")
    for k in ["vmess", "vless", "vless_invalid", "trojan", "ss", "socks", "hysteria", "other"]:
        print(f"{k:15s}: {len(classified[k])}")
    print(f"\nOutput directory: {os.path.abspath(args.outdir)}")
    print("Done.")


if __name__ == "__main__":
    main()
