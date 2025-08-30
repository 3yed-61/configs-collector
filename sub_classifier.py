import os
import re
import argparse
import json
import base64
from urllib.parse import unquote
try:
    import requests
except Exception:
    requests = None
    import urllib.request

DEFAULT_URL = "https://raw.githubusercontent.com/hamedp-71/Sub_Checker_Creator/refs/heads/main/final.txt#xsfilternet"


URI_RE = re.compile(r'\b(?:vmess|vless|trojan|ss|socks5|socks)://[^\s\'"]+', re.IGNORECASE)

JSON_OBJ_RE = re.compile(r'\{.*?\}', re.DOTALL)

def fetch_url(url):
    print(f"[+] دانلود از: {url}")
    if requests:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        return resp.text
    else:
        with urllib.request.urlopen(url, timeout=30) as r:
            return r.read().decode('utf-8', errors='ignore')

def find_uris(text):
    """برگرداندن لیست URIهای پیدا شده توسط regex"""
    found = URI_RE.findall(text)
    return [u.strip() for u in found]

def find_json_configs(text):
    """کشف بلاک‌های JSON و بازگرداندن لیست dictهایی که قابل پارس باشند"""
    results = []
    for m in JSON_OBJ_RE.finditer(text):
        s = m.group(0)
        try:
            j = json.loads(s)
            results.append(j)
        except Exception:
            continue
    return results

def classify_uri(uri):
    scheme = uri.split("://", 1)[0].lower()
    return scheme

def vless_valid(uri):
    """چک می‌کنیم آیا vless شامل tls یا reality هست (در query یا خود uri)"""
    low = uri.lower()
    if "tls" in low or "reality" in low:
        return True
   
    un = unquote(uri).lower()
    if "tls" in un or "reality" in un:
        return True
    return False

def decode_vmess_base64(uri):
    """اگر vmess://<base64> باشد، تلاش می‌کند دِکُد کند و JSON برگرداند"""
    try:
        payload = uri.split("://",1)[1]
        
        payload = payload.split('#')[0].strip()
       
        b = base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4))
        j = json.loads(b.decode('utf-8', errors='ignore'))
        return j
    except Exception:
        return None

def save_list_to_file(lst, path):
    with open(path, "w", encoding="utf-8") as f:
        for item in lst:
            f.write(item + "\n")
    print(f"[+] نوشته شد: {path} ({len(lst)})")

def main():
    p = argparse.ArgumentParser(description="دسته‌بندی کانفیگ‌های ساب به فایل‌های جدا")
    p.add_argument("--url", "-u", help="لینک ساب/raw (پیش‌فرض لینک شما)", default=DEFAULT_URL)
    p.add_argument("--outdir", "-o", help="پوشه خروجی (پیش‌فرض ./classified_output)", default="./classified_output")
    p.add_argument("--decode-vmess", action="store_true", help="در صورت امکان vmess://<base64> را دِکُد کرده و فایل vmess_decoded.json بسازد")
    args = p.parse_args()

    text = fetch_url(args.url)
    os.makedirs(args.outdir, exist_ok=True)

  
    uris = find_uris(text)
    print(f"[+] تعداد URI پیدا شده توسط regex: {len(uris)}")

   
    json_blocks = find_json_configs(text)
    print(f"[+] تعداد بلاک JSON قابل پارس: {len(json_blocks)}")

    classified = {
        "vmess": [],
        "vless": [],
        "vless_invalid": [],
        "trojan": [],
        "ss": [],
        "socks": [],
        "other": []
    }

    for uri in uris:
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
        else:
            classified["other"].append(uri)

    
    for jb in json_blocks:
        
        lowered_keys = {k.lower(): k for k in jb.keys()}
        js_text = json.dumps(jb, ensure_ascii=False)
        
        if any(k in lowered_keys for k in ("ps","add","port","id","aid","net","type","v")):
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
            print(f"[+] vmess دِکُد شده در: {path} ({len(decoded)})")
        else:
            print("[!] vmess قابل دِکُد پیدا نشد یا همه متفرقه بودند.")

    # چاپ خلاصه
    print("\n=== SUMMARY ===")
    for k in ["vmess","vless","vless_invalid","trojan","ss","socks","other"]:
        print(f"{k:15s}: {len(classified[k])}")
    print(f"\nخروجی در پوشه: {os.path.abspath(args.outdir)}")
    print("پایان.")

if __name__ == "__main__":
    main()
