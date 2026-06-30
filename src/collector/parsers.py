"""
URI and JSON config parsing, tag normalization, VMess encoding/decoding.
"""

from __future__ import annotations

import base64
import json
import logging
from typing import List
from urllib.parse import parse_qs, quote, unquote, urlsplit

from .config import FLAG_RE, SCHEME_MAP, URI_RE

log = logging.getLogger(__name__)

# ────────────────────────── URI Extraction ──────────────────────────


def find_uris(text: str) -> List[str]:
    """Extract all proxy URIs from raw text."""
    return [u.strip() for u in URI_RE.findall(text)]


def classify_uri_scheme(uri: str) -> str:
    """Return the normalized protocol scheme for a URI."""
    raw = uri.split("://", 1)[0].lower()
    return SCHEME_MAP.get(raw, raw)


def parse_query(uri: str) -> dict:
    """Parse the query string of a URI into a dict."""
    try:
        return {k: v for k, v in parse_qs(urlsplit(uri).query).items()}
    except ValueError:
        # Fallback for IPv6 URLs that urlsplit cannot handle
        parts = uri.split("?", 1)
        if len(parts) < 2:
            return {}
        query_part = parts[1].split("#", 1)[0]
        return {k: v for k, v in parse_qs(query_part).items()}


# ────────────────────────── JSON Extraction ──────────────────────────


def find_json_configs(text: str) -> List[dict]:
    """Extract standalone JSON objects (e.g. VMess blobs) from text."""
    results: list[dict] = []
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
            except (json.JSONDecodeError, ValueError):
                pass
        idx += 1

    return results


# ────────────────────────── Tag Normalization ──────────────────────────


def normalize_fragment(fragment: str, new_tag: str) -> str:
    """
    Normalize the fragment (tag) portion of a URI.

    Keeps only the new_tag and any country flag emoji found in the
    original fragment.  All other text (channel names, server names,
    etc.) is discarded.
    """
    if not fragment:
        return new_tag

    frag = fragment.strip()

    # Extract country flag emoji (regional indicator pairs like 🇺🇸 🇫🇮)
    match = FLAG_RE.search(frag)
    if match:
        return f"{new_tag}::{match.group(1)}"

    return new_tag


def normalize_tag_in_uri(uri: str, new_tag: str) -> str:
    """Replace or insert the tag in a URI fragment."""
    if "#" not in uri:
        return f"{uri}#{quote(new_tag, safe='')}"

    main, frag = uri.split("#", 1)
    decoded = unquote(frag)
    new_frag = normalize_fragment(decoded, new_tag)
    return f"{main}#{quote(new_frag, safe='')}"


def normalize_tag_in_json_obj(obj: dict, new_tag: str) -> dict:
    """Normalize tag fields in a JSON config object."""
    result = dict(obj)

    for key in ("ps", "remarks", "name"):
        if key in result and isinstance(result[key], str):
            decoded = unquote(result[key])
            result[key] = normalize_fragment(decoded, new_tag)

    return result


# ────────────────────────── VMess Base64 ──────────────────────────


def decode_vmess_base64(uri: str) -> dict | None:
    """Decode a vmess:// URI's base64 payload into a dict."""
    try:
        payload = uri.split("://", 1)[1].split("#", 1)[0]
        payload = payload.replace("-", "+").replace("_", "/")
        padded = payload + "=" * (-len(payload) % 4)

        raw = base64.b64decode(padded, validate=False)
        return json.loads(raw.decode("utf-8", errors="strict"))
    except Exception as exc:
        log.debug("VMess decode failed: %s", exc)
        return None


def encode_vmess_json_to_uri(obj: dict) -> str:
    """Encode a VMess JSON config back to a vmess:// URI."""
    raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    encoded = base64.b64encode(raw.encode()).decode().rstrip("=")
    return f"vmess://{encoded}"
