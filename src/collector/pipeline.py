"""
Core processing pipeline — classify, validate, and collect configs.
"""

from __future__ import annotations

import json
import logging
from typing import Dict, IO, List, Set
from urllib.parse import urlsplit

from .models import ConfigEntry
from .network import live_check
from .parsers import (
    classify_uri_scheme,
    decode_vmess_base64,
    encode_vmess_json_to_uri,
    find_json_configs,
    find_uris,
    normalize_tag_in_json_obj,
    normalize_tag_in_uri,
)
from .security import check_security

log = logging.getLogger(__name__)


def process_text(
    text: str,
    tag: str,
    classified: Dict[str, List[ConfigEntry]],
    seen: Dict[str, Set[str]],
    jsonl_fh: IO[str],
    only_secure: bool = False,
    do_live_check: bool = False,
) -> None:
    """
    Parse raw text, extract proxy configs, classify and deduplicate them.

    Args:
        text: raw subscription/config text.
        tag: tag string to inject into config names.
        classified: dict of protocol → list of ConfigEntry (mutated in place).
        seen: dict of protocol → set of URIs already seen (mutated in place).
        jsonl_fh: open file handle for JSONL output.
        only_secure: if True, only write secure entries to JSONL.
        do_live_check: if True, perform TLS live-checks on secure configs.
    """

    def _add(entry: ConfigEntry) -> None:
        # Route to correct protocol bucket (fallback to "other")
        proto = entry.protocol if entry.protocol in classified else "other"
        entry.protocol = proto

        # Deduplicate
        if entry.uri in seen[proto]:
            return

        seen[proto].add(entry.uri)
        classified[proto].append(entry)

        if not only_secure or entry.secure:
            jsonl_fh.write(json.dumps(entry.to_dict(), ensure_ascii=False) + "\n")

    # ── Process URI-style configs ──
    for uri in find_uris(text):
        scheme = classify_uri_scheme(uri)

        if scheme == "vmess":
            vmess_obj = decode_vmess_base64(uri)
            if not vmess_obj:
                continue
            vmess_obj = normalize_tag_in_json_obj(vmess_obj, tag)
            normalized = encode_vmess_json_to_uri(vmess_obj)
            secure, reasons = check_security("vmess", vmess_obj)

        elif scheme == "vless":
            normalized = normalize_tag_in_uri(uri, tag)
            secure, reasons = check_security("vless", normalized)

        elif scheme == "trojan":
            normalized = normalize_tag_in_uri(uri, tag)
            secure, reasons = check_security("trojan", normalized)

        elif scheme == "ss":
            normalized = normalize_tag_in_uri(uri, tag)
            secure, reasons = check_security("ss", normalized)

        elif scheme in ("socks", "hysteria", "hysteria2"):
            normalized = normalize_tag_in_uri(uri, tag)
            secure, reasons = False, ["no-crypto-or-unsupported"]

        else:
            scheme = "other"
            normalized = normalize_tag_in_uri(uri, tag)
            secure, reasons = False, ["unsupported"]

        # Optional live TLS check
        if do_live_check and secure:
            parts = urlsplit(normalized)
            hostport = parts.netloc.split("@")[-1]

            if ":" in hostport:
                host, port_str = hostport.rsplit(":", 1)
                try:
                    ok, msg = live_check(host, int(port_str))
                    secure = secure and ok
                    reasons.append(f"live:{msg}")
                except Exception as exc:
                    log.debug("Live check failed: %s", exc)

        _add(ConfigEntry(scheme, normalized, secure, reasons, uri))

    # ── Process standalone JSON objects (e.g. VMess blobs) ──
    for obj in find_json_configs(text):
        try:
            vmess_obj = normalize_tag_in_json_obj(obj, tag)
            secure, reasons = check_security("vmess", vmess_obj)
            uri = encode_vmess_json_to_uri(vmess_obj)
            _add(ConfigEntry("vmess", uri, secure, reasons, json.dumps(obj)))
        except Exception as exc:
            log.debug("JSON config skipped: %s", exc)
