"""
Security checks for various proxy protocols.
"""

from __future__ import annotations

import logging
from typing import Tuple, List

from .config import SECURE_SS_CIPHERS, WEAK_SS_CIPHERS
from .parsers import parse_query

log = logging.getLogger(__name__)

SecurityResult = Tuple[bool, List[str]]


def is_shadowsocks_secure(uri: str) -> SecurityResult:
    """Check whether a Shadowsocks URI uses a secure cipher."""
    try:
        blob = uri.split("://", 1)[1].split("#")[0].split("?")[0]

        if "@" in blob and ":" in blob:
            method = blob.split("@", 1)[0].split(":", 1)[0].lower()

            if method in WEAK_SS_CIPHERS:
                return False, [f"weak-cipher:{method}"]
            if method in SECURE_SS_CIPHERS:
                return True, [f"secure-cipher:{method}"]

            return False, [f"cipher:{method}"]
    except Exception as exc:
        log.debug("SS parse error: %s", exc)

    return False, ["unknown-ss-method"]


def is_vless_secure(uri: str) -> SecurityResult:
    """Check whether a VLESS URI uses TLS or Reality."""
    query = parse_query(uri)
    reasons: list[str] = []

    if query.get("insecure", ["0"])[0] == "1":
        return False, ["insecure=1"]

    lower_uri = uri.lower()
    if "tls" in lower_uri or "reality" in lower_uri:
        reasons.append("tls-or-reality")

    return bool(reasons), reasons or ["no-tls-or-reality"]


def is_trojan_secure(uri: str) -> SecurityResult:
    """Check whether a Trojan URI is secure (TLS by default)."""
    if parse_query(uri).get("insecure", ["0"])[0] == "1":
        return False, ["insecure=1"]
    return True, ["tls-based"]


def is_vmess_secure(obj: dict) -> SecurityResult:
    """Check whether a VMess JSON config is secure."""
    if obj.get("allowInsecure"):
        return False, ["allowInsecure"]

    reasons: list[str] = []
    if obj.get("tls"):
        reasons.append("tls")
    if obj.get("sni"):
        reasons.append("sni")

    return bool(reasons), reasons or ["no-tls"]


def check_security(protocol: str, data) -> SecurityResult:
    """
    Dispatch security check based on protocol.

    Args:
        protocol: one of 'ss', 'vless', 'trojan', 'vmess'.
        data: the URI string or parsed JSON dict.

    Returns:
        (is_secure, reasons) tuple.
    """
    dispatch = {
        "ss": is_shadowsocks_secure,
        "vless": is_vless_secure,
        "trojan": is_trojan_secure,
        "vmess": is_vmess_secure,
    }

    checker = dispatch.get(protocol)
    if checker:
        return checker(data)

    return False, ["unknown-protocol"]
