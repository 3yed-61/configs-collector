"""
Unit tests for collector.security module.
"""

import pytest
from collector.security import (
    is_shadowsocks_secure,
    is_vless_secure,
    is_trojan_secure,
    is_vmess_secure,
    check_security,
)


class TestShadowsocksSecurity:
    def test_secure_cipher(self):
        uri = "ss://chacha20-ietf-poly1305:password@host:8388#tag"
        secure, reasons = is_shadowsocks_secure(uri)
        assert secure is True
        assert "secure-cipher:chacha20-ietf-poly1305" in reasons

    def test_weak_cipher(self):
        uri = "ss://rc4-md5:password@host:8388#tag"
        secure, reasons = is_shadowsocks_secure(uri)
        assert secure is False
        assert "weak-cipher:rc4-md5" in reasons

    def test_unknown_cipher(self):
        uri = "ss://unknown-method:password@host:8388#tag"
        secure, reasons = is_shadowsocks_secure(uri)
        assert secure is False


class TestVlessSecurity:
    def test_tls_secure(self):
        uri = "vless://uuid@host:443?security=tls&type=tcp#tag"
        secure, reasons = is_vless_secure(uri)
        assert secure is True
        assert "tls-or-reality" in reasons

    def test_reality_secure(self):
        uri = "vless://uuid@host:443?security=reality&type=tcp#tag"
        secure, reasons = is_vless_secure(uri)
        assert secure is True

    def test_insecure_flag(self):
        uri = "vless://uuid@host:443?insecure=1&security=tls#tag"
        secure, reasons = is_vless_secure(uri)
        assert secure is False
        assert "insecure=1" in reasons

    def test_no_tls(self):
        uri = "vless://uuid@host:443?type=tcp#tag"
        secure, reasons = is_vless_secure(uri)
        assert secure is False


class TestTrojanSecurity:
    def test_default_secure(self):
        uri = "trojan://password@host:443#tag"
        secure, reasons = is_trojan_secure(uri)
        assert secure is True
        assert "tls-based" in reasons

    def test_insecure_flag(self):
        uri = "trojan://password@host:443?insecure=1#tag"
        secure, reasons = is_trojan_secure(uri)
        assert secure is False


class TestVmessSecurity:
    def test_tls_secure(self):
        obj = {"tls": "tls", "sni": "example.com"}
        secure, reasons = is_vmess_secure(obj)
        assert secure is True

    def test_allow_insecure(self):
        obj = {"tls": "tls", "allowInsecure": True}
        secure, reasons = is_vmess_secure(obj)
        assert secure is False

    def test_no_tls(self):
        obj = {"add": "host", "port": 443}
        secure, reasons = is_vmess_secure(obj)
        assert secure is False


class TestCheckSecurity:
    def test_dispatch_ss(self):
        secure, _ = check_security("ss", "ss://chacha20-ietf-poly1305:pass@h:8388")
        assert secure is True

    def test_dispatch_unknown(self):
        secure, reasons = check_security("unknown", "data")
        assert secure is False
        assert "unknown-protocol" in reasons
