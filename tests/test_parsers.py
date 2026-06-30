"""
Unit tests for collector.parsers module.
"""

import json
import base64
import pytest
from collector.parsers import (
    find_uris,
    classify_uri_scheme,
    parse_query,
    find_json_configs,
    normalize_fragment,
    normalize_tag_in_uri,
    normalize_tag_in_json_obj,
    decode_vmess_base64,
    encode_vmess_json_to_uri,
)


class TestFindUris:
    def test_extracts_vless(self):
        text = "some text vless://uuid@host:443?type=tcp#tag more text"
        result = find_uris(text)
        assert len(result) == 1
        assert result[0].startswith("vless://")

    def test_extracts_multiple_protocols(self):
        text = (
            "vmess://abc123 "
            "trojan://pass@host:443 "
            "ss://method:pass@host:8388 "
            "socks5://user:pass@host:1080"
        )
        result = find_uris(text)
        assert len(result) == 4

    def test_empty_text(self):
        assert find_uris("") == []

    def test_no_match(self):
        assert find_uris("just some random text without URIs") == []

    def test_hysteria_protocols(self):
        text = "hysteria://host:443 hysteria2://host:443"
        result = find_uris(text)
        assert len(result) == 2


class TestClassifyUriScheme:
    def test_basic_schemes(self):
        assert classify_uri_scheme("vless://test") == "vless"
        assert classify_uri_scheme("vmess://test") == "vmess"
        assert classify_uri_scheme("trojan://test") == "trojan"
        assert classify_uri_scheme("ss://test") == "ss"

    def test_socks5_maps_to_socks(self):
        assert classify_uri_scheme("socks5://test") == "socks"

    def test_socks_stays_socks(self):
        assert classify_uri_scheme("socks://test") == "socks"

    def test_case_insensitive(self):
        assert classify_uri_scheme("VLESS://test") == "vless"
        assert classify_uri_scheme("Vmess://test") == "vmess"


class TestParseQuery:
    def test_basic_query(self):
        uri = "vless://uuid@host:443?type=tcp&security=tls#tag"
        q = parse_query(uri)
        assert q["type"] == ["tcp"]
        assert q["security"] == ["tls"]

    def test_no_query(self):
        uri = "vless://uuid@host:443#tag"
        q = parse_query(uri)
        assert q == {}


class TestFindJsonConfigs:
    def test_finds_json_object(self):
        text = 'prefix {"v":"2","ps":"test"} suffix'
        result = find_json_configs(text)
        assert len(result) == 1
        assert result[0]["v"] == "2"

    def test_multiple_objects(self):
        text = '{"a":1} text {"b":2}'
        result = find_json_configs(text)
        assert len(result) == 2

    def test_no_json(self):
        assert find_json_configs("no json here") == []


class TestNormalizeFragment:
    def test_empty_fragment(self):
        assert normalize_fragment("", "MyTag") == "MyTag"

    def test_tag_already_present(self):
        assert normalize_fragment("MyTag::US", "MyTag") == "MyTag::US"

    def test_delimiter_replacement(self):
        result = normalize_fragment("OldTag::US", "NewTag")
        assert result == "NewTag::US"

    def test_flag_emoji(self):
        result = normalize_fragment("ServerName 🇺🇸", "MyTag")
        assert "🇺🇸" in result
        assert "MyTag" in result


class TestNormalizeTagInUri:
    def test_add_tag_no_fragment(self):
        uri = "vless://uuid@host:443?type=tcp"
        result = normalize_tag_in_uri(uri, "TestTag")
        assert "#TestTag" in result

    def test_replace_tag(self):
        uri = "vless://uuid@host:443#OldTag"
        result = normalize_tag_in_uri(uri, "NewTag")
        assert "NewTag" in result


class TestNormalizeTagInJsonObj:
    def test_normalize_ps_field(self):
        obj = {"ps": "OldName::US", "add": "host"}
        result = normalize_tag_in_json_obj(obj, "MyTag")
        assert "MyTag" in result["ps"]

    def test_no_tag_fields(self):
        obj = {"add": "host", "port": 443}
        result = normalize_tag_in_json_obj(obj, "MyTag")
        assert result == obj


class TestVmessEncoding:
    def _make_vmess_uri(self, obj: dict) -> str:
        raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
        encoded = base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")
        return f"vmess://{encoded}"

    def test_decode_encode_roundtrip(self):
        original = {"v": "2", "ps": "test", "add": "1.2.3.4", "port": 443}
        uri = self._make_vmess_uri(original)
        decoded = decode_vmess_base64(uri)
        assert decoded is not None
        assert decoded["add"] == "1.2.3.4"

        re_encoded = encode_vmess_json_to_uri(decoded)
        re_decoded = decode_vmess_base64(re_encoded)
        assert re_decoded == decoded

    def test_decode_invalid(self):
        assert decode_vmess_base64("vmess://not-valid-base64!!!") is None
