import base64
import json
from pathlib import Path

import pytest
import yaml

from aggregator.outputs import render_clash_provider
from aggregator.parsing import (
    ParseError,
    deduplicate_proxies,
    filter_proxies,
    normalize_proxies,
    parse_source_payload,
    parse_source_payload_with_drops,
    parse_uri,
)
from aggregator.pipeline import SourceResult, _source_authorized, build_manifest


def test_base64_subscription_is_decoded_and_parsed() -> None:
    raw = "http://node.example.invalid:8080#sample\n"
    payload = base64.b64encode(raw.encode()).decode()

    proxies = parse_source_payload(payload)

    assert proxies[0]["type"] == "http"
    assert proxies[0]["server"] == "node.example.invalid"


def test_uri_parser_reads_scheme_host_port_and_name() -> None:
    proxy = parse_uri("http://node.example.invalid:8080#sample")

    assert proxy == {
        "name": "sample",
        "type": "http",
        "server": "node.example.invalid",
        "port": 8080,
    }


def test_clash_yaml_is_parsed_and_exported() -> None:
    payload = """\
proxies:
  - name: sample
    type: http
    server: node.example.invalid
    port: 8080
"""

    proxies = parse_source_payload(payload, format_hint="yaml")
    output = render_clash_provider(proxies)

    assert proxies[0]["name"] == "sample"
    assert "proxies:" in output
    assert "node.example.invalid" in output


def test_clash_yaml_format_alias_is_parsed() -> None:
    payload = """\
proxies:
  - name: hysteria-sample
    type: hysteria
    server: node.example.invalid
    port: 443
    auth-str: secret
"""

    proxies = parse_source_payload(payload, format_hint="clash-yaml")

    assert proxies[0]["type"] == "hysteria"
    assert proxies[0]["auth-str"] == "secret"


def test_clash_json_is_parsed() -> None:
    payload = '{"proxies":[{"name":"json-sample","type":"http","server":"node.example.invalid","port":8080}]}'

    proxies = parse_source_payload(payload, format_hint="json")

    assert proxies == [
        {
            "name": "json-sample",
            "type": "http",
            "server": "node.example.invalid",
            "port": 8080,
        }
    ]


def test_normalize_and_deduplicate_use_endpoint_identity() -> None:
    proxies = normalize_proxies(
        [
            {
                "name": "first",
                "type": "http",
                "server": "node.example.invalid",
                "port": "8080",
            },
            {
                "name": "duplicate",
                "type": "http",
                "server": "node.example.invalid",
                "port": 8080,
            },
            {
                "name": "other",
                "type": "http",
                "server": "other.example.invalid",
                "port": 8080,
            },
        ]
    )

    assert len(deduplicate_proxies(proxies)) == 2
    assert proxies[0]["port"] == 8080


def test_filters_remove_denied_protocols_and_low_scores() -> None:
    proxies = normalize_proxies(
        [
            {
                "name": "http-node",
                "type": "http",
                "server": "a.example.invalid",
                "port": 80,
            },
            {
                "name": "socks-node",
                "type": "socks5",
                "server": "b.example.invalid",
                "port": 1080,
            },
        ]
    )

    result = filter_proxies(proxies, allow_protocols=["http"], min_quality_score=60)

    assert [proxy["name"] for proxy in result] == ["http-node"]


def test_unsupported_uri_is_rejected() -> None:
    with pytest.raises(ParseError):
        parse_uri("ftp://node.example.invalid:21")


def test_singbox_outbounds_are_parsed_and_unsupported_skipped() -> None:
    payload = json.dumps(
        {
            "outbounds": [
                {
                    "type": "vless",
                    "tag": "node-vless",
                    "server": "node.example.invalid",
                    "server_port": 443,
                    "uuid": "11111111-2222-3333-4444-555555555555",
                    "tls": {
                        "enabled": True,
                        "server_name": "example.invalid",
                        "insecure": True,
                    },
                    "transport": {
                        "type": "ws",
                        "path": "/ws",
                        "headers": {"Host": "example.invalid"},
                    },
                },
                {
                    "type": "trojan",
                    "tag": "node-trojan",
                    "server": "trojan.example.invalid",
                    "server_port": 8443,
                    "password": "secret",
                    "tls": {"enabled": True},
                },
                {"type": "direct", "tag": "direct"},
            ]
        }
    )

    proxies, drops = parse_source_payload_with_drops(payload, "json")

    assert [proxy["type"] for proxy in proxies] == ["vless", "trojan"]
    vless, trojan = proxies
    assert vless["name"] == "node-vless"
    assert vless["server"] == "node.example.invalid"
    assert vless["port"] == 443
    assert vless["uuid"] == "11111111-2222-3333-4444-555555555555"
    assert vless["tls"] is True
    assert vless["sni"] == "example.invalid"
    assert vless["skip-cert-verify"] is True
    assert vless["network"] == "ws"
    assert vless["ws-opts"] == {"path": "/ws", "headers": {"Host": "example.invalid"}}
    assert trojan["name"] == "node-trojan"
    assert trojan["password"] == "secret"
    assert trojan["tls"] is True
    assert drops == {"unsupported_outbound": 1}


def test_hysteria_v1_uri_is_parsed() -> None:
    proxy = parse_uri(
        "hysteria://node.example.invalid:36712"
        "?auth=tok123&peer=bing.com&insecure=1&upmbps=11&downmbps=55"
        "&protocol=udp&alpn=h3#hy-sample"
    )

    assert proxy == {
        "name": "hy-sample",
        "type": "hysteria",
        "server": "node.example.invalid",
        "port": 36712,
        "auth-str": "tok123",
        "sni": "bing.com",
        "protocol": "udp",
        "up": "11 Mbps",
        "down": "55 Mbps",
        "alpn": ["h3"],
        "skip-cert-verify": True,
    }


def test_ssr_uri_is_parsed() -> None:
    def encode(value: str) -> str:
        return base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")

    inner = (
        "node.example.invalid:8388:auth_aes128_md5:aes-256-cfb:plain:"
        f"{encode('secret')}/?obfsparam={encode('abc')}"
        f"&protoparam={encode('def')}&remarks={encode('ssr-sample')}"
    )
    payload = base64.urlsafe_b64encode(inner.encode()).decode().rstrip("=")

    proxy = parse_uri(f"ssr://{payload}")

    assert proxy == {
        "name": "ssr-sample",
        "type": "ssr",
        "server": "node.example.invalid",
        "port": 8388,
        "protocol": "auth_aes128_md5",
        "cipher": "aes-256-cfb",
        "password": "secret",
        "obfs": "plain",
        "obfs-param": "abc",
        "protocol-param": "def",
    }


def test_sources_yaml_declares_boolean_authorized_flag() -> None:
    config_path = Path(__file__).resolve().parents[1] / "config" / "sources.yaml"
    document = yaml.safe_load(config_path.read_text(encoding="utf-8"))

    entries = document["sources"]["public"]
    assert entries
    for source in entries:
        assert isinstance(source.get("authorized"), bool), source["id"]
        if source.get("kind") == "file":
            assert source["authorized"] is True, source["id"]
        else:
            expected = (
                bool(source.get("enabled"))
                and bool(source.get("publish"))
                and not bool(source.get("requires_review"))
            )
            assert source["authorized"] is expected, source["id"]


def test_authorized_flag_derivation_and_manifest_serialization() -> None:
    assert (
        _source_authorized({"enabled": True, "publish": True, "requires_review": False})
        is True
    )
    assert (
        _source_authorized(
            {
                "authorized": False,
                "enabled": True,
                "publish": True,
                "requires_review": False,
            }
        )
        is False
    )

    results = [
        SourceResult(id="approved", kind="public", status="ok", authorized=True),
        SourceResult(id="blocked", kind="public", status="disabled", authorized=False),
    ]
    manifest = build_manifest(
        status="success",
        generated_at="2026-01-01T00:00:00Z",
        proxies=[],
        source_results=results,
        artifacts={},
    )

    sources = {entry["id"]: entry for entry in manifest["sources"]}
    assert sources["approved"]["authorized"] is True
    assert sources["blocked"]["authorized"] is False


def test_uri_line_with_invalid_port_is_dropped_per_line() -> None:
    payload = (
        "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:notaport\n"
        "http://node.example.invalid:8080#sample"
    )

    proxies, drops = parse_source_payload_with_drops(payload, "uri")

    assert [proxy["server"] for proxy in proxies] == ["node.example.invalid"]
    assert drops.get("invalid_port") == 1


def test_control_characters_in_yaml_are_sanitized_not_fatal() -> None:
    payload = (
        "proxies:\n"
        '  - {"name":"ok-one","type":"vmess","server":"10.0.0.1","port":100,"cipher":"auto"}\n'
        '  - {"name":"bad-\x9fchar","type":"vmess","server":"10.0.0.2","port":101,"cipher":"auto"}\n'
    )

    proxies, drops = parse_source_payload_with_drops(payload, "clash-yaml")

    types = sorted(proxy["server"] for proxy in proxies)
    assert types == ["10.0.0.1", "10.0.0.2"]
    assert drops == {}
