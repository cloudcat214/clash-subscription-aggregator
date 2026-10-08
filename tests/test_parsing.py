import base64

import pytest

from aggregator.outputs import render_clash_provider
from aggregator.parsing import (
    ParseError,
    deduplicate_proxies,
    filter_proxies,
    normalize_proxies,
    parse_source_payload,
    parse_uri,
)


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
