from __future__ import annotations

import io
import json
import socket
from pathlib import Path

import pytest
import yaml

from aggregator import fetch
from aggregator.fetch import FetchError
from aggregator.parsing import ParseError, normalize_proxy


def test_controlled_proxy_allowlist_is_exact_and_private_addresses_stay_blocked(
    monkeypatch,
) -> None:
    config = yaml.safe_load(
        (Path(__file__).parents[1] / "config" / "sources.yaml").read_text(
            encoding="utf-8"
        )
    )
    controlled_addresses = set(config["settings"]["controlled_proxy_addresses"])
    assert controlled_addresses == {"198.18.0.21", "198.18.0.37", "198.18.1.48"}

    def validate(address: str) -> tuple[str, str]:
        monkeypatch.setattr(
            fetch.socket,
            "getaddrinfo",
            lambda *args, **kwargs: [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443))
            ],
        )
        return fetch._validate_fetch_url(
            "https://raw.githubusercontent.com/owner/repo/file",
            allowed_hosts={"raw.githubusercontent.com"},
            trust_hosts={"raw.githubusercontent.com"},
            controlled_proxy_addresses=controlled_addresses,
        )

    assert validate("198.18.0.21") == (
        "raw.githubusercontent.com",
        "198.18.0.21",
    )
    assert validate("::ffff:198.18.0.21") == (
        "raw.githubusercontent.com",
        "198.18.0.21",
    )

    assert validate("198.18.0.22") == (
        "raw.githubusercontent.com",
        "198.18.0.22",
    )

    with pytest.raises(FetchError, match="private_source_address"):
        validate("10.0.0.1")


@pytest.mark.parametrize(
    ("hostname", "address"),
    [
        ("www.gitlabip.xyz", "198.18.0.236"),
        ("gitlab.com", "198.18.0.237"),
    ],
)
def test_configured_gitlab_hosts_allow_controlled_dns(
    monkeypatch, hostname, address
) -> None:
    config = yaml.safe_load(
        (Path(__file__).parents[1] / "config" / "sources.yaml").read_text(
            encoding="utf-8"
        )
    )
    settings = config["settings"]
    allowed_hosts = set(settings["allowed_source_hosts"])
    trust_hosts = set(settings["trust_hosts"])
    assert hostname in allowed_hosts
    assert hostname in trust_hosts

    monkeypatch.setattr(
        fetch.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443))
        ],
    )

    assert fetch._validate_fetch_url(
        f"https://{hostname}/source",
        allowed_hosts=allowed_hosts,
        trust_hosts=trust_hosts,
        controlled_proxy_addresses=set(settings["controlled_proxy_addresses"]),
    ) == (hostname, address)


def test_controlled_dns_exception_is_limited_to_trusted_host(monkeypatch) -> None:
    monkeypatch.setattr(
        fetch.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("198.18.1.48", 443))
        ],
    )

    assert fetch._validate_fetch_url(
        "https://raw.githubusercontent.com/owner/repo/file",
        allowed_hosts={"raw.githubusercontent.com"},
        trust_hosts={"raw.githubusercontent.com"},
        controlled_proxy_addresses={"198.18.1.48"},
    ) == ("raw.githubusercontent.com", "198.18.1.48")

    with pytest.raises(FetchError, match="source_host_not_allowlisted"):
        fetch._validate_fetch_url(
            "https://untrusted.example/file",
            allowed_hosts={"raw.githubusercontent.com"},
            trust_hosts={"raw.githubusercontent.com"},
            controlled_proxy_addresses={"198.18.1.48"},
        )


def test_controlled_dns_exception_accepts_configured_exact_drift_address(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        fetch.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("198.18.0.37", 443))
        ],
    )

    assert fetch._validate_fetch_url(
        "https://raw.githubusercontent.com/owner/repo/file",
        allowed_hosts={"raw.githubusercontent.com"},
        trust_hosts={"raw.githubusercontent.com"},
        controlled_proxy_addresses={"198.18.0.37"},
    ) == ("raw.githubusercontent.com", "198.18.0.37")


@pytest.mark.parametrize(
    "address",
    [
        "100.64.0.1",
        "192.0.2.1",
        "198.51.100.1",
        "203.0.113.1",
        "::ffff:169.254.169.254",
        "::ffff:10.0.0.1",
        "::ffff:127.0.0.1",
        "64:ff9b::169.254.169.254",
        "64:ff9b:1::1",
    ],
)
def test_fetch_rejects_explicit_special_use_and_translation_addresses(
    monkeypatch, address: str
) -> None:
    monkeypatch.setattr(
        fetch.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443))
        ],
    )

    with pytest.raises(FetchError, match="private_source_address"):
        fetch._validate_fetch_url(
            "https://raw.githubusercontent.com/owner/repo/file",
            allowed_hosts={"raw.githubusercontent.com"},
            trust_hosts={"raw.githubusercontent.com"},
            controlled_proxy_addresses={"198.18.0.21", "198.18.1.48"},
        )


@pytest.mark.parametrize("address", ["198.18.0.22", "::ffff:198.18.0.22"])
def test_fetch_accepts_rotating_trusted_benchmark_address(
    monkeypatch, address: str
) -> None:
    monkeypatch.setattr(
        fetch.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443))
        ],
    )

    assert fetch._validate_fetch_url(
        "https://raw.githubusercontent.com/owner/repo/file",
        allowed_hosts={"raw.githubusercontent.com"},
        trust_hosts={"raw.githubusercontent.com"},
        controlled_proxy_addresses={"198.18.0.21", "198.18.1.48"},
    ) == ("raw.githubusercontent.com", "198.18.0.22")


def test_fetch_rejects_controlled_range_for_untrusted_host(monkeypatch) -> None:
    monkeypatch.setattr(
        fetch.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("198.18.0.22", 443))
        ],
    )

    with pytest.raises(FetchError, match="controlled_proxy_address_not_trusted"):
        fetch._validate_fetch_url(
            "https://trusted.example/owner/repo/file",
            allowed_hosts={"trusted.example"},
            trust_hosts=set(),
            controlled_proxy_addresses=set(),
        )


@pytest.mark.parametrize(
    "hostname", ["localhost", "metadata", "metadata.google.internal"]
)
def test_fetch_rejects_special_use_hostnames(monkeypatch, hostname: str) -> None:
    monkeypatch.setattr(
        fetch.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))
        ],
    )

    with pytest.raises(FetchError, match="private_source_address"):
        fetch._validate_fetch_url(
            f"https://{hostname}/source",
            allowed_hosts={hostname},
            trust_hosts={hostname},
            controlled_proxy_addresses=set(),
        )


@pytest.mark.parametrize(
    "endpoint",
    [
        "100.64.0.1",
        "192.0.2.1",
        "198.51.100.1",
        "203.0.113.1",
        "198.18.0.22",
        "::ffff:169.254.169.254",
        "::ffff:10.0.0.1",
        "::ffff:127.0.0.1",
        "64:ff9b::169.254.169.254",
        "64:ff9b:1::1",
        "localhost",
        "metadata",
        "metadata.google.internal",
    ],
)
def test_node_endpoint_rejects_special_use_and_metadata(endpoint: str) -> None:
    with pytest.raises(ParseError, match="private_server"):
        normalize_proxy(
            {
                "name": "synthetic-node",
                "type": "http",
                "server": endpoint,
                "port": 8080,
            }
        )


def test_https_redirect_is_validated_before_second_request(monkeypatch) -> None:
    requests = {"count": 0}

    class RedirectProcess:
        def __init__(self, *args, **kwargs) -> None:
            requests["count"] += 1

            class InputBuffer(io.StringIO):
                closed_value = ""

                def close(self) -> None:
                    self.closed_value = self.getvalue()
                    super().close()

            self.stdin = InputBuffer()
            self.stdout = io.StringIO()
            self.returncode: int | None = None

        def poll(self) -> int | None:
            if self.returncode is None:
                options = {
                    key.strip(): json.loads(value.strip())
                    for line in self.stdin.closed_value.splitlines()
                    if " = " in line
                    for key, value in [line.split(" = ", 1)]
                }
                Path(options["dump-header"]).write_bytes(
                    b"HTTP/1.1 302 Found\r\n"
                    b"Location: https://evil.example/redirect\r\n\r\n"
                )
                self.stdout = io.StringIO("302")
                self.returncode = 0
            return self.returncode

    monkeypatch.setattr(fetch.shutil, "which", lambda _: "curl.exe")
    monkeypatch.setattr(fetch.subprocess, "Popen", RedirectProcess)
    monkeypatch.setattr(
        fetch.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))
        ],
    )

    with pytest.raises(FetchError, match="source_host_not_allowlisted"):
        fetch.fetch_http_source_with_meta(
            "https://trusted.example/subscription",
            5,
            1024,
            allowed_hosts={"trusted.example"},
            trust_hosts={"trusted.example"},
            retries=0,
        )

    assert requests["count"] == 1
