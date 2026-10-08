from __future__ import annotations

import io
import json
import socket
from pathlib import Path

import pytest

from aggregator import fetch
from aggregator.fetch import FetchError


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
