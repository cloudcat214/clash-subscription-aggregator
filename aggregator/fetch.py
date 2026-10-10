from __future__ import annotations

import ipaddress
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.parse import urljoin, urlsplit


class FetchError(RuntimeError):
    """A sanitized source-fetch failure."""


_CONTROLLED_PROXY_DNS = ipaddress.ip_network("198.18.0.0/15")
_CONTROLLED_PROXY_HOST = "raw.githubusercontent.com"
_SPECIAL_USE_NETWORKS = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("64:ff9b::/96"),
    ipaddress.ip_network("64:ff9b:1::/48"),
)
_BLOCKED_SOURCE_HOSTS = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "metadata",
        "metadata.google.internal",
        "metadata.google.com",
        "instance-data.ec2.internal",
    }
)
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}


def _normalized_ip(address: str):
    value = ipaddress.ip_address(address)
    return getattr(value, "ipv4_mapped", None) or value


def _blocked_ip(address: str) -> bool:
    value = _normalized_ip(address)
    return bool(
        any(
            value.version == network.version and value in network
            for network in _SPECIAL_USE_NETWORKS
        )
        or value.is_private
        or value.is_loopback
        or value.is_link_local
        or value.is_reserved
        or value.is_unspecified
        or value.is_multicast
    )


def _blocked_source_hostname(hostname: str) -> bool:
    return hostname in _BLOCKED_SOURCE_HOSTS or hostname.endswith(".localhost")


def _curl_string(value: str) -> str:
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise FetchError("invalid_source_url")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _validate_fetch_url(
    url: str,
    *,
    allowed_hosts: set[str],
    trust_hosts: set[str],
    controlled_proxy_addresses: set[str],
) -> tuple[str, str]:
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise FetchError("invalid_source_url") from exc
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise FetchError("https_required")
    if parsed.username is not None or parsed.password is not None:
        raise FetchError("source_url_userinfo")
    if port not in {None, 443}:
        raise FetchError("source_port_not_allowed")
    hostname = parsed.hostname.rstrip(".").lower()
    if _blocked_source_hostname(hostname):
        raise FetchError("private_source_address")
    if hostname not in allowed_hosts:
        raise FetchError("source_host_not_allowlisted")
    try:
        addresses = sorted(
            {
                str(item[4][0]).split("%", 1)[0]
                for item in socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
            }
        )
    except (OSError, socket.gaierror) as exc:
        raise FetchError("source_dns_error") from exc
    if not addresses:
        raise FetchError("source_dns_empty")

    validated_addresses: list[str] = []
    for address in addresses:
        try:
            value = _normalized_ip(address)
        except ValueError as exc:
            raise FetchError("source_dns_invalid_address") from exc
        normalized_address = str(value)
        if (
            value.version == _CONTROLLED_PROXY_DNS.version
            and value in _CONTROLLED_PROXY_DNS
        ):
            if hostname != _CONTROLLED_PROXY_HOST or hostname not in trust_hosts:
                raise FetchError("controlled_proxy_address_not_trusted")
        elif _blocked_ip(normalized_address):
            raise FetchError("private_source_address")
        validated_addresses.append(normalized_address)

    # Pin curl to the address checked above to close the validate-then-resolve gap.
    return hostname, validated_addresses[0]


def _response_headers(path: Path) -> dict[str, str]:
    try:
        raw = path.read_text(encoding="iso-8859-1")
    except OSError as exc:
        raise FetchError(type(exc).__name__) from exc
    blocks = [block for block in raw.replace("\r\n", "\n").split("\n\n") if block]
    if not blocks:
        return {}
    headers: dict[str, str] = {}
    for line in blocks[-1].splitlines()[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        key = name.strip().lower()
        if key in {"etag", "last-modified", "content-type", "location"}:
            headers[key] = value.strip()
    return headers


def fetch_http_source_with_meta(
    url: str,
    timeout: float,
    max_bytes: int,
    *,
    allowed_hosts: set[str],
    trust_hosts: set[str],
    controlled_proxy_addresses: set[str] | None = None,
    retries: int = 2,
    backoff_seconds: float = 0.5,
    max_redirects: int = 3,
    request_headers: dict[str, str] | None = None,
    cached_payload: str | None = None,
) -> tuple[str, dict[str, str]]:
    current_url = url
    redirect_count = 0
    controlled_addresses = controlled_proxy_addresses or set()
    curl = shutil.which("curl.exe") or shutil.which("curl")
    if not curl:
        raise FetchError("curl_unavailable")
    last_error = FetchError("source_fetch_failed")

    for attempt in range(max(0, retries) + 1):
        try:
            current_url = url
            redirect_count = 0
            while True:
                hostname, address = _validate_fetch_url(
                    current_url,
                    allowed_hosts=allowed_hosts,
                    trust_hosts=trust_hosts,
                    controlled_proxy_addresses=controlled_addresses,
                )
                with tempfile.TemporaryDirectory(prefix="clash-fetch-") as temp_dir:
                    body_path = Path(temp_dir) / "body"
                    headers_path = Path(temp_dir) / "headers"
                    options = [
                        f"url = {_curl_string(current_url)}",
                        'proto = "=https"',
                        "max-redirs = 0",
                        f"max-time = {max(1.0, timeout)}",
                        f"connect-timeout = {max(1.0, min(timeout, 10.0))}",
                        f"max-filesize = {max(1, max_bytes)}",
                        'noproxy = "*"',
                        f"output = {_curl_string(str(body_path))}",
                        f"dump-header = {_curl_string(str(headers_path))}",
                        f"resolve = {_curl_string(f'{hostname}:443:{address}')}",
                        'write-out = "%{http_code}"',
                        "silent",
                    ]
                    for name, value in (request_headers or {}).items():
                        if (
                            "\r" in name
                            or "\n" in name
                            or "\r" in value
                            or "\n" in value
                        ):
                            raise FetchError("invalid_request_header")
                        options.append(f"header = {_curl_string(f'{name}: {value}')}")
                    try:
                        process = subprocess.Popen(
                            [curl, "--disable", "--config", "-"],
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL,
                            text=True,
                        )
                        assert process.stdin is not None
                        process.stdin.write("\n".join(options) + "\n")
                        process.stdin.close()
                        deadline = time.monotonic() + max(1.0, timeout + 2.0)
                        while process.poll() is None:
                            if (
                                body_path.exists()
                                and body_path.stat().st_size > max_bytes
                            ):
                                process.kill()
                                process.wait()
                                raise FetchError("source_payload_too_large")
                            if time.monotonic() >= deadline:
                                process.kill()
                                process.wait()
                                raise FetchError("TimeoutExpired")
                            time.sleep(0.02)
                        status_text = process.stdout.read() if process.stdout else ""
                    except FetchError:
                        raise
                    except OSError as exc:
                        raise FetchError(type(exc).__name__) from exc
                    if process.returncode != 0:
                        if process.returncode == 63:
                            raise FetchError("source_payload_too_large")
                        raise FetchError("source_fetch_failed")
                    try:
                        status = int(status_text.strip())
                    except ValueError as exc:
                        raise FetchError("source_response_invalid") from exc
                    response_headers = _response_headers(headers_path)
                    if status == 304 and cached_payload is not None:
                        return cached_payload, response_headers
                    if status in _REDIRECT_STATUSES:
                        location = response_headers.get("location")
                        if not location:
                            raise FetchError("redirect_location_missing")
                        if redirect_count >= max(0, max_redirects):
                            raise FetchError("too_many_redirects")
                        target = urljoin(current_url, location)
                        # Check each hop before curl is allowed to contact it.
                        _validate_fetch_url(
                            target,
                            allowed_hosts=allowed_hosts,
                            trust_hosts=trust_hosts,
                            controlled_proxy_addresses=controlled_addresses,
                        )
                        current_url = target
                        redirect_count += 1
                        continue
                    if status < 200 or status >= 300:
                        raise FetchError(f"http_{status}")
                    try:
                        body = body_path.read_bytes()
                    except OSError as exc:
                        raise FetchError(type(exc).__name__) from exc
                    if len(body) > max_bytes:
                        raise FetchError("source_payload_too_large")
                    content_type = response_headers.get("content-type", "").lower()
                    prefix = body[:512].lstrip().lower()
                    if "text/html" in content_type or prefix.startswith(
                        (b"<!doctype html", b"<html")
                    ):
                        raise FetchError("html_response_rejected")
                    try:
                        return body.decode("utf-8-sig"), response_headers
                    except UnicodeDecodeError as exc:
                        raise FetchError("source_payload_not_utf8") from exc
        except FetchError as exc:
            if str(exc) in {
                "https_required",
                "source_url_userinfo",
                "source_port_not_allowed",
                "source_host_not_allowlisted",
                "controlled_proxy_address_not_trusted",
                "private_source_address",
                "too_many_redirects",
                "redirect_location_missing",
                "html_response_rejected",
                "source_payload_too_large",
                "source_dns_invalid_address",
            }:
                raise
            last_error = exc
        if attempt < max(0, retries):
            time.sleep(max(0.0, backoff_seconds) * (2**attempt))
    raise last_error
