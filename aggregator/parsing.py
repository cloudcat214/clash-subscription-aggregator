from __future__ import annotations

import base64
import binascii
import copy
import ipaddress
import json
from collections.abc import Iterable, Mapping
from urllib.parse import parse_qs, unquote, urlsplit
from uuid import UUID

import yaml


class ParseError(ValueError):
    """Raised when a source does not contain a supported proxy record."""


_TYPE_ALIASES = {
    "https": "http",
    "socks": "socks5",
    "socks5h": "socks5",
    "shadowsocks": "ss",
}
_SUPPORTED_TYPES = {
    "http",
    "socks5",
    "ss",
    "ssr",
    "vmess",
    "vless",
    "trojan",
    "hysteria",
    "hysteria2",
    "tuic",
    "wireguard",
    "snell",
    "ssh",
}
_URI_SCHEMES = {
    "http",
    "https",
    "socks5",
    "socks5h",
    "ss",
    "vmess",
    "vless",
    "trojan",
    "hysteria2",
    "tuic",
}
_PROXY_FIELDS = {
    "alpn",
    "alterId",
    "cipher",
    "client-fingerprint",
    "fingerprint",
    "flow",
    "grpc-opts",
    "h2-opts",
    "headers",
    "http-opts",
    "ip-version",
    "mode",
    "network",
    "obfs",
    "obfs-password",
    "password",
    "public-key",
    "short-id",
    "pbk",
    "sid",
    "plugin",
    "plugin-opts",
    "ports",
    "skip-cert-verify",
    "sni",
    "servername",
    "tls",
    "udp",
    "uuid",
    "up",
    "down",
    "ws-opts",
    "reality-opts",
    "service-name",
    "authority",
    "ip",
    "private-key",
    "interface-name",
    "dialer-proxy",
    "proxy",
    "smux",
    "xudp",
    "packet-encoding",
    "tfo",
    "mptcp",
    "fast-open",
    "auth",
    "auth-str",
    "max-early-data",
    "early-data-header-name",
    "server-name",
    "congestion-controller",
    "udp-relay-mode",
    "reduce-rtt",
    "disable-sni",
    "zero-rtt-handshake",
    "heartbeat",
    "hop-interval",
}

_BASIC_PROXY_FIELDS = {"name", "type", "server", "port", "server_port", "add"}
_BLOCKED_ENDPOINT_NAMES = {
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
    "metadata.google.com",
    "instance-data.ec2.internal",
}


def decode_base64_payload(payload: str) -> str:
    """Decode a padded or unpadded standard/url-safe Base64 text payload."""
    if not isinstance(payload, str):
        raise ParseError("base64 payload must be text")
    compact = "".join(payload.strip().split())
    if not compact:
        raise ParseError("base64 payload is empty")
    padded = compact + "=" * (-len(compact) % 4)
    try:
        decoded = base64.b64decode(padded, altchars=b"-_", validate=True)
        return decoded.decode("utf-8-sig")
    except (binascii.Error, UnicodeDecodeError) as exc:
        raise ParseError("invalid base64 subscription") from exc


def _parse_port(value: object) -> int:
    try:
        port = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ParseError("proxy port is not an integer") from exc
    if not 1 <= port <= 65535:
        raise ParseError("proxy port is outside 1..65535")
    return port


def _bool_value(value: object) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _proxy_name(proxy_type: str, server: str, port: int, fragment: str = "") -> str:
    return fragment or f"{proxy_type}-{server}:{port}"


def _query_bool(
    query: Mapping[str, list[str]], key: str, default: bool = False
) -> bool:
    values = query.get(key, [])
    return _bool_value(values[0]) if values else default


def _query_first(query: Mapping[str, list[str]], *keys: str) -> str:
    for key in keys:
        if query.get(key):
            return query[key][0]
    return ""


def _query_list(query: Mapping[str, list[str]], *keys: str) -> list[str]:
    value = _query_first(query, *keys)
    return [item.strip() for item in value.split(",") if item.strip()]


def _validate_uuid(value: object) -> str:
    text = str(value or "").strip()
    try:
        UUID(text)
    except (ValueError, AttributeError) as exc:
        raise ParseError("invalid_uuid") from exc
    return text


def _validate_endpoint_host(server: str) -> None:
    hostname = server.strip().strip("[]").rstrip(".").lower()
    if hostname in _BLOCKED_ENDPOINT_NAMES or hostname.endswith(".localhost"):
        raise ParseError("private_server")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return
    if (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_unspecified
        or address.is_multicast
    ):
        raise ParseError("private_server")


def _apply_transport_query(
    proxy: dict[str, object], query: Mapping[str, list[str]]
) -> None:
    network = _query_first(query, "type", "network")
    if network:
        proxy["network"] = network
    alpn = _query_list(query, "alpn")
    if alpn:
        proxy["alpn"] = alpn
    fingerprint = _query_first(query, "fp", "fingerprint")
    if fingerprint:
        proxy["client-fingerprint"] = fingerprint
    flow = _query_first(query, "flow")
    if flow:
        proxy["flow"] = flow
    if _query_bool(query, "allowInsecure") or _query_bool(query, "insecure"):
        proxy["skip-cert-verify"] = True
    if network == "ws":
        ws_opts: dict[str, object] = {}
        path = _query_first(query, "path")
        host = _query_first(query, "host")
        if path:
            ws_opts["path"] = path
        if host:
            ws_opts["headers"] = {"Host": host}
        if ws_opts:
            proxy["ws-opts"] = ws_opts
    if network == "grpc":
        service_name = _query_first(query, "serviceName", "service-name")
        authority = _query_first(query, "authority")
        grpc_opts: dict[str, object] = {}
        if service_name:
            grpc_opts["grpc-service-name"] = service_name
        if authority:
            grpc_opts["authority"] = authority
        if grpc_opts:
            proxy["grpc-opts"] = grpc_opts


def _apply_reality_query(
    proxy: dict[str, object], query: Mapping[str, list[str]]
) -> None:
    if _query_first(query, "security") != "reality":
        return
    public_key = _query_first(query, "pbk", "publicKey", "public-key")
    short_id = _query_first(query, "sid", "shortId", "short-id")
    if not public_key:
        raise ParseError("missing_reality_public_key")
    proxy["tls"] = True
    proxy["reality-opts"] = {
        "public-key": public_key,
        "short-id": short_id,
    }


def _parse_standard_uri(uri: str, scheme: str) -> dict[str, object]:
    parts = urlsplit(uri)
    if not parts.hostname or parts.port is None:
        raise ParseError("proxy URI must include host and port")
    server = parts.hostname
    port = _parse_port(parts.port)
    query = parse_qs(parts.query, keep_blank_values=True)
    proxy_type = _TYPE_ALIASES.get(scheme, scheme)
    proxy: dict[str, object] = {
        "name": _proxy_name(proxy_type, server, port, unquote(parts.fragment)),
        "type": proxy_type,
        "server": server,
        "port": port,
    }
    if parts.username:
        proxy["username"] = unquote(parts.username)
    if parts.password:
        proxy["password"] = unquote(parts.password)
    if scheme == "https" or _query_bool(query, "tls"):
        proxy["tls"] = True
    if query.get("sni"):
        proxy["sni"] = query["sni"][0]
    _apply_transport_query(proxy, query)
    return proxy


def _parse_trojan_uri(uri: str) -> dict[str, object]:
    parts = urlsplit(uri)
    if not parts.hostname or parts.port is None:
        raise ParseError("trojan URI must include host and port")
    password = unquote(parts.username or parts.password or "")
    if not password:
        raise ParseError("trojan URI must include a password")
    query = parse_qs(parts.query, keep_blank_values=True)
    proxy: dict[str, object] = {
        "name": _proxy_name(
            "trojan", parts.hostname, _parse_port(parts.port), unquote(parts.fragment)
        ),
        "type": "trojan",
        "server": parts.hostname,
        "port": _parse_port(parts.port),
        "password": password,
        "tls": True,
    }
    sni = _query_first(query, "sni", "servername", "serverName")
    if sni:
        proxy["sni"] = sni
    _apply_transport_query(proxy, query)
    return proxy


def _parse_vless_uri(uri: str) -> dict[str, object]:
    parts = urlsplit(uri)
    if not parts.hostname or parts.port is None or not parts.username:
        raise ParseError("vless URI must include UUID, host and port")
    query = parse_qs(parts.query, keep_blank_values=True)
    uuid = _validate_uuid(parts.username)
    proxy: dict[str, object] = {
        "name": _proxy_name(
            "vless", parts.hostname, _parse_port(parts.port), unquote(parts.fragment)
        ),
        "type": "vless",
        "server": parts.hostname,
        "port": _parse_port(parts.port),
        "uuid": uuid,
    }
    if _query_first(query, "security") in {"tls", "reality"}:
        proxy["tls"] = True
    sni = _query_first(query, "sni", "servername", "serverName")
    if sni:
        proxy["sni"] = sni
    _apply_transport_query(proxy, query)
    _apply_reality_query(proxy, query)
    return proxy


def _parse_vmess_uri(uri: str) -> dict[str, object]:
    parts = urlsplit(uri)
    encoded = parts.netloc or parts.path
    if not encoded:
        raise ParseError("vmess URI is empty")
    try:
        data = json.loads(decode_base64_payload(encoded))
    except (json.JSONDecodeError, ParseError) as exc:
        raise ParseError("vmess URI payload is not valid JSON") from exc
    if not isinstance(data, Mapping):
        raise ParseError("vmess URI payload is not an object")
    server = str(data.get("add", ""))
    if not server:
        raise ParseError("vmess URI has no server")
    port = _parse_port(data.get("port"))
    uuid = _validate_uuid(data.get("id"))
    proxy: dict[str, object] = {
        "name": str(
            data.get("ps")
            or _proxy_name("vmess", server, port, unquote(parts.fragment))
        ),
        "type": "vmess",
        "server": server,
        "port": port,
        "uuid": uuid,
        "alterId": int(data.get("aid", 0) or 0),
        "cipher": str(data.get("scy") or "auto"),
    }
    if _bool_value(data.get("tls", False)):
        proxy["tls"] = True
    if data.get("net"):
        proxy["network"] = str(data["net"])
    if data.get("sni"):
        proxy["sni"] = str(data["sni"])
    if str(data.get("net", "")) == "ws":
        ws_opts: dict[str, object] = {}
        if data.get("path"):
            ws_opts["path"] = str(data["path"])
        if data.get("host"):
            ws_opts["headers"] = {"Host": str(data["host"])}
        if ws_opts:
            proxy["ws-opts"] = ws_opts
    if data.get("alpn"):
        proxy["alpn"] = (
            data["alpn"] if isinstance(data["alpn"], list) else [str(data["alpn"])]
        )
    if data.get("fp"):
        proxy["client-fingerprint"] = str(data["fp"])
    if str(data.get("security", data.get("tls", ""))).lower() == "reality":
        reality_opts = {
            "public-key": data.get("pbk") or data.get("publicKey"),
            "short-id": data.get("sid") or data.get("shortId", ""),
        }
        if not reality_opts["public-key"]:
            raise ParseError("missing_reality_public_key")
        proxy["reality-opts"] = reality_opts
    return proxy


def _parse_ss_uri(uri: str) -> dict[str, object]:
    parts = urlsplit(uri)
    value = uri[len("ss://") :].split("#", 1)[0]
    if not value:
        raise ParseError("ss URI is empty")
    if "@" in value:
        auth, endpoint = value.rsplit("@", 1)
        try:
            auth = decode_base64_payload(auth)
        except ParseError:
            auth = unquote(auth)
    else:
        decoded = decode_base64_payload(value)
        if "@" not in decoded:
            raise ParseError("ss URI has no endpoint")
        auth, endpoint = decoded.rsplit("@", 1)
    if ":" not in auth:
        raise ParseError("ss URI has no method/password pair")
    method, password = auth.split(":", 1)
    endpoint_parts = urlsplit(f"//{endpoint}")
    if not endpoint_parts.hostname or endpoint_parts.port is None:
        raise ParseError("ss URI has no host/port")
    port = _parse_port(endpoint_parts.port)
    proxy: dict[str, object] = {
        "name": _proxy_name(
            "ss", endpoint_parts.hostname, port, unquote(parts.fragment)
        ),
        "type": "ss",
        "server": endpoint_parts.hostname,
        "port": port,
        "cipher": unquote(method),
        "password": unquote(password),
    }
    plugin = _query_first(parse_qs(parts.query, keep_blank_values=True), "plugin")
    if plugin:
        plugin_parts = [item for item in plugin.split(";") if item]
        proxy["plugin"] = plugin_parts[0]
        plugin_opts: dict[str, object] = {}
        for item in plugin_parts[1:]:
            if "=" in item:
                key, value = item.split("=", 1)
                plugin_opts[key] = value
        if plugin_opts:
            proxy["plugin-opts"] = plugin_opts
    return proxy


def _parse_hysteria2_uri(uri: str) -> dict[str, object]:
    parts = urlsplit(uri)
    if not parts.hostname or parts.port is None or not parts.username:
        raise ParseError("hysteria2 URI must include password, host and port")
    query = parse_qs(parts.query, keep_blank_values=True)
    proxy: dict[str, object] = {
        "name": _proxy_name(
            "hysteria2",
            parts.hostname,
            _parse_port(parts.port),
            unquote(parts.fragment),
        ),
        "type": "hysteria2",
        "server": parts.hostname,
        "port": _parse_port(parts.port),
        "password": unquote(parts.username),
        "tls": True,
    }
    sni = _query_first(query, "sni", "serverName")
    if sni:
        proxy["sni"] = sni
    for key in ("obfs", "obfs-password"):
        value = _query_first(query, key)
        if value:
            proxy[key] = value
    for query_key, proxy_key in (
        ("upmbps", "up"),
        ("downmbps", "down"),
        ("mport", "ports"),
    ):
        value = _query_first(query, query_key)
        if value:
            proxy[proxy_key] = value
    hop_interval = _query_first(query, "hopInterval", "hop-interval")
    if hop_interval:
        proxy["hop-interval"] = hop_interval
    if _query_first(query, "pinSHA256"):
        proxy["fingerprint"] = _query_first(query, "pinSHA256")
    if _query_bool(query, "insecure"):
        proxy["skip-cert-verify"] = True
    proxy["alpn"] = _query_list(query, "alpn")
    if not proxy["alpn"]:
        proxy.pop("alpn")
    return proxy


def _parse_tuic_uri(uri: str) -> dict[str, object]:
    parts = urlsplit(uri)
    if (
        not parts.hostname
        or parts.port is None
        or not parts.username
        or not parts.password
    ):
        raise ParseError("tuic URI must include UUID, password, host and port")
    query = parse_qs(parts.query, keep_blank_values=True)
    proxy: dict[str, object] = {
        "name": _proxy_name(
            "tuic", parts.hostname, _parse_port(parts.port), unquote(parts.fragment)
        ),
        "type": "tuic",
        "server": parts.hostname,
        "port": _parse_port(parts.port),
        "uuid": _validate_uuid(unquote(parts.username)),
        "password": unquote(parts.password),
        "tls": True,
    }
    key_map = {
        "congestion_control": "congestion-controller",
        "udp_relay_mode": "udp-relay-mode",
        "reduce_rtt": "reduce-rtt",
        "disable_sni": "disable-sni",
    }
    for query_key, output_key in key_map.items():
        value = _query_first(query, query_key)
        if value:
            proxy[output_key] = (
                _bool_value(value)
                if query_key in {"reduce_rtt", "disable_sni"}
                else value
            )
    sni = _query_first(query, "sni", "serverName")
    if sni:
        proxy["sni"] = sni
    ports = _query_first(query, "ports", "mport")
    if ports:
        proxy["ports"] = ports
    for query_key, proxy_key in (("up", "up"), ("down", "down")):
        value = _query_first(query, query_key, f"{query_key}mbps")
        if value:
            proxy[proxy_key] = value
    hop_interval = _query_first(query, "hopInterval", "hop-interval")
    if hop_interval:
        proxy["hop-interval"] = hop_interval
    proxy["alpn"] = _query_list(query, "alpn")
    if not proxy["alpn"]:
        proxy.pop("alpn")
    if _query_bool(query, "allow_insecure") or _query_bool(query, "insecure"):
        proxy["skip-cert-verify"] = True
    return proxy


def parse_uri(uri: str) -> dict[str, object]:
    """Parse one supported subscription URI into a Clash-like proxy mapping."""
    if not isinstance(uri, str) or "://" not in uri:
        raise ParseError("proxy URI has no scheme")
    scheme = uri.split("://", 1)[0].lower()
    if scheme not in _URI_SCHEMES:
        raise ParseError(f"unsupported proxy scheme: {scheme}")
    if scheme == "vmess":
        return _parse_vmess_uri(uri)
    if scheme == "vless":
        return _parse_vless_uri(uri)
    if scheme == "trojan":
        return _parse_trojan_uri(uri)
    if scheme == "ss":
        return _parse_ss_uri(uri)
    if scheme == "hysteria2":
        return _parse_hysteria2_uri(uri)
    if scheme == "tuic":
        return _parse_tuic_uri(uri)
    return _parse_standard_uri(uri, scheme)


def _document_proxies(
    document: object,
) -> tuple[list[dict[str, object]] | None, dict[str, int]]:
    if isinstance(document, Mapping) and isinstance(document.get("proxies"), list):
        proxies: list[dict[str, object]] = []
        invalid = 0
        for item in document["proxies"]:
            if isinstance(item, Mapping):
                proxies.append(dict(item))
            else:
                invalid += 1
        return proxies, {"invalid_proxy_record": invalid} if invalid else {}
    return None, {}


def _parse_structured(
    payload: str, format_hint: str
) -> tuple[list[dict[str, object]] | None, dict[str, int]]:
    stripped = payload.lstrip()
    if format_hint == "json" or (format_hint == "auto" and stripped[:1] in {"{", "["}):
        try:
            document = json.loads(payload)
        except json.JSONDecodeError:
            if format_hint == "json":
                raise ParseError("invalid JSON source")
        else:
            proxies, drops = _document_proxies(document)
            if proxies is not None:
                return proxies, drops
            if format_hint == "json":
                raise ParseError("JSON source has no proxies list")
    if format_hint in {"yaml", "auto"}:
        try:
            document = yaml.safe_load(payload)
        except yaml.YAMLError:
            if format_hint == "yaml":
                raise ParseError("invalid YAML source")
        else:
            proxies, drops = _document_proxies(document)
            if proxies is not None:
                return proxies, drops
            if format_hint == "yaml" and isinstance(document, Mapping):
                raise ParseError("YAML source has no proxies list")
    return None, {}


def parse_source_payload_with_drops(
    payload: str, format_hint: str = "auto", _decoded: bool = False
) -> tuple[list[dict[str, object]], dict[str, int]]:
    """Parse Clash YAML/JSON, Base64-wrapped text, or one-URI-per-line input."""
    if not isinstance(payload, str) or not payload.strip():
        raise ParseError("source payload is empty")
    format_hint = format_hint.lower()
    if format_hint not in {"auto", "base64", "json", "yaml", "uri"}:
        raise ParseError(f"unsupported format hint: {format_hint}")
    if format_hint == "base64":
        return parse_source_payload_with_drops(
            decode_base64_payload(payload), "auto", True
        )

    structured, structured_drops = _parse_structured(payload, format_hint)
    if structured is not None:
        return structured, structured_drops
    if format_hint in {"auto", "uri"}:
        proxies: list[dict[str, object]] = []
        drops: dict[str, int] = {}
        for line in payload.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "://" not in line:
                continue
            scheme = line.split("://", 1)[0].lower()
            if scheme not in _URI_SCHEMES:
                drops["unsupported_scheme"] = drops.get("unsupported_scheme", 0) + 1
                continue
            try:
                proxies.append(parse_uri(line))
            except ParseError as exc:
                reason = str(exc).split(":", 1)[0]
                drops[reason] = drops.get(reason, 0) + 1
        if proxies or drops:
            return proxies, drops
    if format_hint in {"auto", "base64"} and not _decoded:
        return parse_source_payload_with_drops(
            decode_base64_payload(payload), "auto", True
        )
    raise ParseError("no supported proxies found")


def parse_source_payload(
    payload: str, format_hint: str = "auto", _decoded: bool = False
) -> list[dict[str, object]]:
    return parse_source_payload_with_drops(payload, format_hint, _decoded)[0]


def classify_protocol(proxy: Mapping[str, object]) -> str:
    proxy_type = str(proxy.get("type", "unknown")).lower()
    return _TYPE_ALIASES.get(proxy_type, proxy_type)


def normalize_proxy(proxy: Mapping[str, object]) -> dict[str, object]:
    if not isinstance(proxy, Mapping):
        raise ParseError("proxy record is not an object")
    proxy_type = classify_protocol(proxy)
    if proxy_type not in _SUPPORTED_TYPES:
        raise ParseError(f"unsupported proxy type: {proxy_type}")
    server = str(proxy.get("server") or proxy.get("add") or "").strip()
    if not server or "://" in server:
        raise ParseError("proxy server is missing or contains a scheme")
    _validate_endpoint_host(server)
    port = _parse_port(proxy.get("port", proxy.get("server_port")))
    name = str(proxy.get("name") or f"{proxy_type}-{server}:{port}").strip()
    normalized: dict[str, object] = copy.deepcopy(dict(proxy))
    normalized.update(
        {"name": name, "type": proxy_type, "server": server, "port": port}
    )
    for key in _PROXY_FIELDS:
        if key in proxy and proxy[key] is not None:
            value = copy.deepcopy(proxy[key])
            if key in {"tls", "udp", "skip-cert-verify"}:
                value = _bool_value(value)
            normalized[key] = value
    for key in ("username", "password"):
        if key in proxy and proxy[key] is not None:
            normalized[key] = str(proxy[key])
    if proxy_type in {"vmess", "vless", "tuic"}:
        normalized["uuid"] = _validate_uuid(normalized.get("uuid"))
    if proxy_type in {"trojan", "hysteria2", "tuic", "ss"} and not normalized.get(
        "password"
    ):
        raise ParseError("missing_password")
    if proxy_type == "ss" and not normalized.get("cipher"):
        raise ParseError("missing_cipher")
    return normalized


def normalize_proxies(
    proxies: Iterable[Mapping[str, object]],
) -> list[dict[str, object]]:
    return normalize_proxies_with_drops(proxies)[0]


def normalize_proxies_with_drops(
    proxies: Iterable[Mapping[str, object]],
) -> tuple[list[dict[str, object]], dict[str, int]]:
    normalized: list[dict[str, object]] = []
    drops: dict[str, int] = {}
    for proxy in proxies:
        try:
            normalized_proxy = normalize_proxy(proxy)
            normalized.append(normalized_proxy)
        except (ParseError, TypeError, ValueError) as exc:
            reason = str(exc).split(":", 1)[0]
            drops[reason] = drops.get(reason, 0) + 1
            continue
    unique = deduplicate_proxies(normalized)
    duplicate_count = len(normalized) - len(unique)
    if duplicate_count:
        drops["duplicate"] = duplicate_count
    return unique, drops


def _identity(proxy: Mapping[str, object]) -> str:
    identity = {
        key: value
        for key, value in proxy.items()
        if key not in {"name", "source", "source_repo", "quality_score"}
    }
    return json.dumps(identity, ensure_ascii=False, sort_keys=True, default=str)


def deduplicate_proxies(
    proxies: Iterable[Mapping[str, object]],
) -> list[dict[str, object]]:
    seen: set[str] = set()
    unique: list[dict[str, object]] = []
    for proxy in proxies:
        key = _identity(proxy)
        if key in seen:
            continue
        seen.add(key)
        unique.append(dict(proxy))
    return unique


def quality_score(proxy: Mapping[str, object]) -> int:
    score = 20
    if classify_protocol(proxy) in _SUPPORTED_TYPES:
        score += 30
    if proxy.get("server"):
        score += 20
    if proxy.get("port"):
        score += 20
    if (
        proxy.get("tls")
        or proxy.get("uuid")
        or proxy.get("password")
        or proxy.get("cipher")
    ):
        score += 5
    return min(score, 100)


def filter_proxies(
    proxies: Iterable[Mapping[str, object]],
    *,
    allow_protocols: Iterable[str] = (),
    deny_protocols: Iterable[str] = (),
    deny_name_keywords: Iterable[str] = (),
    min_quality_score: int = 0,
) -> list[dict[str, object]]:
    allow = {str(value).lower() for value in allow_protocols if str(value).strip()}
    deny = {str(value).lower() for value in deny_protocols if str(value).strip()}
    keywords = [
        str(value).casefold() for value in deny_name_keywords if str(value).strip()
    ]
    result: list[dict[str, object]] = []
    for proxy in proxies:
        protocol = classify_protocol(proxy)
        name = str(proxy.get("name", ""))
        if allow and protocol not in allow:
            continue
        if protocol in deny:
            continue
        if any(keyword in name.casefold() for keyword in keywords):
            continue
        if quality_score(proxy) < min_quality_score:
            continue
        result.append(dict(proxy))
    return result
