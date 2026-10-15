from __future__ import annotations

import json
from collections.abc import Iterable, Mapping

import yaml


def render_clash_provider(proxies: Iterable[Mapping[str, object]]) -> str:
    return yaml.safe_dump(
        {"proxies": [dict(proxy) for proxy in proxies]},
        allow_unicode=True,
        default_flow_style=False,
        sort_keys=False,
    )


def render_clash_config(
    proxies: Iterable[Mapping[str, object]] = (), base_url: str | None = None
) -> str:
    proxy_list = [dict(proxy) for proxy in proxies]
    names = [str(proxy.get("name")) for proxy in proxy_list]
    selectable = ["DIRECT", *names]
    config = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "proxies": proxy_list,
        "proxy-groups": [
            {
                "name": "PROXY",
                "type": "select",
                "proxies": selectable,
            },
            {
                "name": "AUTO",
                "type": "url-test",
                "proxies": names or ["DIRECT"],
                "url": "https://www.gstatic.com/generate_204",
                "timeout": 5000,
                "interval": 600,
                "tolerance": 100,
            },
            {
                "name": "FALLBACK",
                "type": "fallback",
                "proxies": names or ["DIRECT"],
                "url": "https://www.gstatic.com/generate_204",
                "timeout": 5000,
                "interval": 600,
            },
        ],
        "rules": ["MATCH,PROXY"],
    }
    return yaml.safe_dump(
        config, allow_unicode=True, default_flow_style=False, sort_keys=False
    )


def render_clash_http_provider_config(base_url: str) -> str:
    config = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "proxy-providers": {
            "aggregate": {
                "type": "http",
                "url": f"{base_url.rstrip('/')}/clash/providers/aggregate.yaml",
                "path": "./providers/aggregate.yaml",
                "interval": 3600,
                "health-check": {"enable": False},
            }
        },
        "proxy-groups": [
            {
                "name": "PROXY",
                "type": "select",
                "use": ["aggregate"],
                "proxies": ["DIRECT"],
            },
            {
                "name": "AUTO",
                "type": "url-test",
                "use": ["aggregate"],
                "url": "https://www.gstatic.com/generate_204",
                "timeout": 5000,
                "interval": 600,
                "tolerance": 100,
            },
            {
                "name": "FALLBACK",
                "type": "fallback",
                "use": ["aggregate"],
                "url": "https://www.gstatic.com/generate_204",
                "timeout": 5000,
                "interval": 600,
            },
        ],
        "rules": ["MATCH,PROXY"],
    }
    return yaml.safe_dump(
        config, allow_unicode=True, default_flow_style=False, sort_keys=False
    )


def _singbox_outbound(
    proxy: Mapping[str, object], tag: str
) -> tuple[dict[str, object] | None, str | None]:
    proxy_type = str(proxy.get("type", "")).lower()
    type_map = {
        "http": "http",
        "socks5": "socks",
        "ss": "shadowsocks",
        "vmess": "vmess",
        "vless": "vless",
        "trojan": "trojan",
        "hysteria2": "hysteria2",
        "tuic": "tuic",
    }
    singbox_type = type_map.get(proxy_type)
    if singbox_type is None:
        return None, f"unsupported_protocol:{proxy_type or 'unknown'}"
    network = str(proxy.get("network") or "tcp").lower()
    if network not in {"tcp", "ws", "grpc"}:
        return None, f"unsupported_transport:{network}"
    if proxy_type == "ss" and (not proxy.get("cipher") or not proxy.get("password")):
        return None, "missing_shadowsocks_credentials"
    if proxy_type in {"vmess", "vless", "tuic"} and not proxy.get("uuid"):
        return None, "missing_uuid"
    if proxy_type in {"trojan", "hysteria2", "tuic"} and not proxy.get("password"):
        return None, "missing_password"
    reality = proxy.get("reality-opts")
    if reality is not None and not isinstance(reality, Mapping):
        return None, "invalid_reality_options"
    if isinstance(reality, Mapping) and not (
        reality.get("public-key") or reality.get("public_key") or reality.get("pbk")
    ):
        return None, "missing_reality_public_key"
    if proxy.get("plugin"):
        return None, "unsupported_shadowsocks_plugin"
    outbound: dict[str, object] = {
        "type": singbox_type,
        "tag": tag,
        "server": proxy["server"],
        "server_port": proxy["port"],
    }
    if proxy_type in {"http", "socks5"}:
        for key in ("username", "password"):
            if proxy.get(key) is not None:
                outbound[key] = proxy[key]
    elif proxy_type == "ss":
        outbound["method"] = proxy.get("cipher", "")
        outbound["password"] = proxy.get("password", "")
    elif proxy_type in {"vmess", "vless"}:
        outbound["uuid"] = proxy.get("uuid", "")
        if proxy.get("flow"):
            outbound["flow"] = proxy["flow"]
        if proxy.get("cipher"):
            outbound["security"] = proxy["cipher"]
    elif proxy_type == "trojan":
        outbound["password"] = proxy.get("password", "")
    elif proxy_type == "hysteria2":
        outbound["password"] = proxy.get("password", "")
        if proxy.get("obfs"):
            if str(proxy["obfs"]).lower() != "salamander":
                return None, "unsupported_hysteria2_obfs"
            outbound["obfs"] = {
                "type": "salamander",
                "password": proxy.get("obfs-password", ""),
            }
        for source_key, target_key in (("up", "up_mbps"), ("down", "down_mbps")):
            if proxy.get(source_key) is not None:
                try:
                    outbound[target_key] = int(
                        str(proxy[source_key]).removesuffix("Mbps").strip()
                    )
                except ValueError:
                    return None, f"invalid_hysteria2_{target_key}"
        ports = proxy.get("ports")
        if ports:
            outbound["server_ports"] = (
                [str(item) for item in ports]
                if isinstance(ports, list)
                else [item.strip() for item in str(ports).split(",") if item.strip()]
            )
        hop_interval = proxy.get("hop-interval")
        if hop_interval:
            outbound["hop_interval"] = hop_interval
    elif proxy_type == "tuic":
        outbound["uuid"] = proxy.get("uuid", "")
        outbound["password"] = proxy.get("password", "")
        for source_key, target_key in (
            ("congestion-controller", "congestion_control"),
            ("udp-relay-mode", "udp_relay_mode"),
            ("reduce-rtt", "zero_rtt_handshake"),
            ("heartbeat", "heartbeat"),
        ):
            if proxy.get(source_key) is not None:
                outbound[target_key] = proxy[source_key]
    if proxy.get("tls") or proxy.get("sni") or proxy.get("servername") or reality:
        tls: dict[str, object] = {"enabled": True}
        server_name = (
            proxy.get("sni") or proxy.get("servername") or proxy.get("server-name")
        )
        if server_name:
            tls["server_name"] = server_name
        if proxy.get("alpn"):
            tls["alpn"] = proxy["alpn"]
        if proxy.get("skip-cert-verify"):
            tls["insecure"] = True
        fingerprint = proxy.get("client-fingerprint") or proxy.get("fingerprint")
        if fingerprint:
            tls["utls"] = {"enabled": True, "fingerprint": fingerprint}
        if isinstance(reality, Mapping):
            public_key = (
                reality.get("public-key")
                or reality.get("public_key")
                or reality.get("pbk")
            )
            short_id = (
                reality.get("short-id")
                or reality.get("short_id")
                or reality.get("sid", "")
            )
            if public_key:
                tls["reality"] = {
                    "enabled": True,
                    "public_key": public_key,
                    "short_id": short_id,
                }
        if proxy.get("disable-sni"):
            tls["disable_sni"] = True
        outbound["tls"] = tls
    network_value = proxy.get("network")
    ws_opts_value = proxy.get("ws-opts")
    if network_value == "ws":
        ws_opts = ws_opts_value if isinstance(ws_opts_value, Mapping) else {}
        transport: dict[str, object] = {"type": "ws"}
        if ws_opts.get("path"):
            transport["path"] = ws_opts["path"]
        if isinstance(ws_opts.get("headers"), Mapping):
            transport["headers"] = dict(ws_opts["headers"])
        outbound["transport"] = transport
    elif network_value == "grpc":
        grpc_opts_value = proxy.get("grpc-opts")
        transport = {"type": "grpc"}
        if isinstance(grpc_opts_value, Mapping):
            service_name = grpc_opts_value.get(
                "grpc-service-name"
            ) or grpc_opts_value.get("service-name")
            if service_name:
                transport["service_name"] = service_name
        if proxy.get("service-name"):
            transport["service_name"] = proxy["service-name"]
        outbound["transport"] = transport
    return outbound, None


def render_sing_box_config_with_stats(
    proxies: Iterable[Mapping[str, object]], stats: dict[str, object] | None = None
) -> str:
    outbounds: list[dict[str, object]] = []
    selector: dict[str, object] = {
        "type": "selector",
        "tag": "proxy",
        "outbounds": ["direct"],
    }
    used_tags: set[str] = {"proxy", "direct"}
    drop_reasons: dict[str, int] = {}
    for index, proxy in enumerate(proxies, start=1):
        base_tag = str(proxy.get("name") or f"proxy-{index}")
        tag = base_tag
        suffix = 2
        while tag in used_tags:
            tag = f"{base_tag}-{suffix}"
            suffix += 1
        used_tags.add(tag)
        outbound, reason = _singbox_outbound(proxy, tag)
        if outbound is not None:
            outbounds.append(outbound)
            selector["outbounds"].append(tag)  # type: ignore[union-attr]
        else:
            drop_reason = reason or "unsupported_outbound"
            drop_reasons[drop_reason] = drop_reasons.get(drop_reason, 0) + 1
    outbounds.insert(0, {"type": "direct", "tag": "direct"})
    outbounds.insert(0, selector)
    config = {
        "log": {"level": "info"},
        "outbounds": outbounds,
    }
    if stats is not None:
        stats["unsupported"] = sum(drop_reasons.values())
        stats["drop_reasons"] = dict(sorted(drop_reasons.items()))
    return json.dumps(config, ensure_ascii=False, indent=2) + "\n"


def render_sing_box_config(proxies: Iterable[Mapping[str, object]]) -> str:
    return render_sing_box_config_with_stats(proxies)


def render_artifacts(
    proxies: Iterable[Mapping[str, object]],
    *,
    base_url: str | None = None,
    metadata: dict[str, object] | None = None,
) -> dict[str, str]:
    proxy_list = [dict(proxy) for proxy in proxies]
    sing_box_stats: dict[str, object] = {}
    sing_box = render_sing_box_config_with_stats(proxy_list, sing_box_stats)
    if metadata is not None:
        metadata["sing_box_unsupported"] = sing_box_stats.get("unsupported", 0)
        metadata["sing_box_drop_reasons"] = sing_box_stats.get("drop_reasons", {})
    return {
        "clash/providers/aggregate.yaml": render_clash_provider(proxy_list),
        "clash/config.yaml": render_clash_config(proxy_list, base_url),
        "sing-box/config.json": sing_box,
        **(
            {"clash/config-provider.yaml": render_clash_http_provider_config(base_url)}
            if base_url
            else {}
        ),
    }
