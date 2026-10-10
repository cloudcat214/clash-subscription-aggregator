from __future__ import annotations

import json
import math
import secrets
import socket
import subprocess
import tempfile
import time
from collections import Counter
from collections.abc import Iterable, Mapping
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener

import yaml

from .quality import node_key, probe_verdict
from .validators import CoreValidationError

DEFAULT_TARGET_URL = "https://www.gstatic.com/generate_204"
DIRECT_CONTROL_URL = "http://www.baidu.com"
MAX_PROBE_TIMEOUT_SECONDS = 30.0
DIRECT_DNS_CONFIG = {
    "enable": True,
    "ipv6": False,
    "enhanced-mode": "normal",
    "nameserver": ["udp://223.5.5.5", "udp://119.29.29.29"],
    "default-nameserver": ["223.5.5.5", "119.29.29.29"],
}
PROBE_ERROR_CATEGORIES = frozenset(
    {
        "timeout",
        "http_error",
        "network_error",
        "invalid_response",
        "invalid_probe_result",
        "invalid_probe_policy",
        "probe_unavailable",
        "process_start_error",
        "process_exit",
        "controller_timeout",
        "controller_auth_error",
        "controller_http_error",
        "probe_direct_control_failed",
        "probe_interface_invalid",
        "probe_interface_required",
        "core_validation_error",
        "probe_error",
    }
)

_CORE_ERROR_CATEGORIES = {
    "probe_process_start_failed": "process_start_error",
    "probe_process_exited": "process_exit",
    "probe_controller_timeout": "controller_timeout",
    "probe_controller_auth_failed": "controller_auth_error",
    "probe_controller_http_error": "controller_http_error",
    "probe_direct_control_failed": "probe_direct_control_failed",
    "probe_interface_invalid": "probe_interface_invalid",
    "probe_interface_required": "probe_interface_required",
}


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _api_request(
    base_url: str,
    path: str,
    *,
    method: str = "GET",
    payload: object | None = None,
    timeout: float,
    headers: Mapping[str, str] | None = None,
) -> bytes:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request_headers = dict(headers or {})
    if data is not None:
        request_headers.setdefault("Content-Type", "application/json")
    request = Request(
        f"{base_url}{path}",
        data=data,
        method=method,
        headers=request_headers,
    )
    opener = build_opener(ProxyHandler({}))
    with opener.open(request, timeout=timeout) as response:
        return response.read()


def _error_category(exc: Exception) -> str:
    if isinstance(exc, (TimeoutError, subprocess.TimeoutExpired)) or (
        isinstance(exc, URLError) and isinstance(exc.reason, TimeoutError)
    ):
        return "timeout"
    if isinstance(exc, HTTPError):
        return "http_error"
    if isinstance(exc, (OSError, URLError)):
        return "network_error"
    if isinstance(exc, (TypeError, ValueError)):
        return "invalid_response"
    return "probe_error"


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    """Stop a worker without masking the probe result or leaking a process."""
    try:
        if process.poll() is None:
            process.terminate()
    except (AttributeError, OSError):
        pass
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except OSError:
            pass
        else:
            try:
                process.wait(timeout=3)
            except (OSError, subprocess.TimeoutExpired):
                pass
    except OSError:
        pass


def _p95(values: list[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return round(ordered[math.ceil(0.95 * len(ordered)) - 1], 1)


def _probe_config(
    proxy: Mapping[str, object],
    *,
    mixed_port: int,
    controller_port: int,
    controller_secret: str,
    probe_interface: str | None = None,
    interface_mode: str = "top-level",
    direct_control: bool = False,
) -> dict[str, object]:
    node = dict(proxy)
    config: dict[str, object] = {
        "mixed-port": mixed_port,
        "bind-address": "127.0.0.1",
        "allow-lan": False,
        "mode": "rule",
        "log-level": "silent",
        "external-controller": f"127.0.0.1:{controller_port}",
        "secret": controller_secret,
    }
    if probe_interface:
        config["dns"] = dict(DIRECT_DNS_CONFIG)
        if interface_mode == "top-level":
            config["interface-name"] = probe_interface
        elif interface_mode == "proxy":
            node["interface-name"] = probe_interface
        else:
            raise CoreValidationError("probe_interface_invalid")

    if direct_control:
        config["proxies"] = [node] if interface_mode == "proxy" else []
        config["proxy-groups"] = []
        config["rules"] = ["MATCH,DIRECT"]
    else:
        name = str(node["name"])
        config["proxies"] = [node]
        config["proxy-groups"] = [
            {"name": "PROBE", "type": "select", "proxies": [name]}
        ]
        config["rules"] = ["MATCH,PROBE"]
    return config


def _wait_for_controller(
    process: subprocess.Popen[bytes],
    *,
    controller: str,
    headers: Mapping[str, str],
    timeout: float,
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise CoreValidationError("probe_process_exited")
        try:
            _api_request(
                controller,
                "/version",
                timeout=min(1.0, timeout),
                headers=headers,
            )
            return
        except HTTPError as exc:
            if exc.code in {401, 403}:
                raise CoreValidationError("probe_controller_auth_failed") from exc
            raise CoreValidationError("probe_controller_http_error") from exc
        except (OSError, ValueError):
            time.sleep(0.1)
    raise CoreValidationError("probe_controller_timeout")


def _run_direct_control_attempt(
    *,
    mihomo_path: str,
    timeout: float,
    probe_interface: str,
    interface_mode: str,
    proxy: Mapping[str, object],
) -> bool:
    with tempfile.TemporaryDirectory(
        prefix="aggregator-mihomo-direct-control-"
    ) as temp:
        root = Path(temp)
        mixed_port = _free_port()
        controller_port = _free_port()
        controller_secret = secrets.token_urlsafe(32)
        config = _probe_config(
            proxy,
            mixed_port=mixed_port,
            controller_port=controller_port,
            controller_secret=controller_secret,
            probe_interface=probe_interface,
            interface_mode=interface_mode,
            direct_control=True,
        )
        config_path = root / "config.yaml"
        config_path.write_text(
            yaml.safe_dump(config, sort_keys=False), encoding="utf-8"
        )
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            process = subprocess.Popen(
                [mihomo_path, "-f", str(config_path), "-d", str(root)],
                cwd=root,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=creationflags,
            )
        except (OSError, TypeError, ValueError):
            return False

        controller = f"http://127.0.0.1:{controller_port}"
        controller_headers = {"Authorization": f"Bearer {controller_secret}"}
        try:
            _wait_for_controller(
                process,
                controller=controller,
                headers=controller_headers,
                timeout=timeout,
            )
            proxy_opener = build_opener(
                ProxyHandler(
                    {
                        "http": f"http://127.0.0.1:{mixed_port}",
                        "https": f"http://127.0.0.1:{mixed_port}",
                    }
                )
            )
            request = Request(
                DIRECT_CONTROL_URL,
                headers={"User-Agent": "clash-mihomo-aggregator-direct-control/0.1"},
            )
            with proxy_opener.open(request, timeout=timeout) as response:
                status = getattr(response, "status", None)
                if status is None and hasattr(response, "getcode"):
                    status = response.getcode()
                if status is not None and not 200 <= status < 400:
                    return False
                response.read(64)
            return True
        except Exception:  # noqa: BLE001 - control failures are fail-closed below
            return False
        finally:
            _stop_process(process)


def _run_direct_control(
    *,
    mihomo_path: str,
    timeout: float,
    probe_interface: str,
    proxy: Mapping[str, object],
) -> str:
    for interface_mode in ("top-level", "proxy"):
        if _run_direct_control_attempt(
            mihomo_path=mihomo_path,
            timeout=timeout,
            probe_interface=probe_interface,
            interface_mode=interface_mode,
            proxy=proxy,
        ):
            return interface_mode
    raise CoreValidationError("probe_direct_control_failed")


def _probe_one_node(
    proxy: Mapping[str, object],
    *,
    mihomo_path: str,
    rounds: int,
    timeout: float,
    target_url: str,
    probe_interface: str | None = None,
    interface_mode: str = "top-level",
) -> dict[str, object]:
    """Probe one node with a private process, controller, and loopback port."""
    with tempfile.TemporaryDirectory(prefix="aggregator-mihomo-probe-") as temp:
        root = Path(temp)
        mixed_port = _free_port()
        controller_port = _free_port()
        node = dict(proxy)
        name = str(node["name"])
        controller_secret = secrets.token_urlsafe(32)
        config = _probe_config(
            node,
            mixed_port=mixed_port,
            controller_port=controller_port,
            controller_secret=controller_secret,
            probe_interface=probe_interface,
            interface_mode=interface_mode,
        )
        config_path = root / "config.yaml"
        config_path.write_text(
            yaml.safe_dump(config, sort_keys=False), encoding="utf-8"
        )
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            process = subprocess.Popen(
                [mihomo_path, "-f", str(config_path), "-d", str(root)],
                cwd=root,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=creationflags,
            )
        except (OSError, TypeError, ValueError) as exc:
            raise CoreValidationError("probe_process_start_failed") from exc

        controller = f"http://127.0.0.1:{controller_port}"
        controller_headers = {"Authorization": f"Bearer {controller_secret}"}
        try:
            _wait_for_controller(
                process,
                controller=controller,
                headers=controller_headers,
                timeout=timeout,
            )

            proxy_opener = build_opener(
                ProxyHandler(
                    {
                        "http": f"http://127.0.0.1:{mixed_port}",
                        "https": f"http://127.0.0.1:{mixed_port}",
                    }
                )
            )
            successes = 0
            latencies: list[float] = []
            errors: list[str] = []
            for _ in range(rounds):
                try:
                    _api_request(
                        controller,
                        "/proxies/PROBE",
                        method="PUT",
                        payload={"name": name},
                        timeout=timeout,
                        headers=controller_headers,
                    )
                    started = time.perf_counter()
                    request = Request(
                        target_url,
                        headers={"User-Agent": "clash-mihomo-aggregator-probe/0.1"},
                    )
                    with proxy_opener.open(request, timeout=timeout) as response:
                        status = getattr(response, "status", None)
                        if status is None and hasattr(response, "getcode"):
                            status = response.getcode()
                        if status is not None and status != 204:
                            raise ValueError("unexpected_status")
                        response.read(64)
                    latencies.append((time.perf_counter() - started) * 1000)
                    successes += 1
                except Exception as exc:  # noqa: BLE001 - return only safe category
                    errors.append(_error_category(exc))
            average = round(sum(latencies) / len(latencies), 1) if latencies else None
            return probe_verdict(
                successes,
                rounds,
                average,
                p95_latency_ms=_p95(latencies),
                error_category=errors[0] if errors else None,
            )
        finally:
            _stop_process(process)


def _probe_task(
    proxy: Mapping[str, object],
    *,
    mihomo_path: str,
    rounds: int,
    timeout: float,
    target_url: str,
    probe_interface: str | None = None,
    interface_mode: str = "top-level",
) -> dict[str, object]:
    """Keep one worker failure isolated and return only redacted probe data."""
    try:
        result = _probe_one_node(
            proxy,
            mihomo_path=mihomo_path,
            rounds=rounds,
            timeout=timeout,
            target_url=target_url,
            probe_interface=probe_interface,
            interface_mode=interface_mode,
        )
        if not isinstance(result, dict):
            raise TypeError("probe_result_not_mapping")
        return result
    except CoreValidationError as exc:
        reason = str(exc)
        error_category = _CORE_ERROR_CATEGORIES.get(reason, "core_validation_error")
        return {
            **probe_verdict(0, rounds, None, error_category=error_category),
        }
    except Exception as exc:  # noqa: BLE001 - never expose worker exception text
        return {
            **probe_verdict(0, rounds, None, error_category=_error_category(exc)),
        }


def probe_nodes(
    proxies: Iterable[Mapping[str, object]],
    *,
    mihomo_path: str,
    max_nodes: int = 500,
    rounds: int = 3,
    timeout: float = 10.0,
    concurrency: int = 1,
    target_url: str = DEFAULT_TARGET_URL,
    probe_interface: str | None = None,
) -> dict[str, object]:
    """Probe a small bounded set through an isolated temporary Mihomo process."""
    if not mihomo_path:
        raise CoreValidationError("mihomo_path_missing_for_probe")
    if target_url != DEFAULT_TARGET_URL:
        raise CoreValidationError("probe_target_not_allowed")
    bounded_max_nodes = max(1, min(max_nodes, 500))
    bounded_nodes = [dict(proxy) for proxy in proxies][:bounded_max_nodes]
    bounded_rounds = max(1, min(rounds, 3))
    bounded_concurrency = max(1, min(concurrency, 8))
    try:
        requested_timeout = float(timeout)
    except (TypeError, ValueError):
        requested_timeout = 10.0
    bounded_timeout = (
        min(MAX_PROBE_TIMEOUT_SECONDS, max(0.1, requested_timeout))
        if math.isfinite(requested_timeout)
        else 10.0
    )
    if probe_interface is not None and not isinstance(probe_interface, str):
        raise CoreValidationError("probe_interface_invalid")
    normalized_interface = probe_interface.strip() if probe_interface else None
    if not bounded_nodes:
        return {
            "status": "not_tested",
            "reason": "no_nodes",
            "tested": 0,
            "verified": 0,
            "fast": 0,
            "stable": 0,
            "failed": 0,
            "rounds": bounded_rounds,
            "concurrency": bounded_concurrency,
            "max_nodes": bounded_max_nodes,
            "timeout_seconds": bounded_timeout,
            "execution_mode": "serial",
            "target": DEFAULT_TARGET_URL,
            "direct_control": {
                "status": "not_tested",
                "reason": "no_nodes",
            },
            "results": [],
        }

    interface_mode: str | None = None
    direct_control: dict[str, object] = {
        "status": "not_tested",
        "reason": "probe_interface_disabled",
    }
    if normalized_interface:
        interface_mode = _run_direct_control(
            mihomo_path=mihomo_path,
            timeout=bounded_timeout,
            probe_interface=normalized_interface,
            proxy=bounded_nodes[0],
        )
        direct_control = {
            "status": "passed",
            "target": DIRECT_CONTROL_URL,
            "interface_mode": interface_mode,
        }

    with ThreadPoolExecutor(max_workers=bounded_concurrency) as executor:
        futures = [
            executor.submit(
                _probe_task,
                proxy,
                mihomo_path=mihomo_path,
                rounds=bounded_rounds,
                timeout=bounded_timeout,
                target_url=DEFAULT_TARGET_URL,
                probe_interface=normalized_interface,
                interface_mode=interface_mode or "top-level",
            )
            for proxy in bounded_nodes
        ]
        results: list[dict[str, object]] = []
        for proxy, future in zip(bounded_nodes, futures):
            try:
                verdict = dict(future.result())
            except Exception as exc:  # noqa: BLE001 - redact unexpected worker faults
                verdict = {
                    **probe_verdict(
                        0,
                        bounded_rounds,
                        None,
                        error_category=_error_category(exc),
                    ),
                }
            results.append({"node_key": node_key(proxy), **verdict})

    verified_count = sum(1 for item in results if item["verified"])
    fast_count = sum(1 for item in results if item["fast"])
    stable_count = sum(1 for item in results if item["stable"])
    failed_count = sum(1 for item in results if not item["stable"])
    error_counts = Counter(
        str(item["error_category"])
        for item in results
        if item.get("error_category") in PROBE_ERROR_CATEGORIES
    )
    return {
        "status": "performed",
        "tested": len(results),
        "verified": verified_count,
        "fast": fast_count,
        "stable": stable_count,
        "failed": failed_count,
        "rounds": bounded_rounds,
        "concurrency": bounded_concurrency,
        "max_nodes": bounded_max_nodes,
        "timeout_seconds": bounded_timeout,
        "execution_mode": (
            "parallel" if bounded_concurrency > 1 and len(results) > 1 else "serial"
        ),
        "target": DEFAULT_TARGET_URL,
        "probe_interface": normalized_interface,
        "interface_mode": interface_mode,
        "direct_control": direct_control,
        "error_categories": dict(sorted(error_counts.items())),
        "results": results,
    }
