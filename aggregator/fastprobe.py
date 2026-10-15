from __future__ import annotations

import json
import math
import secrets
import subprocess
import tempfile
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote

import yaml

from .probe import (
    DIRECT_CONTROL_URL,
    DIRECT_DNS_CONFIG,
    _api_request,
    _free_port,
    _run_direct_control,
    _stop_process,
    _wait_for_controller,
)
from .quality import node_key, probe_verdict
from .validators import CoreValidationError

BATCH_SIZE = 400
MAX_FASTPROBE_NODES = 2000
MAX_FASTPROBE_CONCURRENCY = 16
STAGE1_TIMEOUT_MS = 5000
STAGE2_TIMEOUT_MS = 5000
TARGET_URL = "https://www.gstatic.com/generate_204"

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


def _safe_core_category(exc: Exception) -> str:
    return _CORE_ERROR_CATEGORIES.get(str(exc), "core_validation_error")


def _failed_row(node: Mapping[str, object], error_category: str) -> dict[str, object]:
    return {
        "node_key": node_key(node),
        "ok": False,
        "delay": None,
        "error": error_category,
    }


def _delay_once(
    base_url: str,
    name: str,
    secret: str,
    timeout_ms: int,
    request_timeout: float,
) -> tuple[bool, float | None, str | None]:
    path = (
        f"/proxies/{quote(name, safe='')}/delay?timeout={timeout_ms}&url={TARGET_URL}"
    )
    try:
        raw = _api_request(
            base_url,
            path,
            timeout=request_timeout,
            headers={"Authorization": f"Bearer {secret}"},
        )
        payload = json.loads(raw.decode("utf-8"))
        delay = payload.get("delay")
        if (
            isinstance(delay, (int, float))
            and not isinstance(delay, bool)
            and math.isfinite(float(delay))
            and delay >= 0
        ):
            return True, float(delay), None
        return False, None, "invalid_response"
    except HTTPError:
        return False, None, "http_error"
    except (TimeoutError, URLError, OSError):
        return False, None, "network_error"
    except (TypeError, ValueError, UnicodeError):
        return False, None, "invalid_response"


def _batch_config(
    nodes: list[dict[str, object]],
    *,
    mixed_port: int,
    controller_port: int,
    controller_secret: str,
    probe_interface: str | None,
) -> dict[str, object]:
    config: dict[str, object] = {
        "mixed-port": mixed_port,
        "bind-address": "127.0.0.1",
        "allow-lan": False,
        "mode": "rule",
        "log-level": "silent",
        "external-controller": f"127.0.0.1:{controller_port}",
        "secret": controller_secret,
        "proxies": nodes,
        "proxy-groups": [
            {"name": "PROBE", "type": "select", "proxies": [n["name"] for n in nodes]}
        ],
        "rules": ["MATCH,PROBE"],
    }
    if probe_interface:
        config["interface-name"] = probe_interface
        config["dns"] = dict(DIRECT_DNS_CONFIG)
    return config


def _run_delay_batch(
    nodes: list[dict[str, object]],
    *,
    mihomo_path: str,
    timeout_ms: int,
    concurrency: int,
    timeout: float,
    probe_interface: str | None,
) -> list[dict[str, object]]:
    if not nodes:
        return []

    with tempfile.TemporaryDirectory(prefix="aggregator-mihomo-delay-") as temp:
        root = Path(temp)
        mixed_port = _free_port()
        controller_port = _free_port()
        controller_secret = secrets.token_urlsafe(32)
        config_path = root / "config.yaml"
        config_path.write_text(
            yaml.safe_dump(
                _batch_config(
                    nodes,
                    mixed_port=mixed_port,
                    controller_port=controller_port,
                    controller_secret=controller_secret,
                    probe_interface=probe_interface,
                ),
                sort_keys=False,
            ),
            encoding="utf-8",
        )
        try:
            process = subprocess.Popen(
                [mihomo_path, "-f", str(config_path), "-d", str(root)],
                cwd=root,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, TypeError, ValueError):
            return [_failed_row(node, "process_start_error") for node in nodes]

        controller = f"http://127.0.0.1:{controller_port}"
        headers = {"Authorization": f"Bearer {controller_secret}"}
        request_timeout = max(float(timeout), timeout_ms / 1000 + 2.0)
        try:
            try:
                _wait_for_controller(
                    process,
                    controller=controller,
                    headers=headers,
                    timeout=timeout,
                )
            except CoreValidationError as exc:
                return [_failed_row(node, _safe_core_category(exc)) for node in nodes]
            except Exception as exc:  # noqa: BLE001 - keep worker failures redacted
                return [_failed_row(node, _error_category(exc)) for node in nodes]

            def run_one(node: dict[str, object]) -> dict[str, object]:
                name = str(node.get("name") or "")
                ok, delay, error = _delay_once(
                    controller,
                    name,
                    controller_secret,
                    timeout_ms,
                    request_timeout,
                )
                return {
                    "node_key": node_key(node),
                    "ok": ok,
                    "delay": delay,
                    "error": error,
                }

            with ThreadPoolExecutor(max_workers=concurrency) as executor:
                futures = [executor.submit(run_one, node) for node in nodes]
                results: list[dict[str, object]] = []
                for node, future in zip(nodes, futures):
                    try:
                        results.append(dict(future.result()))
                    except Exception as exc:  # noqa: BLE001 - redact node failures
                        results.append(_failed_row(node, _error_category(exc)))
                return results
        finally:
            _stop_process(process)


def _round_result(
    node: Mapping[str, object],
    stage1: Mapping[str, object],
    rounds: Sequence[Mapping[str, object]],
    round_count: int,
) -> dict[str, object]:
    if not bool(stage1.get("ok")):
        verdict = probe_verdict(
            0,
            round_count,
            None,
            error_category=(
                str(stage1.get("error")) if stage1.get("error") else "network_error"
            ),
        )
        verdict["node_key"] = node_key(node)
        verdict["round_latencies_ms"] = []
        return verdict

    successes: list[float] = []
    for item in rounds:
        delay = item.get("delay")
        if (
            bool(item.get("ok"))
            and isinstance(delay, (int, float))
            and not isinstance(delay, bool)
        ):
            successes.append(float(delay))
    errors = [str(item["error"]) for item in rounds if item.get("error")]
    average = round(sum(successes) / len(successes), 1) if successes else None
    p95 = sorted(successes)[math.ceil(0.95 * len(successes)) - 1] if successes else None
    verdict = probe_verdict(
        len(successes),
        round_count,
        average,
        p95_latency_ms=round(float(p95), 1) if p95 is not None else None,
        error_category=errors[0]
        if errors
        else ("network_error" if not successes else None),
    )
    verdict["node_key"] = node_key(node)
    verdict["round_latencies_ms"] = [round(value, 1) for value in successes]
    return verdict


def probe_nodes(
    proxies: Iterable[Mapping[str, object]],
    *,
    mihomo_path: str,
    max_nodes: int = 500,
    rounds: int = 3,
    timeout: float = 10.0,
    concurrency: int = 1,
    target_url: str = TARGET_URL,
    probe_interface: str | None = None,
) -> dict[str, object]:
    """Probe nodes in Mihomo batches using the controller delay endpoint."""
    if not mihomo_path:
        raise CoreValidationError("mihomo_path_missing_for_probe")
    if target_url != TARGET_URL:
        raise CoreValidationError("probe_target_not_allowed")
    if probe_interface is not None and not isinstance(probe_interface, str):
        raise CoreValidationError("probe_interface_invalid")

    bounded_nodes = [dict(proxy) for proxy in proxies][
        : max(1, min(max_nodes, MAX_FASTPROBE_NODES))
    ]
    bounded_rounds = max(1, min(rounds, 3))
    bounded_concurrency = max(1, min(concurrency, MAX_FASTPROBE_CONCURRENCY))
    try:
        requested_timeout = float(timeout)
    except (TypeError, ValueError):
        requested_timeout = 10.0
    bounded_timeout = (
        min(30.0, max(0.1, requested_timeout))
        if math.isfinite(requested_timeout)
        else 10.0
    )
    interface = probe_interface.strip() if probe_interface else None
    if not bounded_nodes:
        return {
            "status": "not_tested",
            "reason": "no_nodes",
            "backend": "delay",
            "tested": 0,
            "verified": 0,
            "fast": 0,
            "stable": 0,
            "failed": 0,
            "rounds": bounded_rounds,
            "concurrency": bounded_concurrency,
            "max_nodes": max(1, min(max_nodes, MAX_FASTPROBE_NODES)),
            "timeout_seconds": bounded_timeout,
            "execution_mode": "serial",
            "target": TARGET_URL,
            "probe_interface": interface,
            "interface_mode": "auto" if interface is None else None,
            "direct_control": {"status": "not_tested", "reason": "no_nodes"},
            "stage1_tested": 0,
            "stage1_passed": 0,
            "stage2_tested": 0,
            "stage2_stable": 0,
            "results": [],
        }

    interface_mode = _run_direct_control(
        mihomo_path=mihomo_path,
        timeout=bounded_timeout,
        probe_interface=interface,
        proxy=bounded_nodes[0],
    )
    stage1_results: list[dict[str, object]] = []
    for start in range(0, len(bounded_nodes), BATCH_SIZE):
        stage1_results.extend(
            _run_delay_batch(
                bounded_nodes[start : start + BATCH_SIZE],
                mihomo_path=mihomo_path,
                timeout_ms=STAGE1_TIMEOUT_MS,
                concurrency=bounded_concurrency,
                timeout=bounded_timeout,
                probe_interface=interface,
            )
        )

    stage1_by_key = {str(item["node_key"]): item for item in stage1_results}
    passed_nodes = [
        node
        for node in bounded_nodes
        if bool(stage1_by_key.get(node_key(node), {}).get("ok"))
    ]
    stage2_by_key: dict[str, list[dict[str, object]]] = {
        node_key(node): [] for node in passed_nodes
    }
    for _ in range(bounded_rounds):
        round_results: list[dict[str, object]] = []
        for start in range(0, len(passed_nodes), BATCH_SIZE):
            round_results.extend(
                _run_delay_batch(
                    passed_nodes[start : start + BATCH_SIZE],
                    mihomo_path=mihomo_path,
                    timeout_ms=STAGE2_TIMEOUT_MS,
                    concurrency=bounded_concurrency,
                    timeout=bounded_timeout,
                    probe_interface=interface,
                )
            )
        for item in round_results:
            stage2_by_key.setdefault(str(item["node_key"]), []).append(item)

    results = [
        _round_result(
            node,
            stage1_by_key.get(node_key(node), _failed_row(node, "network_error")),
            stage2_by_key.get(node_key(node), []),
            bounded_rounds,
        )
        for node in bounded_nodes
    ]
    error_counts = Counter(
        str(item["error_category"]) for item in results if item.get("error_category")
    )
    stable_count = sum(1 for item in results if item["stable"])
    verified_count = sum(1 for item in results if item["verified"])
    fast_count = sum(1 for item in results if item["fast"])
    return {
        "status": "performed",
        "backend": "delay",
        "tested": len(results),
        "verified": verified_count,
        "fast": fast_count,
        "stable": stable_count,
        "failed": len(results) - stable_count,
        "rounds": bounded_rounds,
        "concurrency": bounded_concurrency,
        "max_nodes": max(1, min(max_nodes, MAX_FASTPROBE_NODES)),
        "timeout_seconds": bounded_timeout,
        "execution_mode": (
            "parallel" if bounded_concurrency > 1 and len(results) > 1 else "serial"
        ),
        "target": TARGET_URL,
        "probe_interface": interface,
        "interface_mode": interface_mode,
        "direct_control": {
            "status": "passed",
            "target": DIRECT_CONTROL_URL,
            "interface_mode": interface_mode,
        },
        "stage1_tested": len(bounded_nodes),
        "stage1_passed": len(passed_nodes),
        "stage2_tested": len(passed_nodes),
        "stage2_stable": stable_count,
        "error_categories": dict(sorted(error_counts.items())),
        "results": results,
    }
