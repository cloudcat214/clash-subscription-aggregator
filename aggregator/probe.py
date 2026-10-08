from __future__ import annotations

import json
import socket
import subprocess
import tempfile
import time
from collections.abc import Iterable, Mapping
from pathlib import Path
from urllib.request import ProxyHandler, Request, build_opener

import yaml

from .validators import CoreValidationError


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
) -> bytes:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = Request(
        f"{base_url}{path}",
        data=data,
        method=method,
        headers={"Content-Type": "application/json"} if data is not None else {},
    )
    opener = build_opener(ProxyHandler({}))
    with opener.open(request, timeout=timeout) as response:
        return response.read()


def probe_nodes(
    proxies: Iterable[Mapping[str, object]],
    *,
    mihomo_path: str,
    max_nodes: int = 30,
    rounds: int = 3,
    timeout: float = 10.0,
    concurrency: int = 1,
    target_url: str = "https://www.gstatic.com/generate_204",
) -> dict[str, object]:
    """Probe a small bounded set through an isolated temporary Mihomo process."""
    if not mihomo_path:
        raise CoreValidationError("mihomo_path_missing_for_probe")
    bounded_nodes = [dict(proxy) for proxy in proxies][: max(1, min(max_nodes, 30))]
    bounded_rounds = max(1, min(rounds, 3))
    bounded_concurrency = max(1, min(concurrency, 4))
    if not bounded_nodes:
        return {
            "status": "not_tested",
            "reason": "no_nodes",
            "tested": 0,
            "verified": 0,
            "fast": 0,
            "rounds": bounded_rounds,
            "concurrency": bounded_concurrency,
        }

    with tempfile.TemporaryDirectory(prefix="aggregator-mihomo-probe-") as temp:
        root = Path(temp)
        mixed_port = _free_port()
        controller_port = _free_port()
        config = {
            "mixed-port": f"127.0.0.1:{mixed_port}",
            "allow-lan": False,
            "mode": "rule",
            "log-level": "silent",
            "external-controller": f"127.0.0.1:{controller_port}",
            "proxies": bounded_nodes,
            "proxy-groups": [
                {
                    "name": "PROBE",
                    "type": "select",
                    "proxies": [str(proxy["name"]) for proxy in bounded_nodes],
                }
            ],
            "rules": ["MATCH,PROBE"],
        }
        config_path = root / "config.yaml"
        config_path.write_text(
            yaml.safe_dump(config, sort_keys=False), encoding="utf-8"
        )
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        process = subprocess.Popen(
            [mihomo_path, "-f", str(config_path), "-d", str(root)],
            cwd=root,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=creationflags,
        )
        controller = f"http://127.0.0.1:{controller_port}"
        try:
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                try:
                    _api_request(controller, "/version", timeout=min(1.0, timeout))
                    break
                except OSError:
                    time.sleep(0.1)
            else:
                raise CoreValidationError("probe_controller_timeout")

            proxy_opener = build_opener(
                ProxyHandler(
                    {
                        "http": f"http://127.0.0.1:{mixed_port}",
                        "https": f"http://127.0.0.1:{mixed_port}",
                    }
                )
            )
            results: list[dict[str, object]] = []
            for proxy in bounded_nodes:
                name = str(proxy["name"])
                successes = 0
                latencies: list[float] = []
                for _ in range(bounded_rounds):
                    try:
                        _api_request(
                            controller,
                            "/proxies/PROBE",
                            method="PUT",
                            payload={"name": name},
                            timeout=timeout,
                        )
                        started = time.perf_counter()
                        request = Request(
                            target_url,
                            headers={"User-Agent": "clash-mihomo-aggregator-probe/0.1"},
                        )
                        with proxy_opener.open(request, timeout=timeout) as response:
                            response.read(64)
                        latencies.append((time.perf_counter() - started) * 1000)
                        successes += 1
                    except (OSError, ValueError):
                        continue
                verified = successes == bounded_rounds
                results.append(
                    {
                        "verified": verified,
                        "fast": verified
                        and bool(latencies)
                        and sum(latencies) / len(latencies) < 800,
                        "rounds_passed": successes,
                        "latency_ms": round(sum(latencies) / len(latencies), 1)
                        if latencies
                        else None,
                    }
                )
            verified_count = sum(1 for item in results if item["verified"])
            fast_count = sum(1 for item in results if item["fast"])
            return {
                "status": "performed",
                "tested": len(results),
                "verified": verified_count,
                "fast": fast_count,
                "rounds": bounded_rounds,
                "concurrency": bounded_concurrency,
                "target": "https://www.gstatic.com/generate_204",
            }
        finally:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
