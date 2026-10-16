from __future__ import annotations

import json
from pathlib import Path
from typing import cast
from urllib.parse import unquote

import pytest
import yaml

from aggregator import fastprobe
from aggregator import probe as probe_mod
from aggregator.__main__ import main
from aggregator.quality import node_key
from aggregator.validators import CoreValidationError


def _node(name: str) -> dict[str, object]:
    return {
        "name": name,
        "type": "ss",
        "server": "node.example.invalid",
        "port": 8443,
        "cipher": "aes-256-gcm",
        "password": "synthetic-password",
    }


class _FakeProcess:
    def poll(self) -> None:
        return None

    def terminate(self) -> None:
        return None

    def kill(self) -> None:
        return None

    def wait(self, timeout: float | None = None) -> int:
        return 0


def test_delay_backend_maps_delay_api_and_records_each_round(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configs: list[dict[str, object]] = []
    paths: list[str] = []
    monkeypatch.setattr(
        fastprobe,
        "_run_direct_control",
        lambda **_kwargs: "top-level",
    )
    monkeypatch.setattr(
        fastprobe.subprocess,
        "Popen",
        lambda command, **_kwargs: (
            configs.append(
                cast(
                    dict[str, object],
                    yaml.safe_load(
                        Path(command[command.index("-f") + 1]).read_text(
                            encoding="utf-8"
                        )
                    ),
                )
            )
            or _FakeProcess()
        ),
    )
    monkeypatch.setattr(
        fastprobe, "_wait_for_controller", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(fastprobe, "_stop_process", lambda _process: None)

    def fake_api(_base: str, path: str, **_kwargs: object) -> bytes:
        paths.append(path)
        encoded_name = path.split("/proxies/", 1)[1].split("/delay", 1)[0]
        name = unquote(encoded_name)
        if name == "bad node":
            return b'{"delay":"not-a-number"}'
        return b'{"delay":123}'

    monkeypatch.setattr(fastprobe, "_api_request", fake_api)

    result = fastprobe.probe_nodes(
        [_node("good node"), _node("bad node")],
        mihomo_path="/fake/mihomo",
        max_nodes=2,
        rounds=3,
        timeout=8,
        concurrency=2,
        probe_interface="WLAN",
    )

    assert result["backend"] == "delay"
    assert result["stage1_tested"] == 2
    assert result["stage1_passed"] == 1
    assert result["stage2_tested"] == 1
    assert result["stage2_stable"] == 1
    assert result["stage1_timeout_ms"] == 5000
    assert result["stage2_timeout_ms"] == 5000
    assert result["stable"] == 1
    assert len(paths) == 5
    assert all("timeout=5000" in path for path in paths)

    rows = cast(list[dict[str, object]], result["results"])
    good = next(row for row in rows if row["node_key"] == node_key(_node("good node")))
    bad = next(row for row in rows if row["node_key"] == node_key(_node("bad node")))
    assert good["rounds_passed"] == 3
    assert good["rounds_total"] == 3
    assert good["success_rate"] == 1.0
    assert good["round_latencies_ms"] == [123.0, 123.0, 123.0]
    assert bad["rounds_passed"] == 0
    assert bad["error_category"] == "invalid_response"
    serialized = json.dumps(result, ensure_ascii=False)
    for secret in (
        "good node",
        "bad node",
        "node.example.invalid",
        "synthetic-password",
    ):
        assert secret not in serialized

    config = configs[0]
    assert config["interface-name"] == "WLAN"
    assert config["dns"] == {
        "enable": True,
        "ipv6": False,
        "enhanced-mode": "normal",
        "nameserver": ["udp://223.5.5.5", "udp://119.29.29.29"],
        "default-nameserver": ["223.5.5.5", "119.29.29.29"],
    }
    assert config["allow-lan"] is False
    assert config["log-level"] == "silent"
    assert config["rules"] == ["MATCH,PROBE"]
    assert config["unified-delay"] is True


def test_delay_backend_batches_stage1_and_stage2(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[int, int, int]] = []
    monkeypatch.setattr(
        fastprobe,
        "_run_direct_control",
        lambda **_kwargs: "top-level",
    )

    def fake_batch(
        nodes: list[dict[str, object]], **kwargs: object
    ) -> list[dict[str, object]]:
        calls.append(
            (
                len(nodes),
                int(cast(int, kwargs["timeout_ms"])),
                int(cast(int, kwargs["concurrency"])),
            )
        )
        return [
            {
                "node_key": node_key(node),
                "ok": True,
                "delay": 100.0,
                "error": None,
            }
            for node in nodes
        ]

    monkeypatch.setattr(fastprobe, "_run_delay_batch", fake_batch)
    nodes = [_node(f"node-{index}") for index in range(401)]

    result = fastprobe.probe_nodes(
        nodes,
        mihomo_path="/fake/mihomo",
        max_nodes=401,
        rounds=3,
        timeout=8,
        concurrency=16,
        probe_interface="WLAN",
    )

    assert [item[0] for item in calls] == [400, 1, 400, 1, 400, 1, 400, 1]
    assert [item[1] for item in calls] == [5000] * 8
    assert all(item[2] == 16 for item in calls)
    assert result["stage1_tested"] == 401
    assert result["stage1_passed"] == 401
    assert result["stage2_tested"] == 401
    assert result["stage2_stable"] == 401
    assert result["stage1_timeout_ms"] == 5000
    assert result["stage2_timeout_ms"] == 5000
    assert result["tested"] == 401
    assert result["stable"] == 401


def test_delay_backend_supports_automatic_interface(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        fastprobe,
        "_run_direct_control",
        lambda **_kwargs: "auto",
    )
    monkeypatch.setattr(
        fastprobe,
        "_run_delay_batch",
        lambda nodes, **_kwargs: [
            {"node_key": node_key(node), "ok": True, "delay": 100.0, "error": None}
            for node in nodes
        ],
    )

    result = fastprobe.probe_nodes(
        [_node("node")],
        mihomo_path="/fake/mihomo",
        max_nodes=1,
        rounds=3,
        timeout=8,
        concurrency=1,
        probe_interface=None,
    )

    assert result["interface_mode"] == "auto"
    assert result["probe_interface"] is None


def test_delay_backend_automatic_control_uses_default_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[object, str]] = []

    def fake_control(**kwargs: object) -> bool:
        calls.append((kwargs["probe_interface"], str(kwargs["interface_mode"])))
        return True

    monkeypatch.setattr(probe_mod, "_run_direct_control_attempt", fake_control)

    assert (
        fastprobe._run_direct_control(
            mihomo_path="/fake/mihomo",
            timeout=1.0,
            probe_interface=None,
            proxy=_node("node"),
        )
        == "auto"
    )
    assert calls == [(None, "auto")]


def test_delay_backend_control_failure_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = {"batches": 0}

    def fail_control(**_kwargs: object) -> str:
        raise CoreValidationError("probe_direct_control_failed")

    def unexpected_batch(*_args: object, **_kwargs: object) -> list[dict[str, object]]:
        calls["batches"] += 1
        return []

    monkeypatch.setattr(fastprobe, "_run_direct_control", fail_control)
    monkeypatch.setattr(fastprobe, "_run_delay_batch", unexpected_batch)

    with pytest.raises(CoreValidationError, match="probe_direct_control_failed"):
        fastprobe.probe_nodes(
            [_node("node")],
            mihomo_path="/fake/mihomo",
            probe_interface="WLAN",
        )
    assert calls["batches"] == 0


def test_cli_delay_backend_allows_automatic_interface(monkeypatch) -> None:
    monkeypatch.setattr(
        "aggregator.__main__.run_pipeline",
        lambda *args, **kwargs: type(
            "Result",
            (),
            {"success": False, "failure_reason": "stop", "used_last_known_good": False},
        )(),
    )

    assert (
        main(
            [
                "run",
                "--probe",
                "--probe-backend",
                "delay",
                "--mihomo",
                "/fake/mihomo",
            ]
        )
        == 2
    )
