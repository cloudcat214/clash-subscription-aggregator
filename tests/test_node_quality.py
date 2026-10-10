"""真实节点探测/评估功能的离线回归测试。

用户目标：自动采集节点 → 有限真实探测 → 确认真正可用 → 按成功率/延迟/稳定性评分 → 分层发布。

本文件只使用离线 fake 数据与 monkeypatch：
不启动真实 mihomo、不发真实网络请求、不读密钥。

公共 API（位于 `aggregator/quality.py`）：
    probe_verdict(rounds_passed, rounds, latency_ms=None) -> dict
        # 返回轮次、成功率、平均/p95 延迟及 verified/fast/stable 分层字段
        # verified 仅在 rounds_passed == rounds 且 rounds > 0 时为 True（100% 多轮通过）
    score_node(node, probe=None) -> float
        # 0..100：成功率优先、延迟次之、结构质量低权重；probe=None 记 not_tested（低分）
    classify_node(node, probe=None) -> str
        # 返回 "fast" / "verified" / "stable" / "failed" / "not_tested" 五层
    select_published(nodes, results) -> list[dict]
        # 丢弃 failed 节点；verified 优先；未探测节点标 not_tested 而非 verified

其中 probe 为 probe_verdict 的返回值（Mapping），results 为 {节点名: probe}。
"""

from __future__ import annotations

import json
import subprocess
import threading
import time
from pathlib import Path
from typing import cast

import pytest
import yaml

from aggregator import probe as probe_mod
from aggregator.pipeline import run_pipeline
from aggregator.probe import probe_nodes
from aggregator.validators import CoreValidationError

# --- 公共 API 导入保护 ---
try:
    from aggregator import quality  # type: ignore
except ImportError as exc:  # pragma: no cover - broken package state guard
    quality = None
    _QUALITY_MISSING = f"{type(exc).__name__}: {exc}"
else:
    _QUALITY_MISSING = None


def _quality():
    if quality is None:
        pytest.fail(
            "缺少节点质量评估 API `aggregator.quality`（导入失败："
            f"{_QUALITY_MISSING}）。节点探测 / 评分 / 分层发布契约不可用。"
        )
    return quality


def _node(name: str, server: str = "node.example.invalid") -> dict:
    return {
        "name": name,
        "type": "ss",
        "server": server,
        "port": 8443,
        "cipher": "aes-256-gcm",
        "password": "placeholder",
    }


def _patch_probe_runtime(monkeypatch, *, version_ok: bool = True) -> None:
    """Fake probe_nodes 的全部 I/O，使其完全离线运行。"""

    monkeypatch.setattr(probe_mod, "_free_port", lambda: 20000)

    class _FakeProcess:
        def poll(self):
            return None

        def terminate(self):
            return None

        def kill(self):
            return None

        def wait(self, timeout=None):
            return 0

    monkeypatch.setattr(
        probe_mod.subprocess, "Popen", lambda *args, **kwargs: _FakeProcess()
    )

    class _FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, n=None):
            return b""

    class _FakeOpener:
        def open(self, request, timeout=None):
            return _FakeResponse()

    monkeypatch.setattr(probe_mod, "build_opener", lambda handler=None: _FakeOpener())

    def fake_api(
        base_url,
        path,
        *,
        method="GET",
        payload=None,
        timeout=1.0,
        headers=None,
    ):
        if not version_ok:
            raise OSError("connection refused")
        return b"{}"

    monkeypatch.setattr(probe_mod, "_api_request", fake_api)


def _write_pipeline_inputs(
    tmp_path: Path,
    *,
    active_probe: bool,
    node_count: int = 2,
    settings_overrides: dict[str, object] | None = None,
) -> tuple[Path, Path, Path]:
    """写入离线节点 source 与管线配置。"""
    source_path = tmp_path / "source.yaml"
    proxies = []
    for index in range(node_count):
        if index == 0:
            name = "good-node"
            server = "good.example.invalid"
        elif index == 1:
            name = "bad-node"
            server = "bad.example.invalid"
        else:
            name = f"candidate-{index}"
            server = f"candidate-{index}.example.invalid"
        proxies.append(
            {
                "name": name,
                "type": "ss",
                "server": server,
                "port": 8443,
                "cipher": "aes-256-gcm",
                "password": "placeholder",
            }
        )
    settings = {
        "active_probe": active_probe,
        "filters": {"min_quality_score": 0},
    }
    settings.update(settings_overrides or {})
    source_path.write_text(
        yaml.safe_dump(
            {"proxies": proxies},
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    config_path = tmp_path / "sources.yaml"
    config_path.write_text(
        yaml.safe_dump(
            {
                "settings": settings,
                "sources": {
                    "public": [
                        {
                            "id": "src",
                            "path": str(source_path),
                            "enabled": True,
                            "publish": True,
                            "requires_review": False,
                        }
                    ],
                    "private": [],
                },
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    return config_path, tmp_path / "dist", tmp_path / "state"


# ---------------------------------------------------------------------------
# 行为 1：三轮结果逐节点保留 + 只有 100% 多轮通过才标 verified
# ---------------------------------------------------------------------------


def test_probe_nodes_retains_per_node_round_results(monkeypatch) -> None:
    """逐节点保留 rounds_passed / success_rate / latency_ms / verified。

    probe_nodes 的汇总之外还必须返回可供管线评分的 `results` 列表。
    """
    _patch_probe_runtime(monkeypatch)
    nodes = [{"name": "node-0"}, {"name": "node-1"}]

    result = probe_nodes(nodes, mihomo_path="/fake/mihomo", rounds=3, timeout=1.0)

    assert "results" in result
    per_node = cast("list[dict]", result["results"])
    assert len(per_node) == 2
    for item in per_node:
        assert "rounds_passed" in item
        assert "success_rate" in item
        assert "verified" in item
        assert "latency_ms" in item
    assert all(item["verified"] for item in per_node)


def test_probe_controller_uses_unique_memory_only_bearer_secrets(monkeypatch) -> None:
    """每个临时 Mihomo controller 都必须使用独立的高熵 Bearer secret。"""
    configs: list[dict[str, object]] = []
    controller_requests: list[tuple[str, str, dict[str, str] | None]] = []
    ports = iter(range(20000, 20010))
    monkeypatch.setattr(probe_mod, "_free_port", lambda: next(ports))

    class _FakeProcess:
        def poll(self):
            return None

        def terminate(self):
            return None

        def kill(self):
            return None

        def wait(self, timeout=None):
            return 0

    def fake_popen(command, **_kwargs):
        config_path = Path(command[command.index("-f") + 1])
        configs.append(yaml.safe_load(config_path.read_text(encoding="utf-8")))
        return _FakeProcess()

    class _FakeResponse:
        status = 204

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, n=None):
            return b""

    class _FakeOpener:
        def open(self, request, timeout=None):
            return _FakeResponse()

    def fake_api(
        base_url,
        path,
        *,
        method="GET",
        payload=None,
        timeout=1.0,
        headers=None,
    ):
        controller_requests.append((base_url, path, headers))
        return b"{}"

    monkeypatch.setattr(probe_mod.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(probe_mod, "build_opener", lambda handler=None: _FakeOpener())
    monkeypatch.setattr(probe_mod, "_api_request", fake_api)

    result = probe_nodes(
        [{"name": "node-0"}, {"name": "node-1"}],
        mihomo_path="/fake/mihomo",
        rounds=1,
        timeout=1.0,
        concurrency=2,
    )

    secrets = [str(config["secret"]) for config in configs]
    assert len(secrets) == 2
    assert len(set(secrets)) == 2
    assert all(len(value) >= 32 for value in secrets)
    assert all(isinstance(config["mixed-port"], int) for config in configs)
    assert all(config["bind-address"] == "127.0.0.1" for config in configs)
    controller_secrets = {
        f"http://{config['external-controller']}": str(config["secret"])
        for config in configs
    }
    assert controller_requests
    for base_url, _path, headers in controller_requests:
        assert headers == {"Authorization": f"Bearer {controller_secrets[base_url]}"}
    serialized = json.dumps(result)
    assert all(secret not in serialized for secret in secrets)


def test_probe_nodes_injects_direct_egress_settings_only_when_requested(
    monkeypatch,
) -> None:
    configs: list[dict[str, object]] = []
    ports = iter(range(20000, 20020))
    monkeypatch.setattr(probe_mod, "_free_port", lambda: next(ports))

    class _FakeProcess:
        def poll(self):
            return None

        def terminate(self):
            return None

        def kill(self):
            return None

        def wait(self, timeout=None):
            return 0

    def fake_popen(command, **_kwargs):
        config_path = Path(command[command.index("-f") + 1])
        configs.append(yaml.safe_load(config_path.read_text(encoding="utf-8")))
        return _FakeProcess()

    class _FakeResponse:
        status = 204

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, n=None):
            return b"ok"

    class _FakeOpener:
        def open(self, request, timeout=None):
            return _FakeResponse()

    monkeypatch.setattr(probe_mod.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(probe_mod, "build_opener", lambda handler=None: _FakeOpener())
    monkeypatch.setattr(probe_mod, "_api_request", lambda *args, **kwargs: b"{}")

    direct = probe_nodes(
        [{"name": "node-0"}],
        mihomo_path="/fake/mihomo",
        rounds=1,
        timeout=1.0,
        probe_interface="WLAN",
    )

    assert direct["direct_control"] == {
        "status": "passed",
        "target": "http://www.baidu.com",
        "interface_mode": "top-level",
    }
    assert len(configs) == 2
    for config in configs:
        assert config["interface-name"] == "WLAN"
        assert config["dns"] == {
            "enable": True,
            "ipv6": False,
            "enhanced-mode": "normal",
            "nameserver": ["udp://223.5.5.5", "udp://119.29.29.29"],
            "default-nameserver": ["223.5.5.5", "119.29.29.29"],
        }
    direct_control_config = configs[1]
    control_proxies = cast(list[dict[str, object]], direct_control_config["proxies"])
    assert "interface-name" not in control_proxies[0]

    configs.clear()
    legacy = probe_nodes(
        [{"name": "node-0"}],
        mihomo_path="/fake/mihomo",
        rounds=1,
        timeout=1.0,
    )

    legacy_control = cast(dict[str, object], legacy["direct_control"])
    assert legacy_control["status"] == "not_tested"
    assert len(configs) == 1
    assert "interface-name" not in configs[0]
    assert "dns" not in configs[0]


def test_probe_direct_control_failure_is_fail_closed(monkeypatch) -> None:
    configs: list[dict[str, object]] = []
    ports = iter(range(20000, 20020))
    monkeypatch.setattr(probe_mod, "_free_port", lambda: next(ports))

    class _FakeProcess:
        def poll(self):
            return None

        def terminate(self):
            return None

        def kill(self):
            return None

        def wait(self, timeout=None):
            return 0

    def fake_popen(command, **_kwargs):
        config_path = Path(command[command.index("-f") + 1])
        configs.append(yaml.safe_load(config_path.read_text(encoding="utf-8")))
        return _FakeProcess()

    class _FakeResponse:
        status = 204

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, n=None):
            return b"ok"

    class _FakeOpener:
        def open(self, request, timeout=None):
            if request.full_url == "http://www.baidu.com":
                raise OSError("direct control unavailable")
            return _FakeResponse()

    monkeypatch.setattr(probe_mod.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(probe_mod, "build_opener", lambda handler=None: _FakeOpener())
    monkeypatch.setattr(probe_mod, "_api_request", lambda *args, **kwargs: b"{}")

    with pytest.raises(CoreValidationError, match="probe_direct_control_failed"):
        probe_nodes(
            [{"name": "node-0"}],
            mihomo_path="/fake/mihomo",
            rounds=1,
            timeout=1.0,
            probe_interface="WLAN",
        )

    assert len(configs) == 2
    assert all(config["rules"] == ["MATCH,DIRECT"] for config in configs)


def test_probe_nodes_uses_bounded_parallel_node_tasks(monkeypatch) -> None:
    """并发参数必须让不同节点任务真实重叠，且结果顺序稳定。"""
    active = 0
    maximum_active = 0
    lock = threading.Lock()

    def fake_probe(proxy, **_kwargs):
        nonlocal active, maximum_active
        with lock:
            active += 1
            maximum_active = max(maximum_active, active)
        time.sleep(0.03)
        with lock:
            active -= 1
        return {
            "rounds_passed": 3,
            "rounds_total": 3,
            "success_rate": 1.0,
            "latency_ms": 10.0,
            "p95_latency_ms": 10.0,
            "verified": True,
            "fast": True,
            "stable": True,
            "error_category": None,
        }

    monkeypatch.setattr(probe_mod, "_probe_one_node", fake_probe, raising=False)
    nodes = [{"name": f"node-{index}"} for index in range(4)]

    result = probe_nodes(
        nodes,
        mihomo_path="/fake/mihomo",
        rounds=3,
        timeout=1.0,
        concurrency=3,
    )

    assert maximum_active >= 2
    assert result["execution_mode"] == "parallel"
    assert result["tested"] == 4
    results = cast(list[dict[str, object]], result["results"])
    assert [item["node_key"] for item in results] == [
        probe_mod.node_key(node) for node in nodes
    ]


def test_probe_node_task_exception_is_redacted_and_isolated(monkeypatch) -> None:
    """单个 worker 异常不得中止其他节点，也不得回显节点输入。"""
    _patch_probe_runtime(monkeypatch)

    def fake_probe(proxy, **_kwargs):
        if proxy["name"] == "bad-node":
            raise ValueError("secret-node-endpoint")
        return {
            "rounds_passed": 3,
            "rounds_total": 3,
            "success_rate": 1.0,
            "latency_ms": 10.0,
            "p95_latency_ms": 10.0,
            "verified": True,
            "fast": True,
            "stable": True,
            "error_category": None,
        }

    monkeypatch.setattr(probe_mod, "_probe_one_node", fake_probe, raising=False)
    result = probe_nodes(
        [{"name": "good-node"}, {"name": "bad-node"}],
        mihomo_path="/fake/mihomo",
        rounds=3,
        timeout=1.0,
        concurrency=2,
    )

    serialized = json.dumps(result)
    assert "secret-node-endpoint" not in serialized
    results = cast(list[dict[str, object]], result["results"])
    bad = next(
        item
        for item in results
        if item["node_key"] == probe_mod.node_key({"name": "bad-node"})
    )
    assert bad["rounds_passed"] == 0
    assert bad["error_category"] == "invalid_response"
    assert result["tested"] == 2


def test_probe_process_exit_is_redacted_and_isolated(monkeypatch) -> None:
    """Mihomo 提前退出只影响该节点，并保留有限错误分类。"""

    class _ExitedProcess:
        def poll(self):
            return 1

        def terminate(self):
            return None

        def kill(self):
            return None

        def wait(self, timeout=None):
            return 1

    monkeypatch.setattr(
        probe_mod.subprocess, "Popen", lambda *args, **kwargs: _ExitedProcess()
    )
    result = probe_nodes(
        [{"name": "failed-node"}],
        mihomo_path="/fake/mihomo",
        rounds=1,
        timeout=1.0,
    )

    assert result["status"] == "performed"
    assert result["tested"] == 1
    assert result["stable"] == 0
    assert result["error_categories"] == {"process_exit": 1}
    row = cast("list[dict]", result["results"])[0]
    assert row["error_category"] == "process_exit"
    assert "failed-node" not in json.dumps(result)


def test_probe_process_cleanup_kills_stuck_worker() -> None:
    """worker 不响应 terminate 时必须进入 kill 路径。"""
    events: list[str] = []

    class _StuckProcess:
        def poll(self):
            return None

        def terminate(self):
            events.append("terminate")

        def kill(self):
            events.append("kill")

        def wait(self, timeout=None):
            events.append("wait")
            if events.count("wait") == 1:
                raise subprocess.TimeoutExpired("mihomo", timeout or 0)
            return 0

    probe_mod._stop_process(cast("subprocess.Popen[bytes]", _StuckProcess()))

    assert events == ["terminate", "wait", "kill", "wait"]


def test_probe_verdict_only_full_multi_round_pass_is_verified() -> None:
    """部分成功（2/3）不得标 verified；只有 3/3 通过才 verified。"""
    q = _quality()
    full = q.probe_verdict(rounds_passed=3, rounds=3, latency_ms=150.0)
    partial = q.probe_verdict(rounds_passed=2, rounds=3, latency_ms=90.0)
    failed = q.probe_verdict(rounds_passed=0, rounds=3, latency_ms=None)

    assert full["verified"] is True
    assert full["success_rate"] == 1.0
    assert full["rounds_passed"] == 3
    assert full["latency_ms"] == 150.0

    assert partial["verified"] is False
    assert partial["success_rate"] == pytest.approx(2 / 3)

    assert failed["verified"] is False
    assert failed["success_rate"] == 0.0
    assert failed["latency_ms"] is None


def test_fast_is_latency_only_without_relaxing_stability() -> None:
    """fast 只记录延迟；低延迟的部分成功仍不能变成 verified。"""
    q = _quality()
    partial_fast = q.probe_verdict(rounds_passed=2, rounds=3, latency_ms=80.0)

    assert partial_fast["fast"] is True
    assert partial_fast["verified"] is False
    assert q.classify_node(_node("partial-fast"), partial_fast) == "stable"


# ---------------------------------------------------------------------------
# 行为 2：评分按成功率优先、延迟次之、结构质量低权重；分层可断言
# ---------------------------------------------------------------------------


def test_score_prioritizes_success_rate_then_latency_then_structure() -> None:
    q = _quality()

    # 100% 通过但很慢（5s）vs 部分通过但很快（10ms）：成功率必须优先
    score_slow_full = q.score_node(
        _node("slow-full"), q.probe_verdict(3, 3, latency_ms=5000.0)
    )
    score_fast_partial = q.score_node(
        _node("fast-partial"), q.probe_verdict(2, 3, latency_ms=10.0)
    )
    assert score_slow_full > score_fast_partial

    # 结构满分但未探测 vs 结构普通但 verified：不得用结构 quality_score 冒充可用性
    pristine_untested = {**_node("pristine"), "tls": True}
    score_pristine = q.score_node(pristine_untested, None)
    score_plain_verified = q.score_node(
        _node("plain-verified"), q.probe_verdict(3, 3, latency_ms=300.0)
    )
    assert score_plain_verified > score_pristine


def test_classify_node_separates_fast_verified_failed_not_tested() -> None:
    """稳定 / 快 / 失败 / 未探测分层必须可断言。"""
    q = _quality()
    node = _node("n")

    assert q.classify_node(node, q.probe_verdict(3, 3, 100.0)) == "fast"
    assert q.classify_node(node, q.probe_verdict(3, 3, 1500.0)) == "verified"
    assert q.classify_node(node, q.probe_verdict(1, 3, 80.0)) == "failed"
    assert q.classify_node(node, None) == "not_tested"


# ---------------------------------------------------------------------------
# 行为 3：探测结果参与发布筛选/排序
# ---------------------------------------------------------------------------


def test_select_published_verified_first_drops_failed_keeps_not_tested() -> None:
    q = _quality()
    nodes = [
        _node("a", "a.example.invalid"),
        _node("b", "b.example.invalid"),
        _node("c", "c.example.invalid"),
    ]
    results = {
        "a": q.probe_verdict(3, 3, 200.0),  # verified
        "b": q.probe_verdict(0, 3, None),  # failed
        # c 未探测 → 必须标 not_tested，而非 verified
    }

    selected = q.select_published(nodes, results)
    names = [node["name"] for node in selected]

    assert "b" not in names  # 失败节点不进 verified 产物
    assert names.index("a") < names.index("c")  # verified 优先于 not_tested

    c_node = next(node for node in selected if node["name"] == "c")
    assert c_node.get("verdict") == "not_tested"
    assert c_node.get("verified") is not True


def test_probe_verification_excludes_failed_nodes_from_publication(
    tmp_path: Path,
) -> None:
    """管线层：active_probe 下，失败节点不得进入公开 provider。

    active_probe 下，run_pipeline 必须用探测结果过滤/排序公开 proxies。
    """

    def fake_probe(proxies):
        per_node = []
        for proxy in proxies:
            ok = "bad" not in str(proxy.get("server", ""))
            per_node.append(
                {
                    "name": str(proxy["name"]),
                    "verified": ok,
                    "fast": ok,
                    "rounds_passed": 3 if ok else 0,
                    "success_rate": 1.0 if ok else 0.0,
                    "latency_ms": 120.0 if ok else None,
                }
            )
        return {
            "status": "performed",
            "tested": len(proxies),
            "verified": sum(1 for item in per_node if item["verified"]),
            "fast": sum(1 for item in per_node if item["fast"]),
            "results": per_node,
        }

    config_path, output_dir, state_dir = _write_pipeline_inputs(
        tmp_path, active_probe=True
    )

    result = run_pipeline(config_path, output_dir, state_dir, probe_runner=fake_probe)

    assert result.success is True
    provider = (output_dir / "clash" / "providers" / "aggregate.yaml").read_text(
        encoding="utf-8"
    )
    assert "bad.example.invalid" not in provider


def test_pipeline_reports_separate_probe_drop_categories_without_node_names(
    tmp_path: Path,
) -> None:
    """预算外未测、探测失败和质量不足必须分开计数且不回显节点。"""

    def fake_probe(proxies):
        results = []
        for proxy in proxies:
            name = str(proxy["name"])
            source_name = name.rsplit("] ", 1)[-1]
            if source_name == "bad-node":
                passed = 0
                error = "timeout"
            elif source_name == "candidate-2":
                passed = 1
                error = None
            else:
                passed = 3
                error = None
            results.append(
                {
                    "name": name,
                    "rounds_passed": passed,
                    "rounds_total": 3,
                    "latency_ms": 100.0 if passed else None,
                    "p95_latency_ms": 100.0 if passed else None,
                    "error_category": error,
                }
            )
        return {
            "status": "performed",
            "tested": len(results),
            "max_nodes": 3,
            "rounds": 3,
            "concurrency": 2,
            "timeout_seconds": 10.0,
            "results": results,
        }

    config_path, output_dir, state_dir = _write_pipeline_inputs(
        tmp_path,
        active_probe=True,
        node_count=4,
        settings_overrides={"probe_max_nodes": 3},
    )
    result = run_pipeline(config_path, output_dir, state_dir, probe_runner=fake_probe)

    assert result.success is True
    manifest = json.loads((output_dir / "manifest.json").read_text(encoding="utf-8"))
    health = json.loads((output_dir / "health.json").read_text(encoding="utf-8"))
    for document in (manifest, health):
        quality_counts = document["node_quality"]
        assert quality_counts["candidates"] == 4
        assert quality_counts["tested"] == 3
        assert quality_counts["not_tested"] == 1
        assert quality_counts["not_tested_budget"] == 1
        assert quality_counts["failed_probe"] == 1
        assert quality_counts["below_quality_threshold"] == 1
        assert quality_counts["dropped"] == 2
        assert quality_counts["published"] == 1
        encoded = json.dumps(document, ensure_ascii=False)
        assert "good-node" not in encoded
        assert "bad-node" not in encoded


@pytest.mark.parametrize(
    ("minimum_key", "expected_reason"),
    [
        ("probe_stable_min_rounds", "probe_rounds_below_stable_min_rounds"),
        ("probe_verified_min_rounds", "probe_rounds_below_verified_min_rounds"),
    ],
)
def test_pipeline_rejects_incompatible_probe_rounds_before_probe_runner(
    tmp_path: Path,
    minimum_key: str,
    expected_reason: str,
) -> None:
    """轮次与 verdict 门槛矛盾时，在调用探测前给出明确失败原因。"""
    calls = {"count": 0}

    def fake_probe(_proxies):
        calls["count"] += 1
        return {"status": "performed", "results": []}

    settings_overrides: dict[str, object] = {
        "probe_rounds": 2,
        minimum_key: 3,
    }
    if minimum_key == "probe_verified_min_rounds":
        settings_overrides["probe_stable_min_rounds"] = 1
    config_path, output_dir, state_dir = _write_pipeline_inputs(
        tmp_path,
        active_probe=True,
        settings_overrides=settings_overrides,
    )
    result = run_pipeline(config_path, output_dir, state_dir, probe_runner=fake_probe)

    assert result.success is False
    assert result.failure_reason == expected_reason
    assert calls["count"] == 0
    health = json.loads((output_dir / "health.json").read_text(encoding="utf-8"))
    assert health["verification"]["policy_error"] == expected_reason


# ---------------------------------------------------------------------------
# 行为 4：预算边界 + active_probe 默认关闭
# ---------------------------------------------------------------------------


def test_probe_budget_is_clamped_to_hard_limits(monkeypatch) -> None:
    """最大节点 500、轮数 3、并发 8，超出必须被钳制。"""
    _patch_probe_runtime(monkeypatch)
    nodes = [{"name": f"node-{index}"} for index in range(505)]

    result = probe_nodes(
        nodes,
        mihomo_path="/fake/mihomo",
        max_nodes=999,
        rounds=99,
        concurrency=99,
        timeout=1.0,
    )

    assert result["tested"] == 500
    assert result["rounds"] == 3
    assert result["concurrency"] == 8
    assert result["verified"] == 500


@pytest.mark.parametrize(
    ("setting", "value"),
    [
        ("probe_max_nodes", 501),
        ("probe_concurrency", 9),
        ("probe_publish_max_nodes", 501),
    ],
)
def test_pipeline_rejects_probe_settings_over_budget(
    tmp_path: Path, setting: str, value: int
) -> None:
    """配置的节点数/并发数超过本机探测预算时必须在 runner 前拒绝。"""
    calls = {"count": 0}

    def fake_probe(_proxies):
        calls["count"] += 1
        return {"status": "performed", "results": []}

    config_path, output_dir, state_dir = _write_pipeline_inputs(
        tmp_path,
        active_probe=True,
        settings_overrides={setting: value},
    )

    result = run_pipeline(config_path, output_dir, state_dir, probe_runner=fake_probe)

    assert result.success is False
    assert result.failure_reason == "probe_parameters_over_budget"
    assert calls["count"] == 0
    health = json.loads((output_dir / "health.json").read_text(encoding="utf-8"))
    assert health["verification"]["policy_error"] == "probe_parameters_over_budget"


def test_pipeline_allows_delay_backend_limits(tmp_path: Path) -> None:
    """delay 后端允许 2000 节点/16 并发，但仍走同一质量筛选。"""

    def fake_probe(proxies):
        return {
            "status": "performed",
            "backend": "delay",
            "tested": len(proxies),
            "max_nodes": 2000,
            "rounds": 3,
            "concurrency": 16,
            "timeout_seconds": 8.0,
            "stage1_tested": len(proxies),
            "stage1_passed": len(proxies),
            "stage2_tested": len(proxies),
            "stage2_stable": len(proxies),
            "results": [
                {
                    "name": proxy["name"],
                    "rounds_passed": 3,
                    "rounds_total": 3,
                    "latency_ms": 100.0,
                    "p95_latency_ms": 100.0,
                }
                for proxy in proxies
            ],
        }

    config_path, output_dir, state_dir = _write_pipeline_inputs(
        tmp_path,
        active_probe=True,
        settings_overrides={
            "probe_backend": "delay",
            "probe_interface": "WLAN",
            "probe_max_nodes": 2000,
            "probe_concurrency": 16,
        },
    )
    result = run_pipeline(config_path, output_dir, state_dir, probe_runner=fake_probe)

    assert result.success is True
    manifest = json.loads((output_dir / "manifest.json").read_text(encoding="utf-8"))
    verification = manifest["verification"]
    assert verification["backend"] == "delay"
    assert verification["stage1_tested"] == 2
    assert verification["stage1_passed"] == 2
    assert verification["stage2_tested"] == 2
    assert verification["stage2_stable"] == 2


@pytest.mark.parametrize(
    ("setting", "value"),
    [("probe_max_nodes", 2001), ("probe_concurrency", 17)],
)
def test_pipeline_rejects_delay_backend_over_budget(
    tmp_path: Path, setting: str, value: int
) -> None:
    calls = {"count": 0}

    def fake_probe(_proxies):
        calls["count"] += 1
        return {"status": "performed", "backend": "delay", "results": []}

    config_path, output_dir, state_dir = _write_pipeline_inputs(
        tmp_path,
        active_probe=True,
        settings_overrides={
            "probe_backend": "delay",
            "probe_interface": "WLAN",
            setting: value,
        },
    )
    result = run_pipeline(config_path, output_dir, state_dir, probe_runner=fake_probe)

    assert result.success is False
    assert result.failure_reason == "probe_parameters_over_budget"
    assert calls["count"] == 0


def test_pipeline_requires_interface_for_delay_backend(tmp_path: Path) -> None:
    calls = {"count": 0}

    def fake_probe(_proxies):
        calls["count"] += 1
        return {"status": "performed", "backend": "delay", "results": []}

    config_path, output_dir, state_dir = _write_pipeline_inputs(
        tmp_path,
        active_probe=True,
        settings_overrides={"probe_backend": "delay", "probe_interface": ""},
    )
    result = run_pipeline(config_path, output_dir, state_dir, probe_runner=fake_probe)

    assert result.success is False
    assert result.failure_reason == "probe_interface_required"
    assert calls["count"] == 0


@pytest.mark.parametrize(
    ("field", "value"),
    [("max_nodes", 501), ("concurrency", 9)],
)
def test_pipeline_rejects_reported_probe_parameters_over_budget(
    tmp_path: Path, field: str, value: int
) -> None:
    """runner 回报的节点数/并发数超过预算时不能被静默钳制。"""
    config_path, output_dir, state_dir = _write_pipeline_inputs(
        tmp_path, active_probe=True
    )

    def fake_probe(_proxies):
        return {
            "status": "performed",
            "tested": 0,
            "results": [],
            field: value,
        }

    result = run_pipeline(config_path, output_dir, state_dir, probe_runner=fake_probe)

    assert result.success is False
    assert result.failure_reason == "probe_parameters_over_budget"
    health = json.loads((output_dir / "health.json").read_text(encoding="utf-8"))
    assert health["failure_reason"] == "probe_parameters_over_budget"


def test_active_probe_default_false_does_not_trigger_probe(tmp_path: Path) -> None:
    """配置 active_probe=false（默认）时绝不调用 probe_runner。"""
    calls = {"count": 0}

    def fake_probe(proxies):
        calls["count"] += 1
        return {"status": "performed", "verified": 0}

    config_path, output_dir, state_dir = _write_pipeline_inputs(
        tmp_path, active_probe=False
    )

    result = run_pipeline(config_path, output_dir, state_dir, probe_runner=fake_probe)

    assert result.success is True
    assert calls["count"] == 0
    manifest = json.loads((output_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["active_probe"] is False
    assert manifest["verification"]["status"] == "not_tested"
    assert manifest["verification"]["reason"] == "active_probe_disabled"


# ---------------------------------------------------------------------------
# 行为 5：探测异常 / 核心启动失败不泄漏节点 URI/uuid/password
# ---------------------------------------------------------------------------


def test_probe_core_startup_failure_is_redacted(monkeypatch) -> None:
    """核心启动失败时，错误只返回脱敏 token，不泄漏任何节点凭据/端点。"""
    _patch_probe_runtime(monkeypatch, version_ok=False)
    secret_uuid = "22222222-2222-2222-2222-222222222222"
    secret_password = "s3cret-password"
    node = {
        "name": "leaky-node",
        "type": "vless",
        "server": "10.0.0.1",
        "port": 443,
        "uuid": secret_uuid,
        "password": secret_password,
    }

    result = probe_nodes([node], mihomo_path="/fake/mihomo", timeout=0.05)

    serialized = json.dumps(result)
    assert result["status"] == "performed"
    assert result["error_categories"] == {"controller_timeout": 1}
    assert secret_uuid not in serialized
    assert secret_password not in serialized
    assert "leaky-node" not in serialized
    assert "10.0.0.1" not in serialized


def test_all_probe_failures_preserve_lkg_and_redacted_categories(
    tmp_path: Path,
) -> None:
    """全节点无成功结果时只回退 LKG，不把未测节点发布。"""
    config_path, output_dir, state_dir = _write_pipeline_inputs(
        tmp_path, active_probe=False, node_count=2
    )
    assert run_pipeline(config_path, output_dir, state_dir).success is True
    previous_manifest = (output_dir / "manifest.json").read_text(encoding="utf-8")

    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    config["settings"]["active_probe"] = True
    config_path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")

    def failed_probe(proxies):
        return {
            "status": "performed",
            "tested": len(proxies),
            "max_nodes": 30,
            "rounds": 3,
            "concurrency": 2,
            "timeout_seconds": 10.0,
            "results": [
                {
                    "name": proxy["name"],
                    "rounds_passed": 0,
                    "rounds_total": 3,
                    "latency_ms": None,
                    "p95_latency_ms": None,
                    "error_category": "process_exit",
                }
                for proxy in proxies
            ],
        }

    result = run_pipeline(config_path, output_dir, state_dir, probe_runner=failed_probe)

    assert result.success is False
    assert result.failure_reason == "probe_no_qualified_nodes"
    assert result.used_last_known_good is True
    assert (output_dir / "manifest.json").read_text(
        encoding="utf-8"
    ) == previous_manifest
    health = json.loads((output_dir / "health.json").read_text(encoding="utf-8"))
    assert health["verification"]["status"] == "performed"
    assert health["verification"]["error_categories"] == {"process_exit": 2}
    assert health["node_quality"]["failed_probe"] == 2
    assert health["node_quality"]["published"] == 0
    encoded = json.dumps(health, ensure_ascii=False)
    assert "good-node" not in encoded
    assert "bad-node" not in encoded


def test_pipeline_maps_runner_failure_to_safe_category(tmp_path: Path) -> None:
    """即使 runner 级异常发生，health 也只保留有限分类。"""
    config_path, output_dir, state_dir = _write_pipeline_inputs(
        tmp_path, active_probe=True, node_count=1
    )

    def failed_runner(_proxies):
        raise CoreValidationError("probe_controller_timeout")

    result = run_pipeline(
        config_path, output_dir, state_dir, probe_runner=failed_runner
    )

    assert result.success is False
    assert result.failure_reason == "probe_execution_failed"
    health = json.loads((output_dir / "health.json").read_text(encoding="utf-8"))
    assert health["verification"]["error_category"] == "controller_timeout"
    assert "controller_timeout" in json.dumps(health)
    assert "probe_controller_timeout" not in json.dumps(health)


def test_pipeline_aborts_when_direct_control_fails(tmp_path: Path) -> None:
    config_path, output_dir, state_dir = _write_pipeline_inputs(
        tmp_path,
        active_probe=True,
        settings_overrides={"probe_interface": "WLAN"},
    )

    def failed_runner(_proxies):
        raise CoreValidationError("probe_direct_control_failed")

    result = run_pipeline(
        config_path, output_dir, state_dir, probe_runner=failed_runner
    )

    assert result.success is False
    assert result.failure_reason == "probe_direct_control_failed"
    health = json.loads((output_dir / "health.json").read_text(encoding="utf-8"))
    assert health["verification"]["error_category"] == "probe_direct_control_failed"
    assert health["failure_reason"] == "probe_direct_control_failed"
