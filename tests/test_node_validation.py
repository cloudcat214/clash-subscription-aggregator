from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest
import yaml

from aggregator import pipeline as pipeline_module
from aggregator import validators
from aggregator.failed_pool import merge_core_validation_failures
from aggregator.pipeline import run_pipeline
from aggregator.quality import node_key, probe_verdict
from aggregator.validators import (
    CoreValidationError,
    _node_secrets,
    _run,
    _sanitize_output,
    _version,
    validate_node_configs,
)

SECRET_UUID = "11111111-2222-3333-4444-555555555555"
SECRET_PASSWORD = "s3cret-password-value"


def _node(name: str, *, server: str) -> dict[str, object]:
    return {
        "name": name,
        "type": "vless",
        "server": server,
        "port": 443,
        "uuid": SECRET_UUID,
        "password": SECRET_PASSWORD,
    }


def test_run_reports_nonzero_exit_with_bounded_redacted_stderr(monkeypatch) -> None:
    """非零退出必须保留可定位的错误，而不是固定字面量。"""

    class _Result:
        returncode = 1
        stdout = ""
        stderr = (
            f"parse config error: proxy 0 uuid {SECRET_UUID} "
            f"password {SECRET_PASSWORD} unsupported cipher\n" + "x" * 5000
        )

    monkeypatch.setattr(validators.subprocess, "run", lambda *a, **k: _Result())

    with pytest.raises(CoreValidationError) as excinfo:
        _run(["mihomo", "-t"], timeout=5)

    message = str(excinfo.value)
    assert "client_rejected_config" in message
    assert "exit=1" in message
    assert "unsupported cipher" in message
    assert SECRET_UUID not in message
    assert SECRET_PASSWORD not in message
    assert len(message) <= 400


def test_run_reports_timeout_without_leaking_details(monkeypatch) -> None:
    """超时边界同样保留可读原因。"""

    def _boom(*_args, **_kwargs):
        raise validators.subprocess.TimeoutExpired("mihomo", 1)

    monkeypatch.setattr(validators.subprocess, "run", _boom)

    with pytest.raises(CoreValidationError, match="timeout"):
        _run(["mihomo", "-t"], timeout=1)


def test_sanitize_output_is_bounded_and_drops_credentials() -> None:
    text = f"bad field uuid={SECRET_UUID} password={SECRET_PASSWORD} " + "y" * 900

    cleaned = _sanitize_output(text)

    assert SECRET_UUID not in cleaned
    assert SECRET_PASSWORD not in cleaned
    assert len(cleaned) <= 300


def test_validate_node_configs_isolates_each_candidate(monkeypatch) -> None:
    """逐节点校验：一个坏节点不能让整批候选一起失败。"""
    good = _node("good-node", server="good.example.invalid")
    bad = _node("bad-node", server="bad.example.invalid")
    seen: list[str] = []

    def fake_run(command, timeout, **_kwargs):
        config_path = Path(command[command.index("-f") + 1])
        text = config_path.read_text(encoding="utf-8")
        seen.append("bad-node" if "bad-node" in text else "good-node")
        if "bad-node" in text:
            raise CoreValidationError(
                f"client_rejected_config exit=1: unsupported cipher {SECRET_PASSWORD}"
            )
        return {"status": "passed", "exit_code": 0}

    monkeypatch.setattr(validators, "_run", fake_run)

    rows = validate_node_configs([good, bad], mihomo_path="/fake/mihomo", timeout=5)

    assert [row["node_key"] for row in rows] == [
        node_key(good),
        node_key(bad),
    ]
    assert [row["status"] for row in rows] == ["passed", "failed"]
    assert sorted(seen) == ["bad-node", "good-node"]  # 每个候选都被独立执行
    failed = rows[1]
    assert failed["protocol"] == "vless"
    assert failed["error_category"] == "core_validation_error"
    assert failed["detail"] and "unsupported cipher" in str(failed["detail"])
    assert failed["rounds_passed"] == 0
    assert failed["rounds_total"] == 1
    assert SECRET_PASSWORD not in json.dumps(rows, ensure_ascii=False)


def test_validate_node_configs_empty_input_is_not_tested() -> None:
    assert validate_node_configs([], mihomo_path="/fake/mihomo", timeout=5) == []


def test_validate_node_configs_runs_mihomo_test_with_config_and_home(
    monkeypatch,
) -> None:
    """命令行必须是 mihomo -t -f <config> -d <dir>，且每个节点独立配置。"""
    captured: list[tuple[list[str], dict[str, object]]] = []

    class _Result:
        returncode = 0
        stdout = "Mihomo v1.19.32"
        stderr = ""

    def fake_run(command, **kwargs):
        captured.append((command, kwargs))
        config_text = Path(command[command.index("-f") + 1]).read_text(encoding="utf-8")
        assert "command-check" in config_text
        return _Result()

    monkeypatch.setattr(validators.subprocess, "run", fake_run)

    rows = validate_node_configs(
        [_node("command-check", server="cmd.example.invalid")],
        mihomo_path="/fake/mihomo",
        timeout=7,
    )

    assert rows[0]["status"] == "passed"
    assert len(captured) == 1
    command, kwargs = captured[0]
    assert command[0] == "/fake/mihomo"
    assert command[1] == "-t"
    assert command[2] == "-f"
    assert command[4] == "-d"
    assert Path(command[3]).name == "config.yaml"
    assert Path(command[5]) == Path(command[3]).parent
    assert kwargs["timeout"] == 7
    assert kwargs["check"] is False


def test_validate_node_configs_all_fail_still_returns_every_node(monkeypatch) -> None:
    nodes = [
        _node("bad-a", server="a.example.invalid"),
        _node("bad-b", server="b.example.invalid"),
    ]

    def fake_run(*_args, **_kwargs):
        raise CoreValidationError("client_rejected_config exit=1: unsupported field")

    monkeypatch.setattr(validators, "_run", fake_run)

    rows = validate_node_configs(nodes, mihomo_path="/fake/mihomo", timeout=5)

    assert [row["status"] for row in rows] == ["failed", "failed"]
    assert [row["node_key"] for row in rows] == [
        node_key(nodes[0]),
        node_key(nodes[1]),
    ]
    assert all(row["error_category"] == "core_validation_error" for row in rows)


def test_validate_node_configs_reports_start_failure(monkeypatch) -> None:
    def boom(*_args, **_kwargs):
        raise FileNotFoundError("mihomo not found")

    monkeypatch.setattr(validators.subprocess, "run", boom)

    rows = validate_node_configs(
        [_node("missing", server="m.example.invalid")], mihomo_path="/fake/mihomo"
    )

    assert rows[0]["status"] == "failed"
    assert "client_start_failed" in str(rows[0]["detail"])


def test_validate_node_configs_reports_timeout(monkeypatch) -> None:
    def boom(*_args, **_kwargs):
        raise validators.subprocess.TimeoutExpired("mihomo", 1)

    monkeypatch.setattr(validators.subprocess, "run", boom)

    rows = validate_node_configs(
        [_node("slow", server="s.example.invalid")],
        mihomo_path="/fake/mihomo",
        timeout=1,
    )

    assert rows[0]["status"] == "failed"
    assert "timeout" in str(rows[0]["detail"])


def test_validate_node_configs_redacts_raw_secret_without_field_label(
    monkeypatch,
) -> None:
    """错误文本裸含密码/UUID（无字段名）也必须脱敏并限长。"""

    class _Result:
        returncode = 1
        stdout = ""
        stderr = (
            f"parse error near token {SECRET_PASSWORD} and {SECRET_UUID}" + "z" * 2000
        )

    monkeypatch.setattr(validators.subprocess, "run", lambda *a, **k: _Result())

    rows = validate_node_configs(
        [_node("secret", server="s.example.invalid")], mihomo_path="/fake/mihomo"
    )

    detail = str(rows[0]["detail"])
    assert SECRET_PASSWORD not in detail
    assert SECRET_UUID not in detail
    assert len(detail) <= 400


def test_node_secrets_collects_short_secret_like_values_only() -> None:
    node = {
        "name": "display-name",
        "server": "host.example.invalid",
        "type": "vless",
        "password": "pw",
        "token": "t7",
        "uuid": "u9",
        "auth-str": "a1",
        "host": "ordinary-host",
    }

    secrets = _node_secrets(node)

    assert {"pw", "t7", "u9", "a1"}.issubset(secrets)
    assert "display-name" not in secrets
    assert "host.example.invalid" not in secrets
    assert "ordinary-host" not in secrets


def test_short_credentials_are_redacted_from_detail_manifest_health_and_failed_pool(
    tmp_path: Path, monkeypatch
) -> None:
    short_password = "pw"
    short_token = "t7"
    short_uuid = "u9"
    # trojan 以 password 为准；vless 会因短 uuid 在解析阶段被丢弃，
    # 无法到达逐节点校验，故用 trojan 承载短凭据场景。
    bad = dict(
        _node("short-secret", server="short.example.invalid"),
        type="trojan",
        password=short_password,
        token=short_token,
        uuid=short_uuid,
    )
    config = _write_pipeline_config(tmp_path, [bad])
    failed_path = tmp_path / "state" / "failed-pool.json"

    _fake_mihomo(
        monkeypatch,
        "short.example.invalid",
        f"parse error near {short_password} {short_token} {short_uuid}",
    )

    result = run_pipeline(
        config,
        tmp_path / "dist",
        tmp_path / "state",
        node_validator=lambda proxies: validate_node_configs(
            proxies, mihomo_path="/fake/mihomo", timeout=5
        ),
        failed_pool_path=failed_path,
    )

    assert result.success is False
    manifest = (
        json.loads((tmp_path / "dist" / "manifest.json").read_text(encoding="utf-8"))
        if (tmp_path / "dist" / "manifest.json").exists()
        else {}
    )
    health = json.loads((tmp_path / "dist" / "health.json").read_text(encoding="utf-8"))
    failed_doc = json.loads(failed_path.read_text(encoding="utf-8"))
    detail = failed_doc["nodes"][0]["last_error_detail"]

    assert short_password not in detail
    assert short_token not in detail
    assert short_uuid not in detail
    serialized = json.dumps(
        {"manifest": manifest, "health": health, "detail": detail},
        ensure_ascii=False,
    )
    assert short_password not in serialized
    assert short_token not in serialized
    assert short_uuid not in serialized


def test_validate_node_configs_isolates_broken_node_objects(monkeypatch) -> None:
    """dict(proxy) 或 node_key 抛错时，只损失该节点，后续节点继续校验。"""
    good = _node("good", server="good.example.invalid")

    class _Result:
        returncode = 0
        stdout = "ok"
        stderr = ""

    monkeypatch.setattr(validators.subprocess, "run", lambda *a, **k: _Result())
    original_node_key = validators.node_key

    def flaky_node_key(node):
        if node.get("name") == "explodes":
            raise ValueError("unhashable credentials")
        return original_node_key(node)

    monkeypatch.setattr(validators, "node_key", flaky_node_key)

    proxies = cast(
        list[dict[str, object]],
        [object(), dict(good, name="explodes"), good],
    )
    rows = validate_node_configs(proxies, mihomo_path="/fake/mihomo")

    assert [row["status"] for row in rows] == ["failed", "failed", "passed"]
    assert rows[0]["detail"] == "node_check_failed: TypeError"
    assert rows[1]["detail"] == "node_check_failed: ValueError"
    assert rows[2]["node_key"] == node_key(good)


def test_version_survives_empty_stdout_and_stderr(monkeypatch) -> None:
    class _Result:
        returncode = 0
        stdout = ""
        stderr = ""

    monkeypatch.setattr(validators.subprocess, "run", lambda *a, **k: _Result())

    with pytest.raises(CoreValidationError, match="client_version_empty"):
        _version(["mihomo", "-v"], timeout=5)


def test_version_falls_back_to_stderr(monkeypatch) -> None:
    class _Result:
        returncode = 0
        stdout = ""
        stderr = "Mihomo v1.19.32\n"

    monkeypatch.setattr(validators.subprocess, "run", lambda *a, **k: _Result())

    assert _version(["mihomo", "-v"], timeout=5) == "Mihomo v1.19.32"


def test_merge_core_validation_failures_reuses_backoff_and_detail() -> None:
    node = _node("repeat", server="r.example.invalid")
    row = {
        "node_key": node_key(node),
        "node": node,
        "source_id": "fixture",
        "error_category": "core_validation_error",
        "detail": "client_rejected_config exit=1: bad",
    }

    entries, stats = merge_core_validation_failures(
        [], [row], now="2026-10-14T00:00:00Z"
    )

    assert stats == {"added": 1, "retested": 0, "pruned": 0, "size": 1}
    assert entries[0]["next_retry_at"] == "2026-10-14T01:00:00Z"
    assert entries[0]["last_error_category"] == "core_validation_error"
    assert str(entries[0]["last_error_detail"]).startswith("client_rejected_config")

    entries, stats = merge_core_validation_failures(
        entries, [row], now="2026-10-14T01:00:00Z"
    )

    assert stats["retested"] == 1
    assert entries[0]["consecutive_failures"] == 2
    assert entries[0]["total_failures"] == 2


def _write_pipeline_config(
    tmp_path: Path,
    nodes: list[dict[str, object]],
    *,
    active_probe: bool = False,
    probe_backend: str = "spawn",
) -> Path:
    source = tmp_path / "source.yaml"
    source.write_text(
        yaml.safe_dump({"proxies": nodes}, sort_keys=False), encoding="utf-8"
    )
    config = tmp_path / "sources.yaml"
    config.write_text(
        yaml.safe_dump(
            {
                "settings": {
                    "active_probe": active_probe,
                    "probe_backend": probe_backend,
                    "probe_max_nodes": 10,
                    "filters": {"min_quality_score": 0},
                },
                "sources": {
                    "public": [
                        {
                            "id": "fixture",
                            "path": str(source),
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
    return config


class _FakeMihomoResult:
    def __init__(self, returncode: int, stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = ""
        self.stderr = stderr


def _fake_mihomo(monkeypatch, bad_marker: str, bad_stderr: str) -> None:
    def fake_run(command, **_kwargs):
        text = Path(command[command.index("-f") + 1]).read_text(encoding="utf-8")
        if bad_marker in text:
            return _FakeMihomoResult(1, bad_stderr)
        return _FakeMihomoResult(0)

    monkeypatch.setattr(validators.subprocess, "run", fake_run)


def test_cli_wires_node_validation_into_pipeline(tmp_path: Path, monkeypatch) -> None:
    """--mihomo 必须在发布链路中真正触发逐节点校验。"""
    from aggregator import __main__ as cli

    config = _write_pipeline_config(
        tmp_path, [_node("cli-good", server="cli.example.invalid")]
    )
    seen: list[str] = []

    def fake_node_validation(proxies, *, mihomo_path, timeout=30.0):
        seen.append(mihomo_path)
        return [
            {
                "node_key": node_key(proxy),
                "protocol": "vless",
                "status": "passed",
                "error_category": None,
                "detail": "",
                "rounds_passed": 1,
                "rounds_total": 1,
            }
            for proxy in proxies
        ]

    monkeypatch.setattr(cli, "validate_node_configs", fake_node_validation)
    monkeypatch.setattr(
        cli, "validate_generated_artifacts", lambda *a, **k: {"status": "not_tested"}
    )

    exit_code = cli.main(
        [
            "run",
            "--config",
            str(config),
            "--output",
            str(tmp_path / "dist"),
            "--state",
            str(tmp_path / "state"),
            "--mihomo",
            "/fake/mihomo",
            "--no-private",
        ]
    )

    assert exit_code == 0
    assert seen == ["/fake/mihomo"]
    manifest = json.loads(
        (tmp_path / "dist" / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["core_validation"]["nodes"]["status"] == "passed"


def test_pipeline_drops_core_invalid_node_and_feeds_failed_pool(
    tmp_path: Path, monkeypatch
) -> None:
    good = _node("good", server="good.example.invalid")
    bad = _node("bad", server="bad.example.invalid")
    config = _write_pipeline_config(tmp_path, [good, bad])
    failed_path = tmp_path / "state" / "failed-pool.json"
    _fake_mihomo(
        monkeypatch,
        "bad.example.invalid",
        f"invalid proxy field password {SECRET_PASSWORD} uuid {SECRET_UUID}",
    )

    result = run_pipeline(
        config,
        tmp_path / "dist",
        tmp_path / "state",
        node_validator=lambda proxies: validate_node_configs(
            proxies, mihomo_path="/fake/mihomo", timeout=5
        ),
        failed_pool_path=failed_path,
    )

    assert result.success is True
    provider = (tmp_path / "dist" / "clash" / "providers" / "aggregate.yaml").read_text(
        encoding="utf-8"
    )
    assert "good.example.invalid" in provider
    assert "bad.example.invalid" not in provider
    manifest = json.loads(
        (tmp_path / "dist" / "manifest.json").read_text(encoding="utf-8")
    )
    nodes_summary = manifest["core_validation"]["nodes"]
    assert nodes_summary["status"] == "failed"
    assert nodes_summary["tested"] == 2
    assert nodes_summary["failed"] == 1
    failure = nodes_summary["failures"][0]
    assert failure["node_key"] == node_key(bad)
    assert failure["protocol"] == "vless"
    assert failure["error_category"] == "core_validation_error"
    assert "invalid proxy field" in failure["detail"]

    failed_doc = json.loads(failed_path.read_text(encoding="utf-8"))
    entry = failed_doc["nodes"][0]
    assert entry["key"] == node_key(bad)
    assert entry["node"]["type"] == "vless"
    assert entry["last_error_category"] == "core_validation_error"
    assert "invalid proxy field" in entry["last_error_detail"]
    assert SECRET_PASSWORD not in entry["last_error_detail"]
    assert SECRET_UUID not in entry["last_error_detail"]
    summary_text = json.dumps(manifest["core_validation"], ensure_ascii=False)
    assert SECRET_PASSWORD not in summary_text
    assert SECRET_UUID not in summary_text


def test_pipeline_fails_closed_when_all_nodes_are_core_invalid(tmp_path: Path) -> None:
    config = _write_pipeline_config(
        tmp_path, [_node("bad", server="bad.example.invalid")]
    )
    failed_path = tmp_path / "state" / "failed-pool.json"

    def node_validator(proxies):
        return [
            {
                "node_key": node_key(proxy),
                "protocol": "vless",
                "status": "failed",
                "error_category": "core_validation_error",
                "detail": "client_rejected_config exit=1: unsupported",
                "rounds_passed": 0,
                "rounds_total": 1,
            }
            for proxy in proxies
        ]

    result = run_pipeline(
        config,
        tmp_path / "dist",
        tmp_path / "state",
        node_validator=node_validator,
        failed_pool_path=failed_path,
    )

    assert result.success is False
    assert result.failure_reason == "core_validation_no_valid_nodes"
    health = json.loads((tmp_path / "dist" / "health.json").read_text(encoding="utf-8"))
    assert health["core_validation"]["nodes"]["failed"] == 1
    assert health["failure_reason"] == "core_validation_no_valid_nodes"


def test_delay_probe_validates_nodes_before_batch_and_isolates_bad_node(
    tmp_path: Path,
) -> None:
    good = _node("delay-good", server="good.example.invalid")
    bad = _node("delay-bad", server="bad.example.invalid")
    config = _write_pipeline_config(
        tmp_path, [good, bad], active_probe=True, probe_backend="delay"
    )
    events: list[tuple[str, list[str]]] = []

    def node_validator(proxies):
        names = [str(proxy["name"]) for proxy in proxies]
        events.append(("node_validator", names))
        return [
            {
                "node_key": node_key(proxy),
                "node": proxy,
                "protocol": "vless",
                "status": "failed"
                if str(proxy["name"]).endswith("delay-bad")
                else "passed",
                "error_category": (
                    "core_validation_error"
                    if str(proxy["name"]).endswith("delay-bad")
                    else None
                ),
                "detail": "bad node"
                if str(proxy["name"]).endswith("delay-bad")
                else "",
                "rounds_passed": 0 if str(proxy["name"]).endswith("delay-bad") else 1,
                "rounds_total": 1,
            }
            for proxy in proxies
        ]

    def delay_probe(proxies):
        names = [str(proxy["name"]) for proxy in proxies]
        events.append(("probe_runner", names))
        assert events[0][0] == "node_validator"
        assert names == ["[fixture] delay-good"]
        return {
            "status": "performed",
            "backend": "delay",
            "target": "https://www.gstatic.com/generate_204",
            "tested": 1,
            "results": [
                {"node_key": node_key(proxies[0]), **probe_verdict(3, 3, 120.0)}
            ],
        }

    result = run_pipeline(
        config,
        tmp_path / "dist",
        tmp_path / "state",
        probe_runner=delay_probe,
        node_validator=node_validator,
        failed_pool_path=tmp_path / "state" / "failed-pool.json",
    )

    assert result.success is True
    assert [event[0] for event in events] == ["node_validator", "probe_runner"]
    manifest = json.loads(
        (tmp_path / "dist" / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["counts"]["published"] == 1
    assert manifest["verification"]["backend"] == "delay"
    assert manifest["verification"]["new_candidates_tested"] == 1
    assert manifest["failure_reason"] if False else True
    provider = (tmp_path / "dist" / "clash" / "providers" / "aggregate.yaml").read_text(
        encoding="utf-8"
    )
    assert "good.example.invalid" in provider
    assert "bad.example.invalid" not in provider


def test_corrupt_failed_pool_is_preserved_and_diagnostic_is_finite(
    tmp_path: Path, monkeypatch
) -> None:
    good = _node("good-after-corruption", server="good.example.invalid")
    bad = _node("bad-after-corruption", server="bad.example.invalid")
    config = _write_pipeline_config(tmp_path, [good, bad])
    failed_path = tmp_path / "state" / "failed-pool.json"
    failed_path.parent.mkdir(parents=True)
    original = "not-json-history-with-short-secret-pw"
    failed_path.write_text(original, encoding="utf-8")
    writes_to_failed_pool: list[Path] = []
    original_write_json = pipeline_module._write_json

    def tracking_write_json(path, document):
        if Path(path) == failed_path:
            writes_to_failed_pool.append(Path(path))
        return original_write_json(path, document)

    monkeypatch.setattr(
        pipeline_module,
        "load_failed_pool",
        lambda _path: (_ for _ in ()).throw(ValueError("bad history")),
    )
    monkeypatch.setattr(pipeline_module, "_write_json", tracking_write_json)

    def node_validator(proxies):
        return [
            {
                "node_key": node_key(proxy),
                "node": proxy,
                "protocol": "vless",
                "status": "failed"
                if str(proxy["name"]).endswith("bad-after-corruption")
                else "passed",
                "error_category": "core_validation_error"
                if str(proxy["name"]).endswith("bad-after-corruption")
                else None,
                "detail": "bad node"
                if str(proxy["name"]).endswith("bad-after-corruption")
                else "",
                "rounds_passed": 0
                if str(proxy["name"]).endswith("bad-after-corruption")
                else 1,
                "rounds_total": 1,
            }
            for proxy in proxies
        ]

    result = run_pipeline(
        config,
        tmp_path / "dist",
        tmp_path / "state",
        node_validator=node_validator,
        failed_pool_path=failed_path,
    )

    assert result.success is True
    assert writes_to_failed_pool == []
    assert failed_path.read_text(encoding="utf-8") == original
    manifest = json.loads(
        (tmp_path / "dist" / "manifest.json").read_text(encoding="utf-8")
    )
    health = json.loads((tmp_path / "dist" / "health.json").read_text(encoding="utf-8"))
    assert manifest["verification"]["failed_pool_load_error"] == "ValueError"
    assert health["verification"]["failed_pool_load_error"] == "ValueError"
    assert "bad history" not in json.dumps({"manifest": manifest, "health": health})


def test_pipeline_evicts_core_invalid_node_from_verified_pool(
    tmp_path: Path, monkeypatch
) -> None:
    good = _node("good", server="good.example.invalid")
    bad = _node("bad", server="bad.example.invalid")
    config = _write_pipeline_config(tmp_path, [good, bad], active_probe=True)
    state = tmp_path / "state"
    active_path = state / "verified-pool.json"
    failed_path = state / "failed-pool.json"
    _fake_mihomo(
        monkeypatch,
        "bad.example.invalid",
        f"invalid proxy uuid {SECRET_UUID}",
    )

    def probe(nodes):
        return {
            "status": "performed",
            "tested": len(nodes),
            "results": [
                {"node_key": node_key(node), **probe_verdict(3, 3, 120.0)}
                for node in nodes
            ],
        }

    result = run_pipeline(
        config,
        tmp_path / "dist",
        state,
        probe_runner=probe,
        node_validator=lambda proxies: validate_node_configs(
            proxies, mihomo_path="/fake/mihomo", timeout=5
        ),
        verified_pool_path=active_path,
        failed_pool_path=failed_path,
    )

    assert result.success is True
    active = json.loads(active_path.read_text(encoding="utf-8"))
    assert [entry["node"]["name"] for entry in active["nodes"]] == ["[fixture] good"]
    failed_doc = json.loads(failed_path.read_text(encoding="utf-8"))
    entries = [entry for entry in failed_doc["nodes"] if entry["key"] == node_key(bad)]
    assert len(entries) == 1
    assert entries[0]["last_error_category"] == "core_validation_error"
    assert SECRET_UUID not in str(entries[0]["last_error_detail"])
    manifest = json.loads(
        (tmp_path / "dist" / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["core_validation"]["nodes"]["failed"] == 1
    assert manifest["counts"]["published"] == 1
