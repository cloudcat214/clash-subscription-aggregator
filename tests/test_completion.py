from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml

from aggregator.outputs import render_clash_config
from aggregator.parsing import normalize_proxies, parse_uri
from aggregator.pipeline import initialize_dist, run_pipeline

FIXTURES = Path(__file__).parent / "fixtures"
SYNTH_UUID = "11111111-1111-1111-1111-111111111111"


def _write_config(
    path: Path,
    sources: list[dict[str, object]],
    *,
    max_shrink_ratio: float = 0.2,
    max_nodes: int = 0,
) -> None:
    path.write_text(
        yaml.safe_dump(
            {
                "settings": {
                    "active_probe": False,
                    "max_shrink_ratio": max_shrink_ratio,
                    "max_nodes": max_nodes,
                    "filters": {"min_quality_score": 0},
                },
                "sources": {"public": sources, "private": []},
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )


def test_remote_clash_config_is_self_contained_and_has_required_groups() -> None:
    config = yaml.safe_load(
        render_clash_config(
            [
                {
                    "name": "sample",
                    "type": "http",
                    "server": "node.example.invalid",
                    "port": 8080,
                }
            ]
        )
    )

    assert config["proxies"]
    assert "proxy-providers" not in config
    assert {group["type"] for group in config["proxy-groups"]} == {
        "select",
        "url-test",
        "fallback",
    }


def test_dedup_keeps_connectivity_fields() -> None:
    proxies = normalize_proxies(
        [
            {
                "name": "first",
                "type": "vless",
                "server": "node.example.invalid",
                "port": 443,
                "uuid": SYNTH_UUID,
                "flow": "xtls-rprx-vision",
            },
            {
                "name": "second",
                "type": "vless",
                "server": "node.example.invalid",
                "port": 443,
                "uuid": "22222222-2222-2222-2222-222222222222",
                "flow": "",
            },
        ]
    )

    assert len(proxies) == 2


def test_normalization_preserves_unknown_fields() -> None:
    proxies = normalize_proxies(
        [
            {
                "name": "first",
                "type": "http",
                "server": "node.example.invalid",
                "port": 8080,
                "custom-option": "retained",
            },
            {
                "name": "duplicate",
                "type": "http",
                "server": "node.example.invalid",
                "port": 8080,
                "custom-option": "retained",
            },
        ]
    )

    assert len(proxies) == 1
    assert proxies[0]["custom-option"] == "retained"


def test_duplicate_and_max_node_drops_are_counted(tmp_path: Path) -> None:
    config_path = tmp_path / "sources.yaml"
    source_path = tmp_path / "source.yaml"
    source_path.write_text(
        "proxies:\n"
        "  - name: first\n"
        "    type: http\n"
        "    server: one.example.invalid\n"
        "    port: 8080\n"
        "    custom-option: retained\n"
        "  - name: duplicate\n"
        "    type: http\n"
        "    server: one.example.invalid\n"
        "    port: 8080\n"
        "    custom-option: retained\n"
        "  - name: second\n"
        "    type: http\n"
        "    server: two.example.invalid\n"
        "    port: 8080\n",
        encoding="utf-8",
    )
    _write_config(
        config_path,
        [
            {
                "id": "fixture",
                "path": str(source_path),
                "enabled": True,
                "publish": True,
                "requires_review": False,
            }
        ],
        max_nodes=1,
    )

    result = run_pipeline(config_path, tmp_path / "dist", tmp_path / "state")

    assert result.success is True
    manifest = json.loads(
        (tmp_path / "dist" / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["drops"] == {"duplicate": 1, "max_nodes": 1}


def test_supported_uri_transports_and_reality_fields_are_retained() -> None:
    vless = parse_uri(
        f"vless://{SYNTH_UUID}@node.example.invalid:443?security=reality&"
        "type=tcp&sni=cdn.example.invalid&flow=xtls-rprx-vision&"
        "pbk=SYNTHETIC-PUBLIC-KEY&sid=abcd#reality"
    )
    trojan = parse_uri(
        "trojan://secret@node.example.invalid:443?type=ws&path=%2Ftrojan&"
        "host=cdn.example.invalid#trojan-ws"
    )
    shadowsocks = parse_uri(
        "ss://aes-256-gcm:secret@node.example.invalid:443/?"
        "plugin=v2ray-plugin%3Bmode%3Dwebsocket%3Bhost%3Dcdn.example.invalid#ss"
    )
    hysteria = parse_uri(
        "hysteria2://secret@node.example.invalid:443/?sni=cdn.example.invalid&"
        "obfs=salamander&obfs-password=obfs#h2"
    )
    tuic = parse_uri(
        f"tuic://{SYNTH_UUID}:secret@node.example.invalid:443?"
        "sni=cdn.example.invalid&congestion_control=bbr&reduce_rtt=true#tuic"
    )

    assert vless["reality-opts"] == {
        "public-key": "SYNTHETIC-PUBLIC-KEY",
        "short-id": "abcd",
    }
    assert vless["flow"] == "xtls-rprx-vision"
    assert trojan["network"] == "ws"
    assert trojan["ws-opts"] == {
        "path": "/trojan",
        "headers": {"Host": "cdn.example.invalid"},
    }
    assert shadowsocks["plugin"] == "v2ray-plugin"
    assert shadowsocks["plugin-opts"] == {
        "mode": "websocket",
        "host": "cdn.example.invalid",
    }
    assert hysteria["obfs"] == "salamander"
    assert hysteria["obfs-password"] == "obfs"
    assert tuic["congestion-controller"] == "bbr"
    assert tuic["reduce-rtt"] is True


def test_lkg_survives_failure_at_state_commit(tmp_path: Path, monkeypatch) -> None:
    config_path = tmp_path / "sources.yaml"
    source_path = tmp_path / "source.yaml"
    source_path.write_text(
        (FIXTURES / "clash.yaml").read_text(encoding="utf-8"), encoding="utf-8"
    )
    source = {
        "id": "fixture",
        "path": str(source_path),
        "enabled": True,
        "publish": True,
        "requires_review": False,
    }
    _write_config(config_path, [source])
    output_dir = tmp_path / "dist"
    state_dir = tmp_path / "state"

    assert run_pipeline(config_path, output_dir, state_dir).success is True
    previous = (output_dir / "manifest.json").read_text(encoding="utf-8")

    def fail_state_commit(*args, **kwargs):
        raise OSError("simulated state commit failure")

    monkeypatch.setattr("aggregator.pipeline._save_lkg", fail_state_commit)
    result = run_pipeline(config_path, output_dir, state_dir)

    assert result.success is False
    assert result.used_last_known_good is True
    assert (output_dir / "manifest.json").read_text(encoding="utf-8") == previous
    assert (
        json.loads((output_dir / "health.json").read_text(encoding="utf-8"))["status"]
        == "failed"
    )


def test_shrink_guard_rejects_unexpected_drop(tmp_path: Path) -> None:
    config_path = tmp_path / "sources.yaml"
    source_path = tmp_path / "source.yaml"
    source_path.write_text(
        (FIXTURES / "clash.yaml").read_text(encoding="utf-8"), encoding="utf-8"
    )
    source = {
        "id": "fixture",
        "path": str(source_path),
        "enabled": True,
        "publish": True,
        "requires_review": False,
    }
    _write_config(config_path, [source], max_shrink_ratio=0.75)
    output_dir = tmp_path / "dist"
    state_dir = tmp_path / "state"

    assert run_pipeline(config_path, output_dir, state_dir).success is True
    source_path.write_text(
        "proxies:\n"
        "  - name: only\n"
        "    type: http\n"
        "    server: only.example.invalid\n"
        "    port: 8080\n",
        encoding="utf-8",
    )
    result = run_pipeline(config_path, output_dir, state_dir)

    assert result.success is False
    assert result.failure_reason == "shrink_guard"
    assert result.used_last_known_good is True


def test_bootstrap_write_failure_preserves_existing_output(
    tmp_path: Path, monkeypatch
) -> None:
    output_dir = tmp_path / "dist"
    output_dir.mkdir()
    marker = output_dir / "existing.txt"
    marker.write_text("preserve", encoding="utf-8")

    def fail_write(*args, **kwargs):
        raise OSError("simulated bootstrap write failure")

    monkeypatch.setattr("aggregator.pipeline._write_text", fail_write)

    try:
        initialize_dist(output_dir)
    except OSError:
        pass
    else:
        raise AssertionError("bootstrap write failure must propagate")

    assert marker.read_text(encoding="utf-8") == "preserve"
    assert sorted(path.name for path in tmp_path.iterdir()) == ["dist"]


def test_manifest_artifact_hashes_match_written_files(tmp_path: Path) -> None:
    config_path = tmp_path / "sources.yaml"
    source_path = tmp_path / "source.yaml"
    source_path.write_text(
        (FIXTURES / "clash.yaml").read_text(encoding="utf-8"), encoding="utf-8"
    )
    _write_config(
        config_path,
        [
            {
                "id": "fixture",
                "path": str(source_path),
                "enabled": True,
                "publish": True,
                "requires_review": False,
            }
        ],
    )
    output_dir = tmp_path / "dist"

    assert run_pipeline(config_path, output_dir, tmp_path / "state").success is True
    manifest = json.loads((output_dir / "manifest.json").read_text(encoding="utf-8"))

    for artifact in manifest["artifacts"]:
        content = (output_dir / artifact["path"]).read_bytes()
        assert hashlib.sha256(content).hexdigest() == artifact["sha256"]
        assert len(content) == artifact["bytes"]


def test_workflow_keeps_pull_requests_offline_and_gates_publication() -> None:
    workflow = yaml.safe_load(
        (Path(__file__).parents[1] / ".github" / "workflows" / "update.yml").read_text(
            encoding="utf-8"
        )
    )
    triggers = workflow.get("on", workflow.get(True))
    assert set(triggers) == {"pull_request", "schedule", "workflow_dispatch"}
    assert triggers["schedule"] == [{"cron": "0 */6 * * *"}]
    assert triggers["workflow_dispatch"]["inputs"]["publish_nodes"]["default"] is False
    assert triggers["workflow_dispatch"]["inputs"]["publish_nodes"]["type"] == "boolean"
    assert set(workflow["jobs"]) == {"tests", "publish"}
    assert workflow["permissions"] == {"contents": "read"}
    assert workflow["jobs"]["tests"]["permissions"] == {"contents": "read"}
    assert workflow["jobs"]["publish"]["permissions"] == {
        "contents": "read",
        "pages": "write",
        "id-token": "write",
    }
    assert workflow["jobs"]["publish"]["concurrency"]["cancel-in-progress"] is False
    test_runs = [
        step.get("run", "")
        for step in workflow["jobs"]["tests"]["steps"]
        if isinstance(step, dict)
        and step.get("name") in {"Run offline tests", "Compile Python sources"}
    ]
    assert all("aggregator run" not in command for command in test_runs)
    assert all("curl" not in command for command in test_runs)
    assert "python -m pytest -q" in test_runs
    assert "python -m compileall -q aggregator tests" in test_runs
    serialized = json.dumps(workflow)
    assert "PUBLIC_NODE_REDISTRIBUTION_APPROVED" in serialized
    assert "actions/upload-pages-artifact@v3" in serialized
    assert "actions/deploy-pages@v4" in serialized
    assert "--no-private" in serialized
    assert "--require-core" in serialized
