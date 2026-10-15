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
    assert all(
        group.get("timeout") == 5000
        for group in config["proxy-groups"]
        if group["type"] in {"url-test", "fallback"}
    )


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


def test_two_public_sources_can_publish_when_one_source_is_empty(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "sources.yaml"
    source_a = tmp_path / "source-a.yaml"
    source_b = tmp_path / "source-b.yaml"
    empty_source = tmp_path / "empty-trojan.yaml"
    for path, name in ((source_a, "source-a"), (source_b, "source-b")):
        path.write_text(
            "proxies:\n"
            f"  - name: {name}\n"
            "    type: http\n"
            f"    server: {name}.example.invalid\n"
            "    port: 8080\n",
            encoding="utf-8",
        )
    empty_source.write_text(
        "proxies:\n"
        "  - name: missing-password\n"
        "    type: trojan\n"
        "    server: empty.example.invalid\n"
        "    port: 443\n",
        encoding="utf-8",
    )
    _write_config(
        config_path,
        [
            {
                "id": "source-a",
                "path": str(source_a),
                "enabled": True,
                "publish": True,
                "requires_review": False,
            },
            {
                "id": "source-b",
                "path": str(source_b),
                "enabled": True,
                "publish": True,
                "requires_review": False,
            },
            {
                "id": "empty-trojan",
                "path": str(empty_source),
                "enabled": True,
                "publish": True,
                "requires_review": False,
            },
        ],
    )

    output_dir = tmp_path / "dist"
    state_dir = tmp_path / "state"
    result = run_pipeline(config_path, output_dir, state_dir)

    assert result.success is True
    manifest = json.loads((output_dir / "manifest.json").read_text(encoding="utf-8"))
    health = json.loads((output_dir / "health.json").read_text(encoding="utf-8"))
    manifest_sources = {item["id"]: item for item in manifest["sources"]}
    health_sources = {item["id"]: item for item in health["sources"]}

    assert manifest["counts"]["published"] == 2
    assert all(item["status"] == "ok" for item in manifest_sources.values())
    assert manifest_sources["source-a"]["accepted"] == 1
    assert manifest_sources["source-b"]["accepted"] == 1
    assert manifest_sources["empty-trojan"]["accepted"] == 0
    assert manifest_sources["empty-trojan"]["drops"] == {"missing_password": 1}
    assert health["status"] == "ok"
    assert health_sources["empty-trojan"]["drops"] == {"missing_password": 1}


def test_workflow_keeps_pull_requests_offline_and_gates_publication() -> None:
    workflow = yaml.safe_load(
        (Path(__file__).parents[1] / ".github" / "workflows" / "update.yml").read_text(
            encoding="utf-8"
        )
    )
    triggers = workflow.get("on", workflow.get(True))
    assert set(triggers) == {"pull_request", "push", "workflow_dispatch"}
    assert triggers["push"]["branches"] == ["main"]
    assert triggers["push"]["paths"] == ["docs/**"]
    assert set(workflow["jobs"]) == {"tests", "deploy"}
    assert workflow["permissions"] == {"contents": "read"}
    assert workflow["jobs"]["tests"]["permissions"] == {"contents": "read"}
    assert workflow["jobs"]["deploy"]["permissions"] == {
        "contents": "read",
        "pages": "write",
        "id-token": "write",
    }
    assert workflow["jobs"]["deploy"]["concurrency"]["cancel-in-progress"] is False
    assert workflow["jobs"]["deploy"]["concurrency"]["group"] == "public-pages-release"
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
    assert '"path": "docs"' in serialized
    assert workflow["jobs"]["tests"]["outputs"]["pages_changed"] == (
        "${{ steps.detect_pages_changes.outputs.pages_changed }}"
    )
    assert "git diff --name-only" in serialized
    assert "docs/dist/" in serialized
    assert "needs.tests.outputs.pages_changed" in str(workflow["jobs"]["deploy"]["if"])
    assert "schedule" not in serialized
    assert "mihomo" not in serialized.lower()
    assert "secrets." not in serialized


def test_workflow_deploy_check_requires_committed_config_without_heredoc() -> None:
    workflow_path = Path(__file__).parents[1] / ".github" / "workflows" / "update.yml"
    workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    deploy_steps = workflow["jobs"]["deploy"]["steps"]
    validate = next(
        step
        for step in deploy_steps
        if step.get("name") == "Validate committed public config"
    )
    validate_run = str(validate["run"])
    assert "docs/dist/clash/config.yaml" in validate_run
    assert "yaml.safe_load" in validate_run
    assert "python - <<'PY'" not in validate_run
    assert (
        next(
            step
            for step in deploy_steps
            if step.get("uses", "").startswith("actions/upload-pages-artifact")
        )["with"]["path"]
        == "docs"
    )


def test_cloud_workflow_runs_probe_commits_only_auto_artifacts_and_deploys_pages() -> (
    None
):
    workflow_path = (
        Path(__file__).parents[1] / ".github" / "workflows" / "auto-refresh.yml"
    )
    workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    triggers = workflow.get("on", workflow.get(True))
    assert triggers["schedule"] == [{"cron": "*/15 * * * *"}]
    assert "workflow_dispatch" in triggers
    assert workflow["permissions"] == {
        "contents": "write",
        "pages": "write",
        "id-token": "write",
    }
    refresh = workflow["jobs"]["refresh"]
    assert refresh["timeout-minutes"] == 20
    assert workflow["concurrency"] == {
        "group": "public-pages-release",
        "cancel-in-progress": False,
    }
    serialized = json.dumps(workflow)
    assert "--probe-backend delay" in serialized
    assert "state/verified-pool-auto.json" in serialized
    assert "docs/auto" in serialized
    commit_run = next(
        step["run"]
        for step in refresh["steps"]
        if step.get("name") == "Commit changed auto artifacts"
    )
    assert commit_run.index("git add") < commit_run.index("git commit")
    assert commit_run.index("git commit") < commit_run.index(
        "git pull --rebase origin main"
    )
    assert commit_run.index("git pull --rebase origin main") < commit_run.index(
        "git push origin HEAD:main"
    )
    assert "actions/upload-pages-artifact@v3" in serialized
    assert "actions/deploy-pages@v4" in serialized


def test_refresh_publish_script_is_the_only_local_refresh_entrypoint() -> None:
    root = Path(__file__).parents[1]
    script_path = root / "scripts" / "refresh-publish.ps1"
    script = script_path.read_text(encoding="utf-8")

    for expected in (
        "[switch]$Publish",
        "[int]$MinStable = 5",
        "[int]$MaxNodes = 1500",
        '[string]$Output = "dist-local"',
        '[string]$State = "state-local"',
        '"D:\\Program Files\\Clash Verge\\verge-mihomo.exe"',
        '"C:\\Program Files\\Clash Verge\\verge-mihomo.exe"',
        "--probe-backend",
        "delay",
        "--probe-rounds",
        "3",
        "--probe-timeout",
        "8",
        "--probe-concurrency",
        "12",
        "--no-private",
        "--require-core",
        '"reports"',
        '"refresh-$Timestamp.log"',
        'Resolve-ProjectPath "docs"',
        '"docs/dist"',
        '"pull", "--rebase"',
        '"push", "origin", "main"',
        '"docs/dist/clash/config.yaml"',
        '"docs/dist/clash/providers/aggregate.yaml"',
        '"docs/dist/sing-box/config.json"',
        "function Test-MaterialChange",
        "Get-HeadMaterialHash",
        "no material change; skip commit/push.",
        "node_quality",
    ):
        assert expected in script
    assert not (root / "scripts" / "local-refresh.ps1").exists()
    assert "Set-ItemProperty" not in script
    assert "ProxyEnable" not in script
    assert "secret" not in script.lower()
