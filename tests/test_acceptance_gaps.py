"""独立验收回归：只使用脱敏 fixture（example.invalid / 合成 UUID / 占位公钥）。

覆盖用户目标的五个关键行为：URL provider 路径、private 输出隔离、
原子发布/异常骤减、sing-box TLS/WS 映射、sing-box Reality 映射。
不读取用户真实配置，不发起任何真实网络连接。
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from aggregator import pipeline
from aggregator.outputs import render_sing_box_config
from aggregator.parsing import normalize_proxies
from aggregator.pipeline import initialize_dist, run_pipeline

FIXTURES = Path(__file__).parent / "fixtures"

SYNTH_UUID = "11111111-1111-1111-1111-111111111111"


def _stub_loader(source: dict, config_dir: Path, settings: dict, offline: bool) -> str:
    """脱敏 stub：只读本地 fixture，绝不访问 source 里的 url。"""
    assert source.get("url", "").startswith(("http://", "https://"))
    return (FIXTURES / "clash.yaml").read_text(encoding="utf-8")


def _write_config(path: Path, public: list[dict], private: list[dict]) -> None:
    path.write_text(
        yaml.safe_dump(
            {
                "settings": {"active_probe": False},
                "sources": {"public": public, "private": private},
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )


def _dist_texts(output_dir: Path) -> str:
    """拼接 dist 下全部文本产物，用于泄漏扫描。"""
    return "\n".join(
        file.read_text(encoding="utf-8")
        for file in sorted(output_dir.rglob("*"))
        if file.is_file()
    )


def test_public_url_source_publishes_via_stub_loader(tmp_path: Path) -> None:
    """URL provider 路径：公开 URL 来源 + stub loader，节点应进入公开聚合，
    且 manifest 必须声明无主动拨测（HTTP 200 不可作为可用性证明）。"""
    config_path = tmp_path / "sources.yaml"
    output_dir = tmp_path / "dist"
    _write_config(
        config_path,
        public=[
            {
                "id": "public-url",
                "url": "https://example.invalid/public-subscription",
                "format": "auto",
                "enabled": True,
                "publish": True,
                "requires_review": False,
            }
        ],
        private=[],
    )

    result = run_pipeline(
        config_path, output_dir, tmp_path / "state", source_loader=_stub_loader
    )

    assert result.success is True
    manifest = json.loads((output_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["counts"]["published"] >= 1
    assert manifest["active_probe"] is False
    assert any("active probing" in item for item in manifest["limitations"])
    provider = (output_dir / "clash" / "providers" / "aggregate.yaml").read_text(
        encoding="utf-8"
    )
    assert "alpha.example.invalid" in provider


def test_private_nodes_never_leak_into_any_public_artifact(tmp_path: Path) -> None:
    """private 输出隔离：混合公开+私有来源时，私有节点不得出现在
    provider / clash 配置 / sing-box 配置 / manifest / health 任何产物里。"""
    private_fixture = tmp_path / "private.yaml"
    private_fixture.write_text(
        yaml.safe_dump(
            {
                "proxies": [
                    {
                        "name": "private-marker-node",
                        "type": "ss",
                        "server": "owned.example.invalid",
                        "port": 8443,
                        "cipher": "aes-256-gcm",
                        "password": "placeholder",
                    }
                ]
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    public_fixture = tmp_path / "public.yaml"
    public_fixture.write_text(
        (FIXTURES / "clash.yaml").read_text(encoding="utf-8"), encoding="utf-8"
    )
    config_path = tmp_path / "sources.yaml"
    _write_config(
        config_path,
        public=[
            {
                "id": "public-file",
                "path": str(public_fixture),
                "enabled": True,
                "publish": True,
                "requires_review": False,
            }
        ],
        private=[
            {
                "id": "owned-file",
                "path": str(private_fixture),
                "enabled": True,
                "publish": True,
                "requires_review": False,
            }
        ],
    )
    output_dir = tmp_path / "dist"

    result = run_pipeline(config_path, output_dir, tmp_path / "state")

    assert result.success is True
    manifest = json.loads((output_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["counts"]["published"] == 2  # 只有公开源的两个节点
    assert "private-marker-node" not in _dist_texts(output_dir)
    assert "owned.example.invalid" not in _dist_texts(output_dir)


def test_write_phase_failure_restores_lkg_instead_of_crashing(
    tmp_path: Path, monkeypatch
) -> None:
    """原子发布/异常骤减：产物写入阶段抛出 OSError 时，
    管线不得让异常逃逸，必须失败并恢复 last-known-good。"""
    config_path = tmp_path / "sources.yaml"
    source_path = tmp_path / "source.yaml"
    source_path.write_text(
        (FIXTURES / "clash.yaml").read_text(encoding="utf-8"), encoding="utf-8"
    )
    output_dir = tmp_path / "dist"
    state_dir = tmp_path / "state"
    _write_config(
        config_path,
        public=[
            {
                "id": "public-file",
                "path": str(source_path),
                "enabled": True,
                "publish": True,
                "requires_review": False,
            }
        ],
        private=[],
    )

    first = run_pipeline(config_path, output_dir, state_dir)
    assert first.success is True
    previous_provider = (
        output_dir / "clash" / "providers" / "aggregate.yaml"
    ).read_text(encoding="utf-8")

    real_write = pipeline._write_text
    calls = {"count": 0}

    def flaky_write(path: Path, content: str) -> None:
        calls["count"] += 1
        if calls["count"] == 1:
            raise OSError("simulated disk failure")
        real_write(path, content)

    monkeypatch.setattr(pipeline, "_write_text", flaky_write)

    second = run_pipeline(config_path, output_dir, state_dir)

    assert second.success is False
    assert second.used_last_known_good is True
    assert (output_dir / "clash" / "providers" / "aggregate.yaml").read_text(
        encoding="utf-8"
    ) == previous_provider
    health = json.loads((output_dir / "health.json").read_text(encoding="utf-8"))
    assert health["status"] == "failed"


def test_sing_box_tls_and_ws_mapping(tmp_path: Path) -> None:
    """sing-box TLS/WS 映射：vmess+ws+tls+sni 应正确生成 tls 与 transport。"""
    proxies = normalize_proxies(
        [
            {
                "name": "ws-node",
                "type": "vmess",
                "server": "node.example.invalid",
                "port": 443,
                "uuid": SYNTH_UUID,
                "tls": True,
                "sni": "cdn.example.invalid",
                "network": "ws",
                "ws-opts": {
                    "path": "/ws-path",
                    "headers": {"Host": "cdn.example.invalid"},
                },
            }
        ]
    )
    config = json.loads(render_sing_box_config(proxies))
    outbound = next(o for o in config["outbounds"] if o.get("tag") == "ws-node")

    assert outbound["type"] == "vmess"
    assert outbound["tls"] == {
        "enabled": True,
        "server_name": "cdn.example.invalid",
    }
    assert outbound["transport"]["type"] == "ws"
    assert outbound["transport"]["path"] == "/ws-path"
    assert outbound["transport"]["headers"]["Host"] == "cdn.example.invalid"


def test_sing_box_reality_mapping(tmp_path: Path) -> None:
    """sing-box Reality 映射：vless+reality 必须输出 tls.reality 参数块，
    而不是把 Reality 节点伪装成普通 TLS 节点。"""
    proxies = normalize_proxies(
        [
            {
                "name": "reality-node",
                "type": "vless",
                "server": "node.example.invalid",
                "port": 443,
                "uuid": SYNTH_UUID,
                "tls": True,
                "sni": "cdn.example.invalid",
                "network": "tcp",
                "flow": "xtls-rprx-vision",
                "reality-opts": {
                    "public-key": "SYNTHETIC-PUBLIC-KEY",
                    "short-id": "abcd1234",
                },
            }
        ]
    )
    config = json.loads(render_sing_box_config(proxies))
    outbound = next(o for o in config["outbounds"] if o.get("tag") == "reality-node")

    assert outbound["type"] == "vless"
    assert outbound["flow"] == "xtls-rprx-vision"
    assert outbound["tls"]["enabled"] is True
    assert outbound["tls"]["server_name"] == "cdn.example.invalid"
    assert outbound["tls"]["reality"]["enabled"] is True
    assert outbound["tls"]["reality"]["public_key"] == "SYNTHETIC-PUBLIC-KEY"
    assert outbound["tls"]["reality"]["short_id"] == "abcd1234"


def test_bootstrap_dist_is_not_a_usable_subscription(tmp_path: Path) -> None:
    """空 dist（bootstrap）不得当作可用订阅：provider 无节点、manifest 非成功态。"""
    output_dir = tmp_path / "dist"
    initialize_dist(output_dir)

    manifest = json.loads((output_dir / "manifest.json").read_text(encoding="utf-8"))
    provider = (output_dir / "clash" / "providers" / "aggregate.yaml").read_text(
        encoding="utf-8"
    )

    assert manifest["status"] == "bootstrap"
    assert manifest["counts"]["published"] == 0
    assert yaml.safe_load(provider) == {"proxies": []}
