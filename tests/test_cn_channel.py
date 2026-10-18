from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import yaml

from aggregator.outputs import render_artifacts
from aggregator.quality import node_key

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "build_cn_channel.py"
_MODULE = None


def _load_module():
    global _MODULE
    if _MODULE is None:
        spec = importlib.util.spec_from_file_location("build_cn_channel", SCRIPT)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _MODULE = module
    return _MODULE


def _node(name: str) -> dict[str, object]:
    return {"name": name, "type": "http", "server": "node.example", "port": 8080}


def _write_dist(tmp_path: Path, proxies: list[dict[str, object]]) -> Path:
    dist_dir = tmp_path / "dist-auto"
    (dist_dir / "clash").mkdir(parents=True, exist_ok=True)
    config = render_artifacts(proxies)["clash/config.yaml"]
    (dist_dir / "clash" / "config.yaml").write_text(config, encoding="utf-8")
    return dist_dir


def _write_feedback(path: Path, keys: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    document = {
        "schema_version": 1,
        "generated_at": "2026-10-15T15:00:00Z",
        "vantage": "cn-one-shot",
        "tested": 3,
        "stable": len(keys),
        "verified": len(keys),
        "stable_keys": keys,
    }
    path.write_text(json.dumps(document), encoding="utf-8")


def test_builds_filtered_channel(tmp_path: Path) -> None:
    module = _load_module()
    proxies = [_node("a"), _node("b"), _node("c")]
    dist_dir = _write_dist(tmp_path, proxies)
    feedback = tmp_path / "cn-feedback" / "latest.json"
    _write_feedback(feedback, [node_key(proxies[0]), node_key(proxies[2])])
    output_dir = tmp_path / "docs" / "cn"

    result = module.build_cn_channel(dist_dir, feedback, output_dir)

    assert result["status"] == "built"
    config = yaml.safe_load(
        (output_dir / "clash" / "config.yaml").read_text(encoding="utf-8")
    )
    assert [proxy["name"] for proxy in config["proxies"]] == ["a", "c"]
    manifest = json.loads((output_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["filter"] == "cn-feedback"
    assert manifest["counts"] == {
        "source_published": 3,
        "selected": 2,
        "blocked_keys": 0,
    }
    assert manifest["feedback"]["stable"] == 2
    assert manifest["feedback"]["age_hours"] >= 0


def test_skips_without_feedback(tmp_path: Path) -> None:
    module = _load_module()
    dist_dir = _write_dist(tmp_path, [_node("a")])
    output_dir = tmp_path / "docs" / "cn"

    result = module.build_cn_channel(dist_dir, tmp_path / "missing.json", output_dir)

    assert result["status"] == "skipped"
    assert result["reason"] == "feedback_missing_or_invalid"
    assert not output_dir.exists()


def test_skips_when_intersection_empty(tmp_path: Path) -> None:
    module = _load_module()
    dist_dir = _write_dist(tmp_path, [_node("a"), _node("b")])
    feedback = tmp_path / "cn-feedback" / "latest.json"
    _write_feedback(feedback, [node_key(_node("ghost"))])
    output_dir = tmp_path / "docs" / "cn"

    result = module.build_cn_channel(dist_dir, feedback, output_dir)

    assert result["status"] == "skipped"
    assert result["reason"] == "no_selected_nodes"
    assert not output_dir.exists()


def test_skips_on_invalid_feedback(tmp_path: Path) -> None:
    module = _load_module()
    dist_dir = _write_dist(tmp_path, [_node("a")])
    feedback = tmp_path / "cn-feedback" / "latest.json"
    feedback.parent.mkdir(parents=True)
    feedback.write_text("{not json", encoding="utf-8")
    output_dir = tmp_path / "docs" / "cn"

    result = module.build_cn_channel(dist_dir, feedback, output_dir)

    assert result["status"] == "skipped"
    assert result["reason"] == "feedback_missing_or_invalid"


def test_builds_with_extra_feedback_union(tmp_path: Path) -> None:
    module = _load_module()
    proxies = [_node("a"), _node("b"), _node("c")]
    dist_dir = _write_dist(tmp_path, proxies)
    feedback = tmp_path / "cn-feedback" / "latest.json"
    _write_feedback(feedback, [node_key(proxies[0])])
    extra = tmp_path / "cn-feedback" / "cloud.json"
    _write_feedback(extra, [node_key(proxies[1])])
    output_dir = tmp_path / "docs" / "cn"

    result = module.build_cn_channel(dist_dir, feedback, output_dir, extra)

    assert result["status"] == "built"
    config = yaml.safe_load(
        (output_dir / "clash" / "config.yaml").read_text(encoding="utf-8")
    )
    assert {proxy["name"] for proxy in config["proxies"]} == {"a", "b"}
    manifest = json.loads(
        (output_dir / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["feedback_extra"]["stable"] == 1


def test_builds_with_only_extra_feedback(tmp_path: Path) -> None:
    module = _load_module()
    proxies = [_node("a")]
    dist_dir = _write_dist(tmp_path, proxies)
    extra = tmp_path / "cn-feedback" / "cloud.json"
    _write_feedback(extra, [node_key(proxies[0])])
    output_dir = tmp_path / "docs" / "cn"

    result = module.build_cn_channel(
        dist_dir, tmp_path / "missing.json", output_dir, extra
    )

    assert result["status"] == "built"
    manifest = json.loads(
        (output_dir / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["counts"]["selected"] == 1


def test_blocked_keys_are_subtracted(tmp_path: Path) -> None:
    module = _load_module()
    proxies = [_node("a"), _node("b"), _node("c")]
    dist_dir = _write_dist(tmp_path, proxies)
    feedback = tmp_path / "cn-feedback" / "latest.json"
    _write_feedback(feedback, [node_key(proxies[0]), node_key(proxies[1])])
    blocked = tmp_path / "cn-feedback" / "blocked.json"
    blocked.write_text(
        json.dumps({"schema_version": 1, "keys": [node_key(proxies[1])]}),
        encoding="utf-8",
    )
    output_dir = tmp_path / "docs" / "cn"

    result = module.build_cn_channel(dist_dir, feedback, output_dir, None, blocked)

    assert result["status"] == "built"
    config = yaml.safe_load(
        (output_dir / "clash" / "config.yaml").read_text(encoding="utf-8")
    )
    assert [proxy["name"] for proxy in config["proxies"]] == ["a"]
    manifest = json.loads(
        (output_dir / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["counts"]["blocked_keys"] == 1
