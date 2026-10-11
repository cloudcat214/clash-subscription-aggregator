from __future__ import annotations

import json
from pathlib import Path

import yaml

from aggregator.pipeline import run_pipeline
from aggregator.quality import node_key, probe_verdict
from aggregator.verified_pool import (
    merge_verified_pool,
    pool_document,
    round_robin_by_source,
)


def _node(name: str) -> dict[str, object]:
    return {
        "name": name,
        "type": "http",
        "server": f"{name}.example.invalid",
        "port": 8080,
    }


def _passed(node: dict[str, object]) -> dict[str, object]:
    return {"node_key": node_key(node), **probe_verdict(3, 3, 120.0)}


def test_round_robin_sampling_balances_sources() -> None:
    nodes = [_node(f"node-{index}") for index in range(6)]
    sources = {
        node_key(node): source
        for node, source in zip(
            nodes,
            ["large", "large", "large", "large", "small", "small"],
        )
    }

    sampled = round_robin_by_source(nodes, sources, limit=6)

    assert [sources[node_key(node)] for node in sampled] == [
        "large",
        "small",
        "large",
        "small",
        "large",
        "large",
    ]


def test_pool_merge_adds_passed_nodes_and_resets_failures() -> None:
    old = _node("old")
    old_entry = {
        "key": node_key(old),
        "node": old,
        "source_id": "source-a",
        "first_seen_at": "2026-10-11T00:00:00Z",
        "last_rechecked_at": "2026-10-11T00:10:00Z",
        "last_conclusion": "failed",
        "consecutive_failures": 1,
        "total_passes": 3,
    }
    new = _node("new")

    merged, stats = merge_verified_pool(
        [old_entry],
        [old, new],
        {node_key(old): _passed(old), node_key(new): _passed(new)},
        {node_key(new): "source-b"},
        now="2026-10-11T00:20:00Z",
        min_verdict="stable",
        verified_min_rounds=3,
        stable_min_rounds=3,
        stable_success_rate=2 / 3,
        fast_latency_ms=800.0,
    )

    assert [entry["key"] for entry in merged] == [node_key(old), node_key(new)]
    assert merged[0]["consecutive_failures"] == 0
    assert merged[0]["total_passes"] == 4
    assert merged[1]["source_id"] == "source-b"
    assert merged[1]["total_passes"] == 1
    assert stats == {"retested": 1, "retained": 2, "added": 1, "evicted": 0}


def test_pool_merge_evicts_only_after_two_consecutive_failures() -> None:
    node = _node("flaky")
    entry = {
        "key": node_key(node),
        "node": node,
        "source_id": "source-a",
        "first_seen_at": "2026-10-11T00:00:00Z",
        "last_rechecked_at": "2026-10-11T00:10:00Z",
        "last_conclusion": "stable",
        "consecutive_failures": 0,
        "total_passes": 1,
    }
    failed = {
        "node_key": node_key(node),
        **probe_verdict(0, 3, None, error_category="timeout"),
    }

    once, first_stats = merge_verified_pool(
        [entry],
        [node],
        {node_key(node): failed},
        {},
        now="2026-10-11T00:20:00Z",
        min_verdict="stable",
        verified_min_rounds=3,
        stable_min_rounds=3,
        stable_success_rate=2 / 3,
        fast_latency_ms=800.0,
    )
    twice, second_stats = merge_verified_pool(
        once,
        [node],
        {node_key(node): failed},
        {},
        now="2026-10-11T00:30:00Z",
        min_verdict="stable",
        verified_min_rounds=3,
        stable_min_rounds=3,
        stable_success_rate=2 / 3,
        fast_latency_ms=800.0,
    )

    assert len(once) == 1
    assert once[0]["consecutive_failures"] == 1
    assert first_stats["retained"] == 1
    assert twice == []
    assert second_stats["evicted"] == 1


def test_pipeline_probes_pool_before_new_candidates(tmp_path: Path) -> None:
    source_path = tmp_path / "source.yaml"
    source_path.write_text(
        yaml.safe_dump(
            {
                "proxies": [
                    {
                        "name": f"candidate-{index}",
                        "type": "http",
                        "server": f"candidate-{index}.example.invalid",
                        "port": 8080,
                    }
                    for index in range(2)
                ]
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    config_path = tmp_path / "sources.yaml"
    config_path.write_text(
        yaml.safe_dump(
            {
                "settings": {
                    "active_probe": True,
                    "probe_max_nodes": 2,
                    "filters": {"min_quality_score": 0},
                },
                "sources": {
                    "public": [
                        {
                            "id": "fixture",
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
    old = _node("old")
    pool_path = tmp_path / "state" / "verified-pool.json"
    pool_path.parent.mkdir()
    pool_path.write_text(
        json.dumps(
            pool_document(
                [
                    {
                        "key": node_key(old),
                        "node": old,
                        "source_id": "fixture-old",
                        "first_seen_at": "2026-10-11T00:00:00Z",
                        "last_rechecked_at": "2026-10-11T00:10:00Z",
                        "last_conclusion": "stable",
                        "consecutive_failures": 0,
                        "total_passes": 1,
                    }
                ],
                "2026-10-11T00:10:00Z",
            )
        ),
        encoding="utf-8",
    )
    seen: list[list[str]] = []

    def probe(nodes: list[dict[str, object]]) -> dict[str, object]:
        seen.append([str(node["name"]) for node in nodes])
        return {
            "status": "performed",
            "tested": len(nodes),
            "results": [_passed(node) for node in nodes],
        }

    result = run_pipeline(
        config_path,
        tmp_path / "dist",
        tmp_path / "state",
        probe_runner=probe,
        verified_pool_path=pool_path,
    )

    assert result.success is True
    assert seen == [["old", "[fixture] candidate-0"]]
    manifest = json.loads((tmp_path / "dist" / "manifest.json").read_text())
    assert manifest["verification"]["probe_queue"] == "verified_pool_first"
    assert manifest["verification"]["pool_probe_candidates"] == 1
    assert manifest["verification"]["pool_retested"] == 1
    assert manifest["verification"]["new_candidates_tested"] == 1


def test_pool_shrink_guard_uses_fifty_percent_for_previous_pool_of_ten(
    tmp_path: Path,
) -> None:
    source_path = tmp_path / "source.yaml"
    source_path.write_text(
        yaml.safe_dump(
            {
                "proxies": [
                    {
                        "name": f"node-{index}",
                        "type": "http",
                        "server": f"node-{index}.example.invalid",
                        "port": 8080,
                    }
                    for index in range(10)
                ]
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    config_path = tmp_path / "sources.yaml"
    config = {
        "settings": {
            "active_probe": False,
            "max_shrink_ratio": 0.2,
            "filters": {"min_quality_score": 0},
        },
        "sources": {
            "public": [
                {
                    "id": "fixture",
                    "path": str(source_path),
                    "enabled": True,
                    "publish": True,
                    "requires_review": False,
                }
            ],
            "private": [],
        },
    }
    config_path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
    output_dir = tmp_path / "dist"
    state_dir = tmp_path / "state"

    assert run_pipeline(config_path, output_dir, state_dir).success is True
    previous = (output_dir / "clash/providers/aggregate.yaml").read_text()
    pool_nodes = [_node(f"[fixture] node-{index}") for index in range(4)]
    pool_path = state_dir / "verified-pool.json"
    pool_path.write_text(
        json.dumps(
            pool_document(
                [
                    {
                        "key": node_key(node),
                        "node": node,
                        "source_id": "fixture",
                        "first_seen_at": "2026-10-11T00:00:00Z",
                        "last_rechecked_at": "2026-10-11T00:10:00Z",
                        "last_conclusion": "stable",
                        "consecutive_failures": 0,
                        "total_passes": 1,
                    }
                    for node in pool_nodes
                ],
                "2026-10-11T00:10:00Z",
            )
        ),
        encoding="utf-8",
    )
    config["settings"]["active_probe"] = True
    config["settings"]["probe_max_nodes"] = 4
    config_path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")

    def probe(nodes: list[dict[str, object]]) -> dict[str, object]:
        return {
            "status": "performed",
            "tested": len(nodes),
            "results": [_passed(node) for node in nodes],
        }

    result = run_pipeline(config_path, output_dir, state_dir, probe_runner=probe)

    assert result.success is False
    assert result.failure_reason == "shrink_guard"
    assert (output_dir / "clash/providers/aggregate.yaml").read_text() == previous


def test_pipeline_shrink_guard_keeps_previous_output(tmp_path: Path) -> None:
    source_path = tmp_path / "source.yaml"
    source_path.write_text(
        yaml.safe_dump(
            {
                "proxies": [
                    {
                        "name": f"node-{index}",
                        "type": "http",
                        "server": f"node-{index}.example.invalid",
                        "port": 8080,
                    }
                    for index in range(4)
                ]
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    config_path = tmp_path / "sources.yaml"
    config_path.write_text(
        yaml.safe_dump(
            {
                "settings": {
                    "active_probe": True,
                    "max_shrink_ratio": 0.5,
                    "filters": {"min_quality_score": 0},
                },
                "sources": {
                    "public": [
                        {
                            "id": "fixture",
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
    output_dir = tmp_path / "dist"
    state_dir = tmp_path / "state"

    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    config["settings"]["active_probe"] = False
    config_path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
    assert run_pipeline(config_path, output_dir, state_dir).success
    previous = (output_dir / "clash/providers/aggregate.yaml").read_text(
        encoding="utf-8"
    )
    config["settings"]["active_probe"] = True
    config_path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")

    def one_pass(nodes: list[dict[str, object]]) -> dict[str, object]:
        return {
            "status": "performed",
            "tested": 1,
            "results": [_passed(nodes[0])],
        }

    result = run_pipeline(config_path, output_dir, state_dir, probe_runner=one_pass)

    assert result.success is False
    assert result.failure_reason == "shrink_guard"
    assert (output_dir / "clash/providers/aggregate.yaml").read_text(
        encoding="utf-8"
    ) == previous
    health = json.loads((output_dir / "health.json").read_text(encoding="utf-8"))
    assert health["failure_reason"] == "shrink_guard"
